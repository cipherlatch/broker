from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .. import audit, crud, oidc
from ..config import get_settings
from ..db import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


def _redirect_uri(request: Request) -> str:
    # Derive from the configured public issuer so it matches the IdP registration
    # exactly, regardless of proxy headers.
    return f"{get_settings().issuer.rstrip('/')}/auth/callback"


@router.get("/login")
def login(request: Request):
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(503, "OIDC login is not configured (set BROKER_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET)")
    url, state, nonce, verifier = oidc.build_auth_request(_redirect_uri(request))
    request.session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier}
    return RedirectResponse(url, status_code=302)


@router.get("/callback")
def callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    db: Session = Depends(get_db),
):
    settings = get_settings()
    if error:
        raise HTTPException(400, f"IdP returned error: {error}")
    pending = request.session.pop("oidc", None)
    if not pending or not code or state != pending.get("state"):
        raise HTTPException(400, "Login state mismatch; start over at /auth/login")

    tokens = oidc.exchange_code(code, _redirect_uri(request), pending["verifier"])
    claims = oidc.verify_id_token(tokens["id_token"], pending["nonce"])

    sub = claims.get("sub", "")
    email = (claims.get("email") or "").lower()
    name = claims.get("name") or claims.get("preferred_username") or ""
    if not sub or not email:
        raise HTTPException(400, "IdP did not supply sub and email claims")

    # Route to a tenant by email domain (falls back to default). A returning
    # user is found by sub across their tenant; a first-time user is JIT'd into
    # the domain-mapped tenant.
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    tenant_slug = settings.tenant_domain_pairs.get(domain, "default")
    tenant = crud.get_or_create_tenant(db, tenant_slug)
    principal = crud.find_principal_by_sub(db, tenant, sub)

    if principal is None:
        # No account carries this sub yet. Bind it to the account with this
        # (verified) email — on first login, or by RE-binding when the IdP's
        # subject identifier for an existing account changed (e.g. its subject
        # mode was reconfigured, or SCIM rewrote externalId). Re-binding is
        # safe: find_principal_by_sub already established no account holds this
        # sub, so there is no collision. Without it, a rotated sub dead-ends at
        # JIT and 409s on the existing email, locking the user out.
        by_email = crud.find_principal_by_email(db, tenant, email)
        if by_email is not None and by_email.deleted_at is None:
            # Require the claim to be explicitly truthy, not merely "not False":
            # an IdP that OMITS email_verified must not silently link an
            # unverified email onto an existing account (takeover primitive).
            if settings.link_requires_verified_email and not claims.get("email_verified"):
                audit.record_request(
                    db, request, "login.denied", actor=email,
                    detail={"reason": "email_not_verified"},
                )
                raise HTTPException(403, "Email not verified by the identity provider")
            relinked = by_email.sub is not None and by_email.sub != sub
            by_email.sub = sub
            db.commit()
            audit.record_request(
                db, request, "account.relinked" if relinked else "account.linked",
                tenant_id=tenant.id, actor=email, detail={"sub": sub, "relinked": relinked},
            )
            principal = by_email
        elif by_email is not None:
            # Soft-deleted account still holds this email: a rotated sub must
            # not resurrect it through JIT (which would also trip the unique
            # email constraint). Same denial as a deleted account logging in.
            audit.record_request(
                db, request, "login.denied", actor=email,
                detail={"reason": "account_deleted"},
            )
            raise HTTPException(403, "Account is disabled")
        elif settings.jit_provisioning:
            if email in settings.admin_email_list:
                role = "broker-admin"
            else:
                raw_groups = claims.get(settings.oidc_groups_claim) or []
                groups = {raw_groups} if isinstance(raw_groups, str) else set(raw_groups)
                role = next(
                    (r for g, r in settings.group_role_pairs if g in groups),
                    settings.default_role,
                )
                if crud.get_role(db, tenant, role) is None:
                    role = settings.default_role
            principal = crud.create_principal(
                db, request, "jit", email=email, display_name=name,
                role=role, sub=sub, event="login.jit_provisioned", tenant=tenant,
            )
        else:
            audit.record_request(
                db, request, "login.denied", actor=email,
                detail={"reason": "not_provisioned", "jit": False},
            )
            raise HTTPException(403, "No account for this identity; ask an admin to add you")

    if not principal.active or principal.deleted_at is not None:
        audit.record_request(
            db, request, "login.denied", actor=email, detail={"reason": "account_disabled"},
        )
        raise HTTPException(403, "Account is disabled")

    # IdP group -> role sync: when a configured mapping matches, the IdP is
    # authoritative for this principal's role (first matching pair wins).
    if settings.group_role_pairs:
        raw_groups = claims.get(settings.oidc_groups_claim) or []
        groups = {raw_groups} if isinstance(raw_groups, str) else set(raw_groups)
        mapped = next(
            (role for group, role in settings.group_role_pairs if group in groups), None
        )
        if mapped and (principal.role is None or principal.role.name != mapped):
            role_obj = crud.get_role(db, tenant, mapped)
            if role_obj is None:
                audit.record_request(
                    db, request, "login.role_sync_skipped", actor=email,
                    detail={"reason": "unknown_role", "role": mapped},
                )
            elif (
                principal.role is not None
                and "*" in (principal.role.permissions or [])
                and "*" not in (role_obj.permissions or [])
                and not crud.other_admins_exist(db, principal)
            ):
                audit.record_request(
                    db, request, "login.role_sync_skipped", actor=email,
                    detail={"reason": "last_admin_guard", "role": mapped},
                )
            else:
                old = principal.role.name if principal.role else None
                principal.role_id = role_obj.id
                db.commit()
                db.refresh(principal)
                audit.record_request(
                    db, request, "user.updated", tenant_id=tenant.id, actor="idp-groups",
                    detail={"email": email, "changes": {"role": [old, mapped]}},
                )

    # Keep role in sync with the configured admin list (promotion only; wins
    # over group mapping). With pinning off, admin_emails only seeds the role
    # at JIT provisioning above, so an explicit demotion sticks.
    if settings.admin_email_pinning and email in settings.admin_email_list and (
        principal.role is None or principal.role.name != "broker-admin"
    ):
        admin_role = crud.get_role(db, tenant, "broker-admin")
        if admin_role is not None:
            principal.role_id = admin_role.id
    if name and not principal.display_name:
        principal.display_name = name
    principal.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(principal)

    request.session["pid"] = principal.id
    audit.record_request(
        db, request, "login.success", tenant_id=tenant.id, actor=principal.email,
        detail={"role": principal.role.name if principal.role else None},
    )
    # An OAuth authorize request parked itself before SSO: return to it.
    # Deliberately restricted to that one local path — this must never grow
    # into a general ?next= redirect.
    next_path = request.session.pop("post_login_next", None)
    if next_path and next_path.startswith("/oauth/authorize"):
        return RedirectResponse(next_path, status_code=302)
    return RedirectResponse("/ui/agents", status_code=302)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    pid = request.session.get("pid")
    if pid:
        from ..models import Principal

        principal = db.get(Principal, pid)
        audit.record_request(
            db, request, "logout", actor=principal.email if principal else str(pid)
        )
    request.session.clear()
    return RedirectResponse("/login", status_code=302)
