"""OAuth 2.1 authorization endpoint (MCP authorization-server role).

Browser-facing: an MCP client sends the user here to delegate access to a
registered MCP server. Order of operations is load-bearing (OAuth 2.1 §4.1.2.1):
client_id and redirect_uri are validated FIRST, and until both check out every
failure renders an error page — redirecting to an unvalidated URI would make
the broker an open redirector. Only after they validate do errors flow back to
the client via redirect, with the RFC 9207 `iss` parameter throughout.

Gated behind BROKER_MCP_AS_ENABLED (404 when off).
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, cimd
from ..authz import client_ip
from ..config import get_settings
from ..db import get_db
from ..models import AuthorizationCode, ConsentGrant, MCPResource, Principal
from .ui import templates  # shared instance carries the asset_v cache-buster

router = APIRouter(include_in_schema=False)

CODE_TTL_SECONDS = 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_enabled() -> None:
    if not get_settings().mcp_as_enabled:
        raise HTTPException(404, "Not found")


def _error_page(request: Request, message: str, status: int = 400):
    """Pre-redirect-validation failures: shown to the human, never redirected."""
    return templates.TemplateResponse(
        request, "authorize_error.html",
        {"message": message, "accent": get_settings().ui_accent},
        status_code=status,
    )


def _error_redirect(redirect_uri: str, error: str, description: str, state: str):
    params = {"error": error, "error_description": description,
              "iss": get_settings().issuer}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


def _code_redirect(redirect_uri: str, code: str, state: str):
    params = {"code": code, "iss": get_settings().issuer}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


def _session_principal(request: Request, db: Session) -> Principal | None:
    pid = request.session.get("pid")
    if not pid:
        return None
    principal = db.get(Principal, pid)
    if principal is None or not principal.active or principal.deleted_at is not None:
        return None
    return principal


def _standing_consent(
    db: Session, principal: Principal, client_id_url: str, resource: str,
    scopes: list[str],
) -> ConsentGrant | None:
    consent = db.scalar(
        select(ConsentGrant).where(
            ConsentGrant.principal_id == principal.id,
            ConsentGrant.client_id_url == client_id_url,
            ConsentGrant.resource == resource,
            ConsentGrant.revoked_at.is_(None),
        )
    )
    if consent is not None and set(scopes) <= set(consent.scopes or []):
        return consent
    return None


def _issue_code(
    db: Session, principal: Principal, client_id_url: str, redirect_uri: str,
    resource: str, scopes: list[str], code_challenge: str,
) -> str:
    code = secrets.token_urlsafe(32)
    db.add(AuthorizationCode(
        code_sha256=hashlib.sha256(code.encode()).hexdigest(),
        tenant_id=principal.tenant_id,
        principal_id=principal.id,
        client_id_url=client_id_url,
        redirect_uri=redirect_uri,
        resource=resource,
        scopes=scopes,
        code_challenge=code_challenge,
        expires_at=_now() + timedelta(seconds=CODE_TTL_SECONDS),
    ))
    # Opportunistic hygiene, same shape as RevokedToken pruning elsewhere.
    from sqlalchemy import delete

    db.execute(delete(AuthorizationCode).where(
        AuthorizationCode.expires_at < _now() - timedelta(hours=1)
    ))
    db.commit()
    return code


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
    resource: str = "",
    db: Session = Depends(get_db),
):
    _require_enabled()
    ip = client_ip(request)

    # -- 1. Identify the client and pin the redirect target. Failures here
    #       render a page; nothing below redirects until both are validated.
    if not client_id or not redirect_uri:
        return _error_page(request, "Missing client_id or redirect_uri.")
    try:
        client = cimd.get_or_refresh_client(db, client_id)
    except cimd.CIMDError as exc:
        audit.record(db, "authorize.denied", ip=ip,
                     detail={"client_id": client_id, "reason": str(exc)})
        return _error_page(request, f"Client could not be verified: {exc}")
    registered = (client.metadata_doc or {}).get("redirect_uris") or []
    if not cimd.redirect_uri_allowed(registered, redirect_uri):
        audit.record(db, "authorize.denied", ip=ip,
                     detail={"client_id": client_id, "reason": "redirect_uri_mismatch"})
        return _error_page(request, "redirect_uri is not registered for this client.")

    # -- 2. redirect_uri is trusted; protocol errors now go back to the client.
    if response_type != "code":
        return _error_redirect(redirect_uri, "unsupported_response_type",
                               "Only response_type=code is supported", state)
    if not code_challenge or code_challenge_method != "S256":
        return _error_redirect(redirect_uri, "invalid_request",
                               "PKCE with code_challenge_method=S256 is required", state)
    if not resource:
        return _error_redirect(redirect_uri, "invalid_target",
                               "resource is required (RFC 8707)", state)

    # -- 3. The human. Not signed in: park the full authorize URL and bounce
    #       through SSO; /auth/callback returns here.
    principal = _session_principal(request, db)
    if principal is None:
        request.session["post_login_next"] = str(request.url.path) + (
            f"?{request.url.query}" if request.url.query else ""
        )
        return RedirectResponse("/auth/login", status_code=302)

    # -- 4. The target must be deliberately enrolled in the user's tenant.
    mcp_resource = db.scalar(
        select(MCPResource).where(
            MCPResource.tenant_id == principal.tenant_id,
            MCPResource.resource_uri == resource,
            MCPResource.active.is_(True),
        )
    )
    if mcp_resource is None:
        audit.record(db, "authorize.denied", tenant_id=principal.tenant_id, ip=ip,
                     actor=principal.email,
                     detail={"client_id": client_id, "resource": resource,
                             "reason": "resource_not_registered"})
        return _error_redirect(redirect_uri, "invalid_target",
                               "Resource is not registered with this broker", state)

    requested = scope.split() if scope else list(mcp_resource.allowed_scopes or [])
    allowed = set(mcp_resource.allowed_scopes or [])
    # An empty allow-list means "no scopes", denying any request — consistent
    # with the client_credentials path. The prior `if allowed else set()`
    # silently granted ANY requested scope when a resource registered none.
    excess = set(requested) - allowed
    if excess:
        return _error_redirect(redirect_uri, "invalid_scope",
                               f"Scope(s) not available: {' '.join(sorted(excess))}", state)

    # -- 5. Standing consent skips the screen entirely.
    if _standing_consent(db, principal, client_id, resource, requested) is not None:
        code = _issue_code(db, principal, client_id, redirect_uri, resource,
                           requested, code_challenge)
        audit.record(db, "authorize.granted", tenant_id=principal.tenant_id, ip=ip,
                     actor=principal.email,
                     detail={"client_id": client_id, "resource": resource,
                             "scopes": requested, "consent": "standing"})
        return _code_redirect(redirect_uri, code, state)

    # -- 6. Ask. The pending request lives in the session (never in hidden
    #       form fields an attacker page could pre-fill); origin_guard +
    #       SameSite=lax cover the decision POST.
    request.session["pending_authz"] = {
        "pid": principal.id,
        "client_id": client_id,
        "client_name": client.name or client_id,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "resource_name": mcp_resource.name,
        "scopes": requested,
        "state": state,
        "code_challenge": code_challenge,
    }
    return templates.TemplateResponse(
        request, "consent.html",
        {
            "accent": get_settings().ui_accent,
            "email": principal.email,
            "client_name": client.name or client_id,
            "client_id": client_id,
            "resource_name": mcp_resource.name,
            "resource_uri": resource,
            "scopes": requested,
        },
    )


@router.post("/oauth/authorize/decision")
def decision(
    request: Request,
    action: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_enabled()
    ip = client_ip(request)
    pending = request.session.pop("pending_authz", None)
    if not pending:
        raise HTTPException(400, "No authorization request pending; start over")

    principal = _session_principal(request, db)
    if principal is None or principal.id != pending["pid"]:
        raise HTTPException(403, "Session does not match the pending request")

    if action != "approve":
        audit.record(db, "consent.denied", tenant_id=principal.tenant_id, ip=ip,
                     actor=principal.email,
                     detail={"client_id": pending["client_id"],
                             "resource": pending["resource"]})
        return _error_redirect(pending["redirect_uri"], "access_denied",
                               "The user denied the request", pending["state"])

    # Upsert the consent: extend scopes, and let a fresh approval supersede an
    # earlier revocation (the unique triple keeps one row per pair).
    consent = db.scalar(
        select(ConsentGrant).where(
            ConsentGrant.principal_id == principal.id,
            ConsentGrant.client_id_url == pending["client_id"],
            ConsentGrant.resource == pending["resource"],
        )
    )
    if consent is None:
        db.add(ConsentGrant(
            tenant_id=principal.tenant_id, principal_id=principal.id,
            client_id_url=pending["client_id"], resource=pending["resource"],
            scopes=pending["scopes"],
        ))
    else:
        consent.scopes = sorted(set(consent.scopes or []) | set(pending["scopes"]))
        consent.revoked_at = None
    db.commit()
    audit.record(db, "consent.granted", tenant_id=principal.tenant_id, ip=ip,
                 actor=principal.email,
                 detail={"client_id": pending["client_id"],
                         "resource": pending["resource"], "scopes": pending["scopes"]})

    code = _issue_code(db, principal, pending["client_id"], pending["redirect_uri"],
                       pending["resource"], pending["scopes"], pending["code_challenge"])
    return _code_redirect(pending["redirect_uri"], code, pending["state"])
