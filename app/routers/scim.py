"""SCIM 2.0 provisioning (RFC 7643/7644): the IdP pushes user lifecycle.

Server-side subset covering what Authentik / Okta / Entra actually send:
`/scim/v2/Users` CRUD + PATCH, `filter=userName eq "..."` (and externalId),
startIndex/count pagination, and the discovery documents. Groups are not
implemented — role assignment stays with the OIDC group→role map at login
(and manual admin action), which SCIM must not fight.

Mapping onto Principal: userName=email (tenant-unique), externalId=OIDC sub
(pre-links the account for first login), displayName=display_name,
active=active. DELETE soft-deletes and revokes owned agents, exactly like
the admin API. Deactivation suspends the user's agents implicitly: the token
endpoint and verify_token() reject agents whose owner is inactive/deleted.

Auth: per-tenant bearer token — generated via POST /v1/scim-token
(`users:manage`; the platform admin targets a tenant with X-Tenant), stored
as a SHA-256 digest. The token maps requests to exactly one tenant, so a
tenant's IdP can never touch another tenant's users.
"""

import hashlib
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crud
from ..authz import Actor, require_permission
from ..config import get_settings
from ..db import get_db
from ..models import Principal, Tenant

router = APIRouter(tags=["scim"])

SCIM_MEDIA = "application/scim+json"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

TOKEN_PREFIX = "cipherlatch_scim_"


# ------------------------------------------------------------------ plumbing


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _scim_json(content: dict, status_code: int = 200, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(content, status_code=status_code, media_type=SCIM_MEDIA, headers=headers)


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        self.status, self.detail, self.scim_type = status, detail, scim_type


def _scim_error_response(exc: ScimError) -> JSONResponse:
    body = {"schemas": [ERROR_SCHEMA], "status": str(exc.status), "detail": exc.detail}
    if exc.scim_type:
        body["scimType"] = exc.scim_type
    return _scim_json(body, exc.status)


def scim_actor(request: Request, db: Session = Depends(get_db)) -> Actor:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ScimError(401, "SCIM requests require a bearer token")
    token = auth[len("Bearer "):].strip()
    tenant = db.scalar(select(Tenant).where(Tenant.scim_token_digest == _digest(token)))
    if tenant is None or not token:
        raise ScimError(401, "Invalid SCIM token")
    return Actor(
        kind="scim", principal=None, permissions=set(),
        tenant_id=tenant.id, tenant_slug=tenant.slug,
        label_override=f"scim:{tenant.slug}",
    )


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _user_resource(p: Principal) -> dict:
    resource = {
        "schemas": [USER_SCHEMA],
        "id": p.id,
        "userName": p.email,
        "displayName": p.display_name or "",
        "active": bool(p.active),
        "meta": {
            "resourceType": "User",
            "created": _iso(p.created_at),
            "location": f"/scim/v2/Users/{p.id}",
        },
    }
    if p.sub:
        resource["externalId"] = p.sub
    return resource


def _get_visible(db: Session, actor: Actor, user_id: str) -> Principal:
    p = db.get(Principal, user_id)
    if p is None or p.tenant_id != actor.tenant_id or p.deleted_at is not None:
        raise ScimError(404, "User not found")
    return p


def _parse_bool(value) -> bool:
    # Entra ID is known to send "True"/"False" strings in PATCH values.
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1")
    return bool(value)


_FILTER_RE = re.compile(r'^\s*(userName|externalId)\s+eq\s+"([^"]*)"\s*$', re.IGNORECASE)


# ------------------------------------------------------------ token issuance


@router.post("/v1/scim-token")
def issue_scim_token(
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    """Generate (or replace) this tenant's SCIM bearer token. Shown once."""
    tenant = crud.actor_tenant(db, actor)
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    replaced = tenant.scim_token_digest is not None
    tenant.scim_token_digest = _digest(token)
    db.commit()
    audit.record_request(
        db, request, "scim.token.issued", tenant_id=tenant.id, actor=actor.label,
        detail={"replaced": replaced},
    )
    return {"scim_token": token, "replaced": replaced,
            "base_url": "/scim/v2", "note": "Store it now; only a digest is kept."}


@router.delete("/v1/scim-token")
def revoke_scim_token(
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    tenant = crud.actor_tenant(db, actor)
    if tenant.scim_token_digest is None:
        raise HTTPException(404, "No SCIM token configured for this tenant")
    tenant.scim_token_digest = None
    db.commit()
    audit.record_request(
        db, request, "scim.token.revoked", tenant_id=tenant.id, actor=actor.label,
    )
    return {"revoked": True}


# ----------------------------------------------------------------- discovery


@router.get("/scim/v2/ServiceProviderConfig")
def service_provider_config(actor: Actor = Depends(scim_actor)):
    return _scim_json({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Per-tenant bearer token from POST /v1/scim-token",
        }],
    })


@router.get("/scim/v2/ResourceTypes")
def resource_types(actor: Actor = Depends(scim_actor)):
    return _scim_json({
        "schemas": [LIST_SCHEMA],
        "totalResults": 1,
        "Resources": [{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/scim/v2/Users",
            "schema": USER_SCHEMA,
        }],
    })


# ------------------------------------------------------------------- groups
#
# Groups are deliberately NOT provisioned: role assignment stays with the
# OIDC group→role map at login (and manual admin action), so SCIM and the
# group map can never fight over roles. But IdPs (Authentik, Okta, Entra)
# often try group sync anyway — a bare 404 makes them error and retry
# forever. Degrade gracefully instead: reads answer empty, writes get a
# proper SCIM error explaining the design.


@router.get("/scim/v2/Groups")
def list_groups(actor: Actor = Depends(scim_actor)):
    return _scim_json({
        "schemas": [LIST_SCHEMA],
        "totalResults": 0,
        "startIndex": 1,
        "itemsPerPage": 0,
        "Resources": [],
    })


@router.api_route("/scim/v2/Groups", methods=["POST"])
@router.api_route("/scim/v2/Groups/{group_id}", methods=["GET", "PUT", "PATCH", "DELETE"])
def groups_not_supported(actor: Actor = Depends(scim_actor), group_id: str = ""):
    raise ScimError(
        501,
        "Group provisioning is not supported: Cipherlatch assigns roles from the "
        "IdP's OIDC groups claim at login (BROKER_GROUP_ROLE_MAP). Disable "
        "group sync for this SCIM provider.",
    )


@router.get("/scim/v2/Schemas")
def schemas(actor: Actor = Depends(scim_actor)):
    return _scim_json({
        "schemas": [LIST_SCHEMA],
        "totalResults": 1,
        "Resources": [{
            "id": USER_SCHEMA,
            "name": "User",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
                {"name": "displayName", "type": "string", "required": False},
                {"name": "externalId", "type": "string", "required": False},
                {"name": "active", "type": "boolean", "required": False},
            ],
        }],
    })


# --------------------------------------------------------------------- users


@router.get("/scim/v2/Users")
def list_users(
    request: Request,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    params = request.query_params
    q = select(Principal).where(
        Principal.tenant_id == actor.tenant_id, Principal.deleted_at.is_(None)
    ).order_by(Principal.created_at)

    filt = params.get("filter")
    if filt:
        m = _FILTER_RE.match(filt)
        if not m:
            raise ScimError(400, f"Unsupported filter: {filt!r}", "invalidFilter")
        attr, value = m.group(1), m.group(2)
        if attr.lower() == "username":
            q = q.where(Principal.email == value.lower())
        else:
            q = q.where(Principal.sub == value)

    users = list(db.scalars(q).all())
    try:
        start = max(1, int(params.get("startIndex", 1)))
        count = min(200, max(0, int(params.get("count", 100))))
    except ValueError:
        raise ScimError(400, "startIndex and count must be integers", "invalidValue")
    page = users[start - 1 : start - 1 + count]
    return _scim_json({
        "schemas": [LIST_SCHEMA],
        "totalResults": len(users),
        "startIndex": start,
        "itemsPerPage": len(page),
        "Resources": [_user_resource(p) for p in page],
    })


@router.get("/scim/v2/Users/{user_id}")
def get_user(
    user_id: str,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    return _scim_json(_user_resource(_get_visible(db, actor, user_id)))


@router.post("/scim/v2/Users")
async def create_user(
    request: Request,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    body = await _json_body(request)
    email = (body.get("userName") or "").strip().lower()
    if not email:
        raise ScimError(400, "userName is required", "invalidValue")
    display = body.get("displayName") or (body.get("name") or {}).get("formatted") or ""
    sub = body.get("externalId")
    active = _parse_bool(body.get("active", True))

    tenant = db.get(Tenant, actor.tenant_id)
    existing = crud.find_principal_by_email(db, tenant, email)
    if existing is not None and existing.deleted_at is None:
        raise ScimError(409, f"User '{email}' already exists", "uniqueness")

    if existing is not None:
        # Re-provisioning a soft-deleted user: reactivate in place (fresh
        # lifecycle from the IdP's point of view; agents stay revoked).
        existing.deleted_at = None
        existing.active = active
        existing.display_name = display
        existing.sub = sub or existing.sub
        db.commit()
        audit.record_request(
            db, request, "user.created", tenant_id=tenant.id, actor=actor.label,
            detail={"email": email, "via": "scim", "reactivated": True},
        )
        principal = existing
    else:
        principal = crud.create_principal(
            db, request, actor.label,
            email=email, display_name=display,
            role=get_settings().default_role, sub=sub,
            event="user.created", tenant=tenant,
        )
        if not active:
            principal.active = False
            db.commit()

    return _scim_json(
        _user_resource(principal), 201,
        headers={"Location": f"/scim/v2/Users/{principal.id}"},
    )


@router.put("/scim/v2/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    body = await _json_body(request)
    p = _get_visible(db, actor, user_id)
    _apply_attrs(db, request, actor, p, {
        "userName": body.get("userName"),
        "displayName": body.get("displayName", (body.get("name") or {}).get("formatted")),
        "externalId": body.get("externalId"),
        "active": body.get("active"),
    })
    return _scim_json(_user_resource(p))


@router.patch("/scim/v2/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    body = await _json_body(request)
    p = _get_visible(db, actor, user_id)
    attrs: dict = {}
    for op in body.get("Operations", []):
        op_name = (op.get("op") or "").lower()
        if op_name not in ("add", "replace"):
            raise ScimError(400, f"Unsupported PATCH op: {op_name!r}", "invalidValue")
        path = (op.get("path") or "").strip()
        value = op.get("value")
        if not path:
            if not isinstance(value, dict):
                raise ScimError(400, "PATCH without path requires an object value",
                                "invalidValue")
            for k, v in value.items():
                attrs[k] = v
        else:
            # normalize e.g. name.formatted -> displayName
            key = {"name.formatted": "displayName"}.get(path, path)
            attrs[key] = value
    _apply_attrs(db, request, actor, p, {
        "userName": attrs.get("userName"),
        "displayName": attrs.get("displayName"),
        "externalId": attrs.get("externalId"),
        "active": attrs.get("active"),
    })
    return _scim_json(_user_resource(p))


@router.delete("/scim/v2/Users/{user_id}")
def delete_user(
    user_id: str,
    request: Request,
    actor: Actor = Depends(scim_actor),
    db: Session = Depends(get_db),
):
    p = _get_visible(db, actor, user_id)
    if crud._admin_capable(p.role) and not crud.other_admins_exist(db, p):
        raise ScimError(409, "Cannot delete the last admin-capable user", "mutability")
    try:
        crud.delete_principal(db, request, actor, p.id)
    except HTTPException as exc:
        raise ScimError(exc.status_code, str(exc.detail))
    return Response(status_code=204)


# ------------------------------------------------------------------- helpers


async def _json_body(request: Request) -> dict:
    """Parse the body regardless of content type (SCIM uses
    application/scim+json, which strict parsers reject)."""
    try:
        body = await request.json()
    except Exception:
        raise ScimError(400, "Request body must be JSON", "invalidSyntax")
    if not isinstance(body, dict):
        raise ScimError(400, "Request body must be a JSON object", "invalidSyntax")
    return body


def _apply_attrs(db: Session, request: Request, actor: Actor, p: Principal, attrs: dict) -> None:
    """Apply SCIM-writable attributes with the same invariants as the admin
    API (tenant-unique email, last-admin deactivation guard)."""
    changes: dict = {}

    email = attrs.get("userName")
    if email is not None:
        email = email.strip().lower()
        if not email:
            raise ScimError(400, "userName cannot be empty", "invalidValue")
        if email != p.email:
            tenant = db.get(Tenant, p.tenant_id)
            other = crud.find_principal_by_email(db, tenant, email)
            if other is not None and other.id != p.id:
                raise ScimError(409, f"User '{email}' already exists", "uniqueness")
            changes["email"] = [p.email, email]
            p.email = email

    display = attrs.get("displayName")
    if display is not None and display != p.display_name:
        changes["display_name"] = True
        p.display_name = display

    sub = attrs.get("externalId")
    if sub is not None and sub != p.sub:
        changes["sub"] = True
        p.sub = sub

    active = attrs.get("active")
    if active is not None:
        active = _parse_bool(active)
        if active != p.active:
            if not active and crud._admin_capable(p.role) and not crud.other_admins_exist(db, p):
                raise ScimError(409, "Cannot deactivate the last admin-capable user",
                                "mutability")
            changes["active"] = [p.active, active]
            p.active = active

    if changes:
        db.commit()
        audit.record_request(
            db, request, "user.updated", tenant_id=p.tenant_id, actor=actor.label,
            detail={"email": p.email, "via": "scim", "changes": changes},
        )
