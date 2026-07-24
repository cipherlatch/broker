"""Management API for the MCP authorization-server surfaces: registered
resources (the MCP servers this broker will mint tokens for), known CIMD
clients, and consent grants.

Registered resources and client revocation are governed by mcp:read /
mcp:manage. Consent grants are self-service: every signed-in user lists and
revokes their own without any permission; the tenant-wide view needs mcp:read
and tenant-wide revocation needs mcp:manage. Missing permissions surface as
404 (existence-hiding, matching the rest of the API).
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crud
from ..authz import Actor, client_ip, require_actor
from ..db import get_db
from ..models import ConsentGrant, MCPClient, MCPResource

router = APIRouter(prefix="/v1/mcp", tags=["mcp"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require(actor: Actor, perm: str) -> None:
    if not actor.has(perm):
        raise HTTPException(404, "Not found")


def _valid_resource_uri(uri: str) -> bool:
    parsed = urlparse(uri)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and not parsed.fragment


# ---------- registered resources ----------

class ResourceCreate(BaseModel):
    resource_uri: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    allowed_scopes: list[str] = []


class ResourceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    allowed_scopes: list[str] | None = None
    active: bool | None = None


class ResourceOut(BaseModel):
    id: str
    resource_uri: str
    name: str
    description: str
    allowed_scopes: list[str]
    active: bool
    created_at: datetime


def _resource_out(r: MCPResource) -> ResourceOut:
    return ResourceOut(
        id=r.id, resource_uri=r.resource_uri, name=r.name, description=r.description,
        allowed_scopes=r.allowed_scopes or [], active=r.active, created_at=r.created_at,
    )


@router.get("/resources", response_model=list[ResourceOut])
def list_resources(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    _require(actor, "mcp:read")
    rows = db.scalars(
        select(MCPResource).where(MCPResource.tenant_id == actor.tenant_id)
        .order_by(MCPResource.created_at)
    ).all()
    return [_resource_out(r) for r in rows]


@router.post("/resources", response_model=ResourceOut, status_code=201)
def create_resource(
    body: ResourceCreate, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    _require(actor, "mcp:manage")
    if not _valid_resource_uri(body.resource_uri):
        raise HTTPException(422, "resource_uri must be an absolute http(s) URI without fragment")
    tenant = crud.actor_tenant(db, actor)  # auto-creates on first write
    exists = db.scalar(select(MCPResource).where(
        MCPResource.tenant_id == tenant.id,
        MCPResource.resource_uri == body.resource_uri,
    ))
    if exists is not None:
        raise HTTPException(409, "A resource with this URI is already registered")
    row = MCPResource(
        tenant_id=tenant.id, resource_uri=body.resource_uri, name=body.name,
        description=body.description, allowed_scopes=body.allowed_scopes,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, "mcp_resource.created", tenant_id=tenant.id,
                 actor=actor.label, ip=client_ip(request),
                 detail={"resource_uri": row.resource_uri, "name": row.name,
                         "allowed_scopes": row.allowed_scopes or []})
    return _resource_out(row)


def _get_resource(db: Session, actor: Actor, resource_id: str) -> MCPResource:
    row = db.get(MCPResource, resource_id)
    if row is None or row.tenant_id != actor.tenant_id:
        raise HTTPException(404, "Not found")
    return row


@router.patch("/resources/{resource_id}", response_model=ResourceOut)
def update_resource(
    resource_id: str, body: ResourceUpdate, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    _require(actor, "mcp:manage")
    row = _get_resource(db, actor, resource_id)
    changes = {}
    for field in ("name", "description", "allowed_scopes", "active"):
        value = getattr(body, field)
        if value is not None and value != getattr(row, field):
            changes[field] = [getattr(row, field), value]
            setattr(row, field, value)
    if changes:
        db.commit()
        db.refresh(row)
        audit.record(db, "mcp_resource.updated", tenant_id=actor.tenant_id,
                     actor=actor.label, ip=client_ip(request),
                     detail={"resource_uri": row.resource_uri, "changes": changes})
    return _resource_out(row)


@router.delete("/resources/{resource_id}")
def delete_resource(
    resource_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    _require(actor, "mcp:manage")
    row = _get_resource(db, actor, resource_id)
    uri = row.resource_uri
    db.delete(row)
    db.commit()
    audit.record(db, "mcp_resource.deleted", tenant_id=actor.tenant_id,
                 actor=actor.label, ip=client_ip(request), detail={"resource_uri": uri})
    return {"deleted": True}


# ---------- known CIMD clients ----------

class ClientOut(BaseModel):
    id: str
    client_id_url: str
    name: str
    active: bool
    fetched_at: datetime
    created_at: datetime


@router.get("/clients", response_model=list[ClientOut])
def list_clients(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    _require(actor, "mcp:read")
    rows = db.scalars(select(MCPClient).order_by(MCPClient.created_at)).all()
    return [ClientOut(id=c.id, client_id_url=c.client_id_url, name=c.name,
                      active=c.active, fetched_at=c.fetched_at, created_at=c.created_at)
            for c in rows]


@router.post("/clients/{client_id}/revoke")
def revoke_client(
    client_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """Deactivate a CIMD client: authorize requests and code redemptions for
    it are refused from the next request on (no metadata refetch involved)."""
    _require(actor, "mcp:manage")
    row = db.get(MCPClient, client_id)
    if row is None:
        raise HTTPException(404, "Not found")
    if row.active:
        row.active = False
        db.commit()
        audit.record(db, "mcp_client.revoked", actor=actor.label,
                     ip=client_ip(request), detail={"client_id_url": row.client_id_url})
    return {"active": row.active}


@router.post("/clients/{client_id}/restore")
def restore_client(
    client_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    _require(actor, "mcp:manage")
    row = db.get(MCPClient, client_id)
    if row is None:
        raise HTTPException(404, "Not found")
    if not row.active:
        row.active = True
        db.commit()
        audit.record(db, "mcp_client.restored", actor=actor.label,
                     ip=client_ip(request), detail={"client_id_url": row.client_id_url})
    return {"active": row.active}


# ---------- consent grants ----------

class ConsentOut(BaseModel):
    id: str
    principal_email: str
    client_id_url: str
    resource: str
    scopes: list[str]
    created_at: datetime
    revoked_at: datetime | None


def _consent_out(c: ConsentGrant) -> ConsentOut:
    return ConsentOut(
        id=c.id, principal_email=c.principal.email if c.principal else "",
        client_id_url=c.client_id_url, resource=c.resource, scopes=c.scopes or [],
        created_at=c.created_at, revoked_at=c.revoked_at,
    )


@router.get("/consents", response_model=list[ConsentOut])
def list_consents(
    all: bool = False,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """Own consents by default; ?all=true is the tenant-wide view (mcp:read)."""
    query = select(ConsentGrant).where(ConsentGrant.tenant_id == actor.tenant_id)
    if all:
        _require(actor, "mcp:read")
    else:
        if actor.principal is None:
            _require(actor, "mcp:read")  # admin key has no "own" consents
        else:
            query = query.where(ConsentGrant.principal_id == actor.principal.id)
    rows = db.scalars(query.order_by(ConsentGrant.created_at)).all()
    return [_consent_out(c) for c in rows]


@router.post("/consents/{consent_id}/revoke")
def revoke_consent(
    consent_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """Revoking consent immediately invalidates outstanding tokens minted
    under it (verify_token checks the grant), not just future authorizes."""
    row = db.get(ConsentGrant, consent_id)
    if row is None or row.tenant_id != actor.tenant_id:
        raise HTTPException(404, "Not found")
    own = actor.principal is not None and row.principal_id == actor.principal.id
    if not own:
        _require(actor, "mcp:manage")
    if row.revoked_at is None:
        row.revoked_at = _now()
        db.commit()
        audit.record(db, "consent.revoked", tenant_id=actor.tenant_id,
                     actor=actor.label, ip=client_ip(request),
                     detail={"client_id": row.client_id_url, "resource": row.resource,
                             "principal_email": row.principal.email if row.principal else "",
                             "by_owner": own})
    return {"revoked": True}
