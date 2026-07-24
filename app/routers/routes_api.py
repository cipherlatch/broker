from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_actor
from ..db import get_db
from ..models import GatewayRoute

router = APIRouter(prefix="/v1/routes", tags=["gateway"])


class RouteCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=64)
    description: str = ""
    icon: str = ""
    upstream_base: str
    credential_name: str
    inject_mode: str = "bearer"
    inject_header: str = "Authorization"
    allowed_methods: list[str] = []
    allowed_path_prefixes: list[str] = []
    owner_email: str | None = None
    # Per granted agent; 0 = unlimited.
    rate_limit_per_minute: int = 0
    daily_quota: int = 0
    # Verify the upstream's TLS certificate. Disable only for testing against
    # self-signed / internal upstreams.
    verify_tls: bool = True
    # Stream git smart-HTTP (clone/fetch/push) through this route.
    git_http: bool = False
    # Ephemeral-credential passthrough (credential lineage):
    # {"prefixes": [...], "capture": {"prefixes": [...], "fields": [...]},
    # "ttl_seconds": N}. None = disabled.
    passthrough: dict | None = None


class RouteUpdate(BaseModel):
    description: str | None = None
    icon: str | None = None
    upstream_base: str | None = None
    inject_mode: str | None = None
    inject_header: str | None = None
    allowed_methods: list[str] | None = None
    allowed_path_prefixes: list[str] | None = None
    active: bool | None = None
    rate_limit_per_minute: int | None = None
    daily_quota: int | None = None
    verify_tls: bool | None = None
    git_http: bool | None = None
    # None = untouched; {} = clear; a dict = validate + set.
    passthrough: dict | None = None


class RouteOut(BaseModel):
    id: str
    slug: str
    description: str
    icon: str
    upstream_base: str
    owner_email: str
    credential_name: str
    inject_mode: str
    inject_header: str
    allowed_methods: list[str]
    allowed_path_prefixes: list[str]
    rate_limit_per_minute: int
    daily_quota: int
    verify_tls: bool
    git_http: bool
    passthrough: dict | None
    granted_agents: list[dict]
    active: bool
    created_at: datetime


def _out(r: GatewayRoute) -> RouteOut:
    return RouteOut(
        id=r.id,
        slug=r.slug,
        description=r.description,
        icon=r.icon,
        upstream_base=r.upstream_base,
        owner_email=r.owner.email,
        credential_name=r.credential.name if r.credential else "",
        inject_mode=r.inject_mode,
        inject_header=r.inject_header,
        allowed_methods=r.allowed_methods or [],
        allowed_path_prefixes=r.allowed_path_prefixes or [],
        rate_limit_per_minute=r.rate_limit_per_minute or 0,
        daily_quota=r.daily_quota or 0,
        verify_tls=r.verify_tls,
        git_http=r.git_http,
        passthrough=r.passthrough_config,
        granted_agents=[
            {"id": g.agent.id, "name": g.agent.name} for g in r.grants if g.agent is not None
        ],
        active=r.active,
        created_at=r.created_at,
    )


@router.get("", response_model=list[RouteOut])
def list_routes(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return [_out(r) for r in crud.visible_routes(db, actor)]


@router.get("/catalog")
def route_catalog(actor: Actor = Depends(require_actor)):
    """Static, curated templates of common upstreams for the create-route form.
    Non-secret; the caller still supplies credential + host."""
    from ..route_catalog import CATALOG

    return CATALOG


@router.post("", response_model=RouteOut, status_code=201)
def create_route(
    body: RouteCreate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    route = crud.create_route(
        db, request, actor,
        slug=body.slug, description=body.description, icon=body.icon,
        upstream_base=body.upstream_base,
        credential_name=body.credential_name, inject_mode=body.inject_mode,
        inject_header=body.inject_header, allowed_methods=body.allowed_methods,
        allowed_path_prefixes=body.allowed_path_prefixes, owner_email=body.owner_email,
        rate_limit_per_minute=body.rate_limit_per_minute, daily_quota=body.daily_quota,
        verify_tls=body.verify_tls, git_http=body.git_http,
        passthrough=body.passthrough,
    )
    return _out(route)


@router.get("/{route_id}", response_model=RouteOut)
def get_route(route_id: str, actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return _out(crud.get_visible_route(db, actor, route_id))


class RouteTest(BaseModel):
    path: str = "/"


@router.post("/{route_id}/test")
def test_route(
    route_id: str,
    body: RouteTest,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Owner-side connectivity test: one real GET through the route (credential
    injected, TLS honored), bypassing the agent-grant/path policy."""
    return crud.probe_route(db, request, actor, route_id, body.path)


@router.post("/{route_id}/detect-icon", response_model=RouteOut)
def detect_icon(
    route_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """(Re)detect the route icon from the upstream's favicon."""
    return _out(crud.detect_route_icon(db, request, actor, route_id))


class IconUrl(BaseModel):
    url: str


@router.post("/{route_id}/icon-from-url", response_model=RouteOut)
def route_icon_from_url(
    route_id: str, body: IconUrl, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """Set the route icon from a user-supplied image URL (for upstreams without a
    discoverable favicon, e.g. an API host whose brand favicon lives elsewhere)."""
    route, ok = crud.set_route_icon_from_url(db, request, actor, route_id, body.url)
    if not ok:
        raise HTTPException(422, "could not fetch a usable image from that URL")
    return _out(route)


@router.patch("/{route_id}", response_model=RouteOut)
def update_route(
    route_id: str,
    body: RouteUpdate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    route = crud.update_route(
        db, request, actor, route_id,
        description=body.description, upstream_base=body.upstream_base,
        inject_mode=body.inject_mode, inject_header=body.inject_header,
        allowed_methods=body.allowed_methods, allowed_path_prefixes=body.allowed_path_prefixes,
        active=body.active,
        rate_limit_per_minute=body.rate_limit_per_minute, daily_quota=body.daily_quota,
        verify_tls=body.verify_tls, git_http=body.git_http, icon=body.icon,
        passthrough=body.passthrough,
    )
    return _out(route)


@router.delete("/{route_id}")
def delete_route(
    route_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return crud.delete_route(db, request, actor, route_id)


@router.post("/{route_id}/grants/{agent_id}", response_model=RouteOut)
def grant(
    route_id: str, agent_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return _out(crud.grant_route(db, request, actor, route_id, agent_id))


@router.delete("/{route_id}/grants/{agent_id}", response_model=RouteOut)
def revoke_grant(
    route_id: str, agent_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return _out(crud.revoke_route_grant(db, request, actor, route_id, agent_id))
