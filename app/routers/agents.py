from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_actor
from ..db import get_db
from ..models import Agent

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    icon: str = ""
    # Optional for logged-in users (defaults to self); required with the admin key.
    owner_email: EmailStr | None = None
    allowed_scopes: list[str] = []
    allowed_resources: list[str] = []
    keyring: str = "default"
    # Workload identity federation (set together): the agent authenticates
    # with a platform-issued JWT instead of a secret — none is issued at all.
    federated_issuer: str | None = None
    federated_subject: str | None = None


class AgentUpdate(BaseModel):
    description: str | None = None
    icon: str | None = None
    allowed_scopes: list[str] | None = None
    allowed_resources: list[str] | None = None
    keyring: str | None = None
    # Set both to bind; set both to "" to clear.
    federated_issuer: str | None = None
    federated_subject: str | None = None


class AgentOut(BaseModel):
    id: str
    name: str
    description: str
    icon: str
    client_id: str
    owner_email: str
    tenant: str
    allowed_scopes: list[str]
    allowed_resources: list[str]
    keyring: str
    federated_issuer: str | None = None
    federated_subject: str | None = None
    active: bool


class AgentCreated(AgentOut):
    # Returned exactly once; only the hash is stored. None for federated
    # (secretless) agents — no usable secret exists.
    client_secret: str | None


def _out(agent: Agent) -> AgentOut:
    return AgentOut(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        icon=agent.icon,
        client_id=agent.client_id,
        owner_email=agent.owner.email,
        tenant=agent.tenant.slug,
        allowed_scopes=agent.allowed_scopes or [],
        allowed_resources=agent.allowed_resources or [],
        keyring=agent.keyring or "default",
        federated_issuer=agent.federated_issuer,
        federated_subject=agent.federated_subject,
        active=agent.active,
    )


@router.post("", response_model=AgentCreated, status_code=201)
def create_agent(
    body: AgentCreate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    agent, secret = crud.create_agent(
        db,
        request,
        actor,
        name=body.name,
        description=body.description,
        icon=body.icon,
        allowed_scopes=body.allowed_scopes,
        allowed_resources=body.allowed_resources,
        owner_email=body.owner_email,
        keyring=body.keyring,
        federated_issuer=body.federated_issuer,
        federated_subject=body.federated_subject,
    )
    return AgentCreated(**_out(agent).model_dump(), client_secret=secret)


@router.get("", response_model=list[AgentOut])
def list_agents(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return [_out(a) for a in crud.visible_agents(db, actor)]


@router.get("/{agent_id}", response_model=AgentOut)
def get_agent(agent_id: str, actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return _out(crud.get_visible_agent(db, actor, agent_id))


@router.patch("/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: str,
    body: AgentUpdate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    agent = crud.update_agent(
        db,
        request,
        actor,
        agent_id,
        description=body.description,
        allowed_scopes=body.allowed_scopes,
        allowed_resources=body.allowed_resources,
        keyring=body.keyring,
        federated_issuer=body.federated_issuer,
        federated_subject=body.federated_subject,
        icon=body.icon,
    )
    return _out(agent)


class IconUrl(BaseModel):
    url: str


@router.post("/{agent_id}/icon-from-url", response_model=AgentOut)
def agent_icon_from_url(
    agent_id: str, body: IconUrl, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    """Set the agent's icon from a user-supplied image URL (agents have no
    upstream to auto-detect from)."""
    agent, ok = crud.set_agent_icon_from_url(db, request, actor, agent_id, body.url)
    if not ok:
        raise HTTPException(422, "could not fetch a usable image from that URL")
    return _out(agent)


@router.post("/{agent_id}/rotate", response_model=AgentCreated)
def rotate_secret(
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    agent, secret = crud.rotate_agent_secret(db, request, actor, agent_id)
    return AgentCreated(**_out(agent).model_dump(), client_secret=secret)


@router.post("/{agent_id}/revoke-tokens", response_model=AgentOut)
def revoke_tokens(
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Invalidate all tokens already issued to this agent (agent stays active)."""
    return _out(crud.revoke_agent_tokens(db, request, actor, agent_id))


class AuthKeyBody(BaseModel):
    jwk: dict | None = None  # public JWK, or null to clear


@router.put("/{agent_id}/auth-key", response_model=AgentOut)
def set_auth_key(
    agent_id: str,
    body: AuthKeyBody,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Register a public JWK for private_key_jwt auth, or null to clear it."""
    return _out(crud.set_agent_auth_key(db, request, actor, agent_id, body.jwk))


@router.delete("/{agent_id}", response_model=AgentOut)
def revoke_agent(
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    return _out(crud.revoke_agent(db, request, actor, agent_id))


@router.post("/{agent_id}/unrevoke", response_model=AgentOut)
def unrevoke_agent(
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Reactivate a revoked agent. Previously issued tokens stay dead."""
    return _out(crud.unrevoke_agent(db, request, actor, agent_id))


@router.post("/{agent_id}/archive")
def archive_agent(
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Archive a REVOKED agent: the row is removed (its name becomes reusable)
    and a graveyard tombstone keeps the audit trail resolvable."""
    return crud.archive_agent(db, request, actor, agent_id)
