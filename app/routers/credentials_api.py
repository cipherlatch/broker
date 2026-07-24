from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_actor
from ..db import get_db
from ..models import DownstreamCredential

router = APIRouter(prefix="/v1/credentials", tags=["credentials"])


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    # For a static credential, the downstream secret. For a provider-backed
    # one, the provider seed (e.g. the SSH CA private key).
    secret: str = Field(min_length=1)
    owner_email: EmailStr | None = None
    # Dynamic credential provider (e.g. "ssh-ca"); omit for a static secret.
    provider: str | None = None
    provider_config: dict | None = None


class CredentialUpdate(BaseModel):
    description: str | None = None
    secret: str | None = None  # replaces the stored secret/seed when provided


class CredentialOut(BaseModel):
    id: str
    name: str
    description: str
    owner_email: str
    provider: str | None = None
    granted_agents: list[dict]
    created_at: datetime
    last_exchanged_at: datetime | None
    # The secret/seed itself is write-only and never returned.


def _out(c: DownstreamCredential) -> CredentialOut:
    return CredentialOut(
        id=c.id,
        name=c.name,
        description=c.description,
        owner_email=c.owner.email,
        provider=c.provider,
        granted_agents=[
            {"id": g.agent.id, "name": g.agent.name} for g in c.grants if g.agent is not None
        ],
        created_at=c.created_at,
        last_exchanged_at=c.last_exchanged_at,
    )


@router.get("", response_model=list[CredentialOut])
def list_credentials(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return [_out(c) for c in crud.visible_credentials(db, actor)]


@router.post("", response_model=CredentialOut, status_code=201)
def create_credential(
    body: CredentialCreate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    cred = crud.create_credential(
        db, request, actor,
        name=body.name, description=body.description,
        secret=body.secret, owner_email=body.owner_email,
        provider=body.provider, provider_config=body.provider_config,
    )
    return _out(cred)


@router.get("/{credential_id}", response_model=CredentialOut)
def get_credential(
    credential_id: str, actor: Actor = Depends(require_actor), db: Session = Depends(get_db)
):
    return _out(crud.get_visible_credential(db, actor, credential_id))


@router.patch("/{credential_id}", response_model=CredentialOut)
def update_credential(
    credential_id: str,
    body: CredentialUpdate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    cred = crud.update_credential(
        db, request, actor, credential_id, description=body.description, secret=body.secret
    )
    return _out(cred)


@router.delete("/{credential_id}")
def delete_credential(
    credential_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    return crud.delete_credential(db, request, actor, credential_id)


@router.post("/{credential_id}/grants/{agent_id}", response_model=CredentialOut)
def grant(
    credential_id: str,
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    return _out(crud.grant_credential(db, request, actor, credential_id, agent_id))


@router.delete("/{credential_id}/grants/{agent_id}", response_model=CredentialOut)
def revoke_grant(
    credential_id: str,
    agent_id: str,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    return _out(crud.revoke_credential_grant(db, request, actor, credential_id, agent_id))
