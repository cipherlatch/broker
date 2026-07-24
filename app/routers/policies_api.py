from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_actor
from ..db import get_db
from ..models import Policy

router = APIRouter(prefix="/v1/policies", tags=["policies"])


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    # change_freeze | business_hours | cidr_fence — typed params per type.
    type: str
    params: dict = {}
    owner_email: EmailStr | None = None


class PolicyUpdate(BaseModel):
    description: str | None = None
    params: dict | None = None
    active: bool | None = None


class PolicyOut(BaseModel):
    id: str
    name: str
    description: str
    type: str
    params: dict
    owner_email: str
    active: bool
    attachments: list[dict]
    created_at: datetime


def _out(p: Policy) -> PolicyOut:
    return PolicyOut(
        id=p.id,
        name=p.name,
        description=p.description,
        type=p.type,
        params=p.params or {},
        owner_email=p.owner.email,
        active=p.active,
        attachments=[
            {"target_type": a.target_type, "target_id": a.target_id} for a in p.attachments
        ],
        created_at=p.created_at,
    )


@router.get("", response_model=list[PolicyOut])
def list_policies(actor: Actor = Depends(require_actor), db: Session = Depends(get_db)):
    return [_out(p) for p in crud.visible_policies(db, actor)]


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(
    body: PolicyCreate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    policy = crud.create_policy(
        db, request, actor,
        name=body.name, type=body.type, params=body.params,
        description=body.description, owner_email=body.owner_email,
    )
    return _out(policy)


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: str, actor: Actor = Depends(require_actor), db: Session = Depends(get_db)
):
    return _out(crud.get_visible_policy(db, actor, policy_id))


@router.patch("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    policy = crud.update_policy(
        db, request, actor, policy_id,
        description=body.description, params=body.params, active=body.active,
    )
    return _out(policy)


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return crud.delete_policy(db, request, actor, policy_id)


@router.post("/{policy_id}/attachments/{target_type}/{target_id}", response_model=PolicyOut)
def attach(
    policy_id: str, target_type: str, target_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return _out(crud.attach_policy(db, request, actor, policy_id, target_type, target_id))


@router.delete("/{policy_id}/attachments/{target_type}/{target_id}", response_model=PolicyOut)
def detach(
    policy_id: str, target_type: str, target_id: str, request: Request,
    actor: Actor = Depends(require_actor), db: Session = Depends(get_db),
):
    return _out(crud.detach_policy(db, request, actor, policy_id, target_type, target_id))
