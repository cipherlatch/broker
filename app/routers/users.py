from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_permission
from ..db import get_db
from ..models import Principal

router = APIRouter(prefix="/v1/users", tags=["users"])


class UserCreate(BaseModel):
    email: EmailStr
    display_name: str = ""
    role: str = "agent-manager"


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    active: bool | None = None


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    active: bool
    provisioned: bool  # has completed an OIDC login (sub bound)
    last_login_at: datetime | None
    created_at: datetime


def _out(p: Principal) -> UserOut:
    return UserOut(
        id=p.id,
        email=p.email,
        display_name=p.display_name,
        role=p.role.name if p.role else "",
        active=p.active,
        provisioned=p.sub is not None,
        last_login_at=p.last_login_at,
        created_at=p.created_at,
    )


@router.get("", response_model=list[UserOut])
def list_users(
    actor: Actor = Depends(require_permission("users:read")), db: Session = Depends(get_db)
):
    return [_out(p) for p in crud.list_principals(db, actor)]


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    principal = crud.create_principal(
        db,
        request,
        actor.label,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        tenant=crud.actor_tenant(db, actor),
        granted_by=actor,
    )
    return _out(principal)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    principal = crud.update_principal(
        db,
        request,
        actor,
        user_id,
        display_name=body.display_name,
        role=body.role,
        active=body.active,
    )
    return _out(principal)


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    return crud.delete_principal(db, request, actor, user_id)


@router.post("/{user_id}/archive")
def archive_user(
    user_id: str,
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    """Archive a soft-DELETED user: the row is removed (freeing the email for
    reuse) behind a graveyard tombstone. Refused while they still own objects."""
    return crud.archive_principal(db, request, actor, user_id)
