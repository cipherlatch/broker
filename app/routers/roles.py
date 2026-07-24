from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_permission
from ..db import get_db
from ..models import Role
from ..permissions import PERMISSIONS

router = APIRouter(prefix="/v1/roles", tags=["roles"])


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    permissions: list[str] = []


class RoleUpdate(BaseModel):
    description: str | None = None
    permissions: list[str] | None = None


class RoleOut(BaseModel):
    id: str
    name: str
    description: str
    permissions: list[str]
    builtin: bool
    created_at: datetime


def _out(r: Role) -> RoleOut:
    return RoleOut(
        id=r.id,
        name=r.name,
        description=r.description,
        permissions=r.permissions or [],
        builtin=r.builtin,
        created_at=r.created_at,
    )


@router.get("/permissions")
def permission_catalog(actor: Actor = Depends(require_permission("roles:read"))):
    return PERMISSIONS


@router.get("", response_model=list[RoleOut])
def list_roles(
    actor: Actor = Depends(require_permission("roles:read")), db: Session = Depends(get_db)
):
    crud.actor_tenant(db, actor)
    return [_out(r) for r in crud.list_roles(db, actor)]


@router.post("", response_model=RoleOut, status_code=201)
def create_role(
    body: RoleCreate,
    request: Request,
    actor: Actor = Depends(require_permission("roles:manage")),
    db: Session = Depends(get_db),
):
    role = crud.create_role(
        db, request, actor, name=body.name, description=body.description, permissions=body.permissions
    )
    return _out(role)


@router.patch("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: str,
    body: RoleUpdate,
    request: Request,
    actor: Actor = Depends(require_permission("roles:manage")),
    db: Session = Depends(get_db),
):
    role = crud.update_role(
        db, request, actor, role_id, description=body.description, permissions=body.permissions
    )
    return _out(role)


@router.delete("/{role_id}")
def delete_role(
    role_id: str,
    request: Request,
    actor: Actor = Depends(require_permission("roles:manage")),
    db: Session = Depends(get_db),
):
    return crud.delete_role(db, request, actor, role_id)
