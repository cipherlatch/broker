from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_permission
from ..db import get_db
from ..models import ServiceKey

router = APIRouter(prefix="/v1/service-keys", tags=["service-keys"])


class ServiceKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    role: str
    description: str = ""


class ServiceKeyOut(BaseModel):
    id: str
    name: str
    description: str
    role: str
    created_by: str
    active: bool
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ServiceKeyCreated(ServiceKeyOut):
    # The bearer value, returned exactly once at creation.
    api_key: str


def _out(k: ServiceKey) -> ServiceKeyOut:
    return ServiceKeyOut(
        id=k.id,
        name=k.name,
        description=k.description,
        role=k.role.name if k.role else "",
        created_by=k.created_by,
        active=k.revoked_at is None,
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        revoked_at=k.revoked_at,
    )


@router.get("", response_model=list[ServiceKeyOut])
def list_service_keys(
    actor: Actor = Depends(require_permission("service_keys:read")),
    db: Session = Depends(get_db),
):
    return [_out(k) for k in crud.list_service_keys(db, actor)]


@router.post("", response_model=ServiceKeyCreated, status_code=201)
def create_service_key(
    body: ServiceKeyCreate,
    request: Request,
    actor: Actor = Depends(require_permission("service_keys:manage")),
    db: Session = Depends(get_db),
):
    key, secret = crud.create_service_key(
        db, request, actor, name=body.name, role=body.role, description=body.description
    )
    return ServiceKeyCreated(**_out(key).model_dump(), api_key=secret)


@router.post("/{key_id}/revoke", response_model=ServiceKeyOut)
def revoke_service_key(
    key_id: str,
    request: Request,
    actor: Actor = Depends(require_permission("service_keys:manage")),
    db: Session = Depends(get_db),
):
    return _out(crud.revoke_service_key(db, request, actor, key_id))
