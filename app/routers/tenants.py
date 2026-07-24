from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_platform_admin
from ..db import get_db
from ..models import Tenant

router = APIRouter(prefix="/v1/tenants", tags=["tenants"])


class TenantCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=64)
    name: str = ""


class TenantOut(BaseModel):
    id: str
    slug: str
    name: str
    created_at: datetime


def _out(t: Tenant) -> TenantOut:
    return TenantOut(id=t.id, slug=t.slug, name=t.name, created_at=t.created_at)


@router.get("", response_model=list[TenantOut])
def list_tenants(
    actor: Actor = Depends(require_platform_admin), db: Session = Depends(get_db)
):
    return [_out(t) for t in crud.list_tenants(db)]


@router.post("", response_model=TenantOut, status_code=201)
def create_tenant(
    body: TenantCreate,
    request: Request,
    actor: Actor = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    return _out(crud.create_tenant(db, request, actor, slug=body.slug, name=body.name))


@router.delete("/{slug}")
def delete_tenant(
    slug: str,
    request: Request,
    actor: Actor = Depends(require_platform_admin),
    db: Session = Depends(get_db),
):
    return crud.delete_tenant(db, request, actor, slug)
