from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, require_actor
from ..db import get_db
from ..models import Agent, AuditEvent

router = APIRouter(prefix="/v1/audit", tags=["audit"])


class AuditOut(BaseModel):
    id: str
    event: str
    tenant_id: str | None
    agent_id: str | None
    actor: str
    ip: str
    detail: dict
    created_at: datetime


def scoped_audit_query(actor: Actor):
    """The platform admin (machine key) sees all audit, including tenant-less
    system events (key rotations, pre-auth denials). Human tenant-admins are
    confined to their tenant. Within either scope, audit:read:all sees
    everything and audit:read only the actor's own agents/actions."""
    q = select(AuditEvent)
    if not actor.is_platform_admin:
        q = q.where(AuditEvent.tenant_id == actor.tenant_id)
    if not actor.has("audit:read:all"):
        if actor.principal is None or not actor.has("audit:read"):
            return q.where(AuditEvent.id.is_(None))  # nothing
        own_agents = select(Agent.id).where(Agent.owner_id == actor.principal.id).scalar_subquery()
        q = q.where(
            or_(AuditEvent.agent_id.in_(own_agents), AuditEvent.actor == actor.principal.email)
        )
    return q


def apply_before(q, db: Session, actor: Actor, before: str):
    """Keyset pagination anchor: only events strictly older than `before`
    (ordered by created_at, id — matching the listing order). The anchor is
    resolved through the actor's scope so a foreign event id 404s rather
    than leaking existence."""
    anchor = db.scalar(scoped_audit_query(actor).where(AuditEvent.id == before))
    if anchor is None:
        raise HTTPException(404, "Unknown audit event in 'before'")
    return q.where(
        or_(
            AuditEvent.created_at < anchor.created_at,
            and_(AuditEvent.created_at == anchor.created_at, AuditEvent.id < anchor.id),
        )
    )


@router.get("", response_model=list[AuditOut])
def list_events(
    response: Response,
    agent_id: str | None = None,
    event: str | None = None,
    actor_filter: str | None = Query(None, alias="actor"),
    limit: int = Query(100, ge=1, le=1000),
    before: str | None = Query(
        None,
        description="Keyset cursor: an event id from a previous page; returns "
        "strictly older events. When more pages exist the response carries "
        "an X-Next-Before header with the cursor for the next call.",
    ),
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    q = scoped_audit_query(actor).order_by(
        AuditEvent.created_at.desc(), AuditEvent.id.desc()
    )
    if agent_id:
        q = q.where(AuditEvent.agent_id == agent_id)
    if event:
        q = q.where(AuditEvent.event == event)
    if actor_filter:
        q = q.where(AuditEvent.actor == actor_filter)
    if before:
        q = apply_before(q, db, actor, before)

    rows = list(db.scalars(q.limit(limit + 1)).all())  # +1 = "more pages?" probe
    if len(rows) > limit:
        rows = rows[:limit]
        response.headers["X-Next-Before"] = rows[-1].id
    return [
        AuditOut(
            id=e.id,
            event=e.event,
            tenant_id=e.tenant_id,
            agent_id=e.agent_id,
            actor=e.actor,
            ip=e.ip,
            detail=e.detail,
            created_at=e.created_at,
        )
        for e in rows
    ]


class TombstoneOut(BaseModel):
    id: str
    kind: str
    original_id: str
    name: str
    snapshot: dict
    original_created_at: datetime | None
    archived_by: str
    archived_at: datetime


@router.get("/graveyard", response_model=list[TombstoneOut])
def graveyard(
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Tombstones of archived agents/users — the resolvable remains behind
    audit rows whose object was deleted."""
    return [
        TombstoneOut(
            id=t.id, kind=t.kind, original_id=t.original_id, name=t.name,
            snapshot=t.snapshot or {}, original_created_at=t.original_created_at,
            archived_by=t.archived_by, archived_at=t.archived_at,
        )
        for t in crud.list_graveyard(db, actor)
    ]
