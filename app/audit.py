from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditEvent
from .observability import observe_audit_event


def record(
    db: Session,
    event: str,
    *,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    actor: str = "",
    ip: str = "",
    detail: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            event=event,
            tenant_id=tenant_id,
            agent_id=agent_id,
            actor=actor,
            ip=ip,
            detail=detail or {},
        )
    )
    db.commit()
    observe_audit_event(
        event, {"actor": actor, "ip": ip, "agent_id": agent_id, "detail": detail or {}}
    )


def record_request(
    db: Session,
    request: Request,
    event: str,
    *,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    actor: str = "",
    detail: dict | None = None,
) -> None:
    from .authz import client_ip

    record(
        db,
        event,
        tenant_id=tenant_id,
        agent_id=agent_id,
        actor=actor,
        ip=client_ip(request),
        detail=detail,
    )
