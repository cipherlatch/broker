"""Break-glass admin CLI: recover an admin without a network credential.

Its trust boundary is host/shell access (``docker exec`` / ``kubectl exec``),
not a bearer token — so a broker that has lost every usable admin *login* (IdP
outage, the last admin disabled, no ``BROKER_ADMIN_API_KEY`` configured) can
still be recovered without a standing, network-reachable ``*`` credential.

    python -m app.admin list [--tenant default]
    python -m app.admin promote you@example.com [--tenant default] [--name "You"]

``promote`` is idempotent: it creates the account, clears a soft-delete,
reactivates it, and/or sets its role to broker-admin as needed. A freshly
created account links to your OIDC identity by email at your next SSO login.
Every mutation is written to the audit log with actor ``admin-cli`` so the use
of break-glass is always visible.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from . import audit, crud
from .authz import Actor
from .db import get_engine
from .models import Principal

ACTOR_LABEL = "admin-cli"
ADMIN_ROLE = "broker-admin"


def _cli_request() -> Request:
    """A minimal ASGI request so shared crud/audit code runs unchanged; with
    no client in scope, audit rows record an empty IP (the shell is the trail)."""
    return Request({"type": "http", "headers": [], "client": None})


def _system_actor(tenant) -> Actor:
    # Same authority as the machine admin key, labelled so the audit trail
    # distinguishes host-CLI break-glass from network X-Admin-Key use.
    return Actor(
        kind="system",
        principal=None,
        permissions={"*"},
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        label_override=ACTOR_LABEL,
    )


def cmd_list(db: Session, args: argparse.Namespace) -> int:
    tenant = crud.get_or_create_tenant(db, args.tenant)
    db.commit()
    rows = db.scalars(
        select(Principal)
        .where(Principal.tenant_id == tenant.id, Principal.deleted_at.is_(None))
        .order_by(Principal.email)
    ).all()
    admins = [p for p in rows if crud._admin_capable(p.role) and p.active]
    print(f"Tenant '{tenant.slug}': {len(rows)} user(s), {len(admins)} active admin-capable.")
    if not admins:
        print("  WARNING: no active admin-capable user — run `promote` to recover.")
    for p in rows:
        tag = "ADMIN" if crud._admin_capable(p.role) else "     "
        state = "active" if p.active else "DISABLED"
        role = p.role.name if p.role else "-"
        print(f"  [{tag}] {p.email:<40} {role:<16} {state}")
    return 0


def cmd_promote(db: Session, args: argparse.Namespace) -> int:
    email = args.email.strip().lower()
    tenant = crud.get_or_create_tenant(db, args.tenant)
    req = _cli_request()
    actor = _system_actor(tenant)
    existing = crud.find_principal_by_email(db, tenant, email)

    if existing is not None and existing.deleted_at is not None:
        # Soft-deleted row holds the unique email, so a fresh create would
        # collide — clear the tombstone and promote in place. Revoked agents
        # stay revoked; recovery only needs the human login back.
        role_obj = crud.get_role(db, tenant, ADMIN_ROLE)
        existing.deleted_at = None
        existing.active = True
        existing.role_id = role_obj.id
        db.commit()
        audit.record_request(
            db, req, "user.updated", tenant_id=tenant.id, actor=ACTOR_LABEL,
            detail={"email": email, "changes": {"restored": True, "role": [None, ADMIN_ROLE]}},
        )
        print(f"Restored soft-deleted {email} as an active broker-admin.")
        return 0

    if existing is None:
        crud.create_principal(
            db, req, ACTOR_LABEL, email=email, display_name=args.name or "",
            role=ADMIN_ROLE, tenant=tenant,
        )
        print(f"Created {email} as broker-admin; links to SSO by email at next login.")
        return 0

    did = []
    if not existing.active:
        crud.update_principal(db, req, actor, existing.id, active=True)
        did.append("reactivated")
    if existing.role is None or existing.role.name != ADMIN_ROLE:
        crud.update_principal(db, req, actor, existing.id, role=ADMIN_ROLE)
        did.append(f"promoted to {ADMIN_ROLE}")
    if did:
        print(f"{email}: {', '.join(did)}.")
    else:
        print(f"{email} is already an active broker-admin; no change.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m app.admin",
        description="Break-glass admin recovery (run with host/shell access).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("list", help="List users and flag active admins.")
    pl.add_argument("--tenant", default="default")
    pl.set_defaults(func=cmd_list)

    pp = sub.add_parser("promote", help="Ensure an email is an active broker-admin.")
    pp.add_argument("email")
    pp.add_argument("--tenant", default="default")
    pp.add_argument("--name", default="", help="Display name when creating the account.")
    pp.set_defaults(func=cmd_promote)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db = Session(bind=get_engine())
    try:
        return args.func(db, args)
    except Exception as exc:  # surface a clean message, not a traceback
        detail = getattr(exc, "detail", None) or str(exc)
        print(f"error: {detail}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
