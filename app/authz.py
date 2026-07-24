"""Request actors: who is calling, and what may they do.

Three authentication paths converge here:
- a session cookie from OIDC login (human principal with a Role),
- the X-Admin-Key header (machine/bootstrap credential; grants `*`,
  platform-admin, cross-tenant), or
- the X-Api-Key header (a scoped machine *service key* carrying a Role;
  tenant-plane only, never platform admin).

Permissions are flat strings from app.permissions. A bare permission is
own-scoped; the `:all` variant crosses ownership. Ownership rule: lookups the
actor may not see return 404 (not 403) so resource existence never leaks.
"""

import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db
from .models import Principal, ServiceKey
from .permissions import grants
from .security import hash_secret

_admin_key_header = APIKeyHeader(
    name="X-Admin-Key",
    auto_error=False,
    description="Machine/bootstrap admin key (BROKER_ADMIN_API_KEY). Grants all permissions.",
)

_service_key_header = APIKeyHeader(
    name="X-Api-Key",
    auto_error=False,
    description="Scoped machine service key (csk_...). Grants its assigned role's "
    "permissions within its tenant — never platform admin.",
)


@dataclass
class Actor:
    kind: str  # "user" | "system" | "scim" | "service"
    principal: Principal | None
    permissions: set[str] = field(default_factory=set)
    # The single tenant this actor operates within. Every data path filters by
    # it, so a human (even a tenant broker-admin) never crosses tenants; the
    # machine admin key targets a tenant via the X-Tenant header (default
    # "default"). None only during bootstrap before a tenant is resolved.
    tenant_id: str | None = None
    tenant_slug: str | None = None
    # Audit label for principal-less actors that aren't the admin key (SCIM).
    label_override: str | None = None

    def has(self, perm: str) -> bool:
        return grants(self.permissions, perm)

    @property
    def is_platform_admin(self) -> bool:
        # Only the machine admin key manages tenants / crosses the tenant plane.
        return self.kind == "system"

    @property
    def is_admin(self) -> bool:
        return "*" in self.permissions

    @property
    def label(self) -> str:
        if self.label_override:
            return self.label_override
        return self.principal.email if self.principal else "admin-key"

    @property
    def role_name(self) -> str:
        if self.principal is not None and self.principal.role is not None:
            return self.principal.role.name
        return "system"


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_ip:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            parts = [p.strip() for p in fwd.split(",") if p.strip()]
            # The client controls the left of the chain; the trusted proxy
            # appends the real peer on the right. Read the Nth-from-right value
            # so a spoofed leading entry cannot forge the source IP.
            hops = max(1, settings.trust_proxy_hops)
            if len(parts) >= hops:
                return parts[-hops]
            if parts:
                return parts[0]
    return request.client.host if request.client else ""


def get_actor(
    request: Request,
    admin_key: str | None = Depends(_admin_key_header),
    service_key: str | None = Depends(_service_key_header),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Actor | None:
    if admin_key and settings.admin_api_key_list:
        # Compare against every configured key (comma-list enables rotation);
        # no early exit, so timing doesn't reveal which entry matched.
        matched = False
        for candidate in settings.admin_api_key_list:
            if hmac.compare_digest(admin_key.encode(), candidate.encode()):
                matched = True
        if matched:
            # Machine admin key: scoped to the requested tenant (default
            # "default"). Tenant management endpoints are the only surface that
            # ignores this scope.
            from . import audit
            from .models import Tenant

            slug = request.headers.get("X-Tenant", "default").strip() or "default"
            tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
            # Every use of the standing root credential is audited — reads
            # included — so break-glass activity is alertable, not silent.
            audit.record_request(
                db, request, "admin_key.used",
                tenant_id=tenant.id if tenant else None, actor="admin-key",
                detail={"method": request.method, "path": request.url.path},
            )
            # Don't 404 or create on read: an unknown tenant resolves to a null
            # scope (reads see nothing); the first write auto-creates it via
            # crud.actor_tenant, exactly like the default tenant.
            return Actor(
                kind="system", principal=None, permissions={"*"},
                tenant_id=tenant.id if tenant else None,
                tenant_slug=slug,
            )
        raise HTTPException(401, "Invalid admin key")

    if service_key:
        # Scoped machine credential: a tenant-plane principal whose permissions
        # come from an assigned role. Distinct from the platform admin key —
        # it can never manage tenants or cross the tenant boundary (kind is
        # "service", so is_platform_admin stays False). Actions it takes are
        # audited under the "svc:<name>" label by the endpoints themselves,
        # exactly as a human principal's are; we don't emit a per-request event
        # (that would flood the very audit stream a monitoring key reads).
        sk = db.scalar(
            select(ServiceKey).where(
                ServiceKey.key_hash == hash_secret(service_key),
                ServiceKey.revoked_at.is_(None),
            )
        )
        if sk is None:
            raise HTTPException(401, "Invalid API key")
        # Bump last-used for operational visibility, throttled so a busy poller
        # doesn't write on every request. SQLite hands back naive datetimes
        # (Postgres, aware) — normalize before comparing so both backends work.
        now = datetime.now(timezone.utc)
        last = sk.last_used_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is None or (now - last).total_seconds() > 60:
            sk.last_used_at = now
            db.commit()
        perms = set(sk.role.permissions or []) if sk.role else set()
        return Actor(
            kind="service", principal=None, permissions=perms,
            tenant_id=sk.tenant_id,
            tenant_slug=sk.tenant.slug if sk.tenant else None,
            label_override=f"svc:{sk.name}",
        )

    pid = request.session.get("pid") if "session" in request.scope else None
    if pid:
        principal = db.get(Principal, pid)
        if principal and principal.active and principal.deleted_at is None:
            perms = set(principal.role.permissions or []) if principal.role else set()
            return Actor(
                kind="user", principal=principal, permissions=perms,
                tenant_id=principal.tenant_id,
                tenant_slug=principal.tenant.slug if principal.tenant else None,
            )
    return None


def require_actor(actor: Actor | None = Depends(get_actor)) -> Actor:
    if actor is None:
        raise HTTPException(401, "Authentication required")
    return actor


def require_permission(perm: str):
    def dependency(actor: Actor = Depends(require_actor)) -> Actor:
        if not actor.has(perm):
            raise HTTPException(403, f"Missing permission: {perm}")
        return actor

    return dependency


def require_platform_admin(actor: Actor = Depends(require_actor)) -> Actor:
    """Cross-tenant management (tenant CRUD). Only the machine admin key holds
    the platform plane; tenant broker-admins are confined to their tenant."""
    if not actor.is_platform_admin:
        raise HTTPException(403, "Platform admin (machine admin key) required")
    return actor
