"""Permission-enforcing operations shared by the JSON API and the web UI.

Every state change records an audit event with actor and IP. Bare permissions
are own-scoped; `:all` variants cross ownership. Out-of-scope lookups behave
exactly like missing resources (404) so existence never leaks across users.
"""

from datetime import datetime, timezone

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .authz import Actor
from .models import Agent, Principal, Role, ServiceKey, Tenant
from .permissions import BUILTIN_ROLES, PERMISSIONS
from .security import hash_secret, new_client_id, new_client_secret, new_service_key

DEFAULT_TENANT_SLUG = "default"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def seed_builtin_roles(db: Session, tenant: Tenant) -> None:
    """Create missing built-ins and keep existing ones in sync with the code
    definition — built-ins are user-immutable, so the catalog is authoritative
    (this is how deployed roles pick up newly added permissions)."""
    existing = {
        r.name: r for r in db.scalars(select(Role).where(Role.tenant_id == tenant.id)).all()
    }
    dirty = False
    for name, spec in BUILTIN_ROLES.items():
        role = existing.get(name)
        if role is None:
            db.add(
                Role(
                    tenant_id=tenant.id,
                    name=name,
                    description=spec["description"],
                    permissions=spec["permissions"],
                    builtin=True,
                )
            )
            dirty = True
        elif role.builtin and (role.permissions or []) != spec["permissions"]:
            role.permissions = spec["permissions"]
            role.description = spec["description"]
            dirty = True
    if dirty:
        db.flush()


def get_or_create_tenant(db: Session, slug: str = DEFAULT_TENANT_SLUG) -> Tenant:
    tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
    if tenant is None:
        tenant = Tenant(slug=slug, name=slug)
        db.add(tenant)
        db.flush()
    seed_builtin_roles(db, tenant)
    return tenant


def actor_tenant(db: Session, actor: "Actor") -> Tenant:
    """The tenant the actor operates within. Every create/list path resolves
    the tenant through here, so no operation can silently target another."""
    slug = actor.tenant_slug or DEFAULT_TENANT_SLUG
    return get_or_create_tenant(db, slug)


def _in_tenant(actor: "Actor", obj) -> bool:
    """A fetched object is visible only if it lives in the actor's tenant.
    Cross-tenant reads are treated as not-found (404), never 403."""
    return obj is not None and obj.tenant_id == actor.tenant_id


# --------------------------------------------------------------------- roles


def get_role(db: Session, tenant: Tenant, name: str) -> Role | None:
    return db.scalar(select(Role).where(Role.tenant_id == tenant.id, Role.name == name))


def list_roles(db: Session, actor: Actor) -> list[Role]:
    return list(
        db.scalars(
            select(Role)
            .where(Role.tenant_id == actor.tenant_id)
            .order_by(Role.builtin.desc(), Role.name)
        ).all()
    )


def _validate_permissions(perms: list[str]) -> list[str]:
    unknown = [p for p in perms if p != "*" and p not in PERMISSIONS]
    if unknown:
        raise HTTPException(422, f"Unknown permission(s): {', '.join(sorted(unknown))}")
    return sorted(set(perms))


def _assert_can_grant(actor: "Actor", permissions: list[str]) -> None:
    """A caller may only confer permissions it holds itself. Without this,
    a delegated `users:manage` / `service_keys:manage` / `roles:manage` holder
    could mint a user, service key, or role carrying `broker-admin` (`*`) and
    escalate to full tenant control. `*` in the actor's own set means it holds
    everything; otherwise every requested permission (including any request for
    `*`) must already be in the actor's effective permissions."""
    if "*" in actor.permissions:
        return
    missing = set(permissions) - actor.permissions
    if missing:
        raise HTTPException(
            403,
            "Cannot grant permission(s) you do not hold yourself: "
            + ", ".join(sorted(missing)),
        )


def create_role(
    db: Session, request: Request, actor: Actor, *, name: str, description: str, permissions: list[str]
) -> Role:
    tenant = actor_tenant(db, actor)
    name = name.strip()
    if not name:
        raise HTTPException(422, "Role name is required")
    if get_role(db, tenant, name):
        raise HTTPException(409, f"Role '{name}' already exists")
    perms = _validate_permissions(permissions)
    _assert_can_grant(actor, perms)
    role = Role(
        tenant_id=tenant.id,
        name=name,
        description=description.strip(),
        permissions=perms,
    )
    db.add(role)
    db.commit()
    audit.record_request(
        db, request, "role.created", tenant_id=tenant.id, actor=actor.label,
        detail={"name": name, "permissions": role.permissions},
    )
    return role


def update_role(
    db: Session, request: Request, actor: Actor, role_id: str,
    *, description: str | None = None, permissions: list[str] | None = None,
) -> Role:
    role = db.get(Role, role_id)
    if not _in_tenant(actor, role):
        raise HTTPException(404, "Role not found")
    if role.builtin:
        raise HTTPException(409, "Built-in roles cannot be modified")
    changes: dict = {}
    if description is not None and description != role.description:
        changes["description"] = True
        role.description = description
    if permissions is not None:
        new_perms = _validate_permissions(permissions)
        _assert_can_grant(actor, new_perms)
        if new_perms != (role.permissions or []):
            changes["permissions"] = [role.permissions, new_perms]
            role.permissions = new_perms
    if changes:
        db.commit()
        audit.record_request(
            db, request, "role.updated", tenant_id=role.tenant_id, actor=actor.label,
            detail={"name": role.name, "changes": changes},
        )
    return role


def delete_role(db: Session, request: Request, actor: Actor, role_id: str) -> dict:
    role = db.get(Role, role_id)
    if not _in_tenant(actor, role):
        raise HTTPException(404, "Role not found")
    if role.builtin:
        raise HTTPException(409, "Built-in roles cannot be deleted")
    in_use = db.scalar(select(Principal.id).where(Principal.role_id == role.id).limit(1))
    if in_use:
        raise HTTPException(409, "Role is assigned to users; reassign them first")
    key_in_use = db.scalar(select(ServiceKey.id).where(ServiceKey.role_id == role.id).limit(1))
    if key_in_use:
        raise HTTPException(409, "Role is assigned to a service key; revoke it first")
    db.delete(role)
    db.commit()
    audit.record_request(
        db, request, "role.deleted", tenant_id=role.tenant_id, actor=actor.label,
        detail={"name": role.name},
    )
    return {"deleted": role.name}


def _admin_capable(role: Role | None) -> bool:
    perms = set(role.permissions or []) if role else set()
    return "*" in perms or "users:manage" in perms


def any_active_admin_exists(db: Session) -> bool:
    """Cross-tenant: is there any live admin-capable login at all? Used by
    /readyz and startup to flag a broker whose only recovery path would be
    the host-shell CLI (no admin key configured, no active admin user)."""
    rows = db.scalars(
        select(Principal).where(
            Principal.active.is_(True), Principal.deleted_at.is_(None)
        )
    ).all()
    return any(_admin_capable(p.role) for p in rows)


def other_admins_exist(db: Session, excluding: Principal) -> bool:
    # Last-admin guard is per-tenant: another admin must exist in the same tenant.
    others = db.scalars(
        select(Principal).where(
            Principal.tenant_id == excluding.tenant_id,
            Principal.id != excluding.id,
            Principal.active.is_(True),
            Principal.deleted_at.is_(None),
        )
    ).all()
    return any(_admin_capable(p.role) for p in others)


# ------------------------------------------------------------- service keys


def list_service_keys(db: Session, actor: Actor) -> list[ServiceKey]:
    return list(
        db.scalars(
            select(ServiceKey)
            .where(ServiceKey.tenant_id == actor.tenant_id)
            .order_by(ServiceKey.created_at)
        ).all()
    )


def create_service_key(
    db: Session, request: Request, actor: Actor, *, name: str, role: str, description: str = ""
) -> tuple[ServiceKey, str]:
    """Mint a scoped machine credential carrying `role`. Returns (key, secret);
    the secret is shown once and only its hash is stored."""
    tenant = actor_tenant(db, actor)
    name = name.strip()
    if not name:
        raise HTTPException(422, "Service key name is required")
    if db.scalar(
        select(ServiceKey.id).where(
            ServiceKey.tenant_id == tenant.id, ServiceKey.name == name
        )
    ):
        raise HTTPException(409, f"Service key '{name}' already exists")
    role_obj = get_role(db, tenant, role)
    if role_obj is None:
        raise HTTPException(422, f"Unknown role '{role}'")
    # A service key carries its role's permissions; minting one is a
    # privilege-granting act, so it may not exceed what the caller holds.
    _assert_can_grant(actor, role_obj.permissions or [])
    raw = new_service_key()
    key = ServiceKey(
        tenant_id=tenant.id,
        role_id=role_obj.id,
        name=name,
        description=description.strip(),
        key_hash=hash_secret(raw),
        created_by=actor.label,
    )
    db.add(key)
    db.commit()
    audit.record_request(
        db, request, "service_key.created", tenant_id=tenant.id, actor=actor.label,
        detail={"name": name, "role": role_obj.name},
    )
    return key, raw


def revoke_service_key(db: Session, request: Request, actor: Actor, key_id: str) -> ServiceKey:
    key = db.get(ServiceKey, key_id)
    if not _in_tenant(actor, key):
        raise HTTPException(404, "Service key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        db.commit()
        audit.record_request(
            db, request, "service_key.revoked", tenant_id=key.tenant_id, actor=actor.label,
            detail={"name": key.name},
        )
    return key


# ---------------------------------------------------------------- principals


def find_principal_by_sub(db: Session, tenant: Tenant, sub: str) -> Principal | None:
    return db.scalar(
        select(Principal).where(Principal.tenant_id == tenant.id, Principal.sub == sub)
    )


def find_principal_by_email(db: Session, tenant: Tenant, email: str) -> Principal | None:
    return db.scalar(
        select(Principal).where(
            Principal.tenant_id == tenant.id, Principal.email == email.lower()
        )
    )


def create_principal(
    db: Session,
    request: Request,
    actor_label: str,
    *,
    email: str,
    display_name: str = "",
    role: str = "agent-manager",
    sub: str | None = None,
    event: str = "user.created",
    tenant: Tenant | None = None,
    granted_by: "Actor | None" = None,
) -> Principal:
    if tenant is None:
        tenant = get_or_create_tenant(db)  # default; callers pass tenant explicitly
    if find_principal_by_email(db, tenant, email):
        raise HTTPException(409, f"User '{email}' already exists")
    role_obj = get_role(db, tenant, role)
    if role_obj is None:
        raise HTTPException(422, f"Unknown role '{role}'")
    # Human-initiated creates pass `granted_by`; the new user's role may not
    # exceed the creator's own permissions. System provisioning (SSO JIT, SCIM,
    # bootstrap) passes none and is exempt — its role comes from trusted config.
    if granted_by is not None:
        _assert_can_grant(granted_by, role_obj.permissions or [])
    principal = Principal(
        tenant_id=tenant.id,
        email=email.lower(),
        display_name=display_name,
        role_id=role_obj.id,
        sub=sub,
    )
    db.add(principal)
    db.commit()
    audit.record_request(
        db, request, event, tenant_id=tenant.id, actor=actor_label,
        detail={"email": principal.email, "role": role_obj.name},
    )
    return principal


def update_principal(
    db: Session,
    request: Request,
    actor: Actor,
    principal_id: str,
    *,
    display_name: str | None = None,
    role: str | None = None,
    active: bool | None = None,
) -> Principal:
    principal = db.get(Principal, principal_id)
    if not _in_tenant(actor, principal) or principal.deleted_at is not None:
        raise HTTPException(404, "User not found")
    changes: dict = {}
    is_self = actor.principal is not None and actor.principal.id == principal.id

    if display_name is not None and display_name != principal.display_name:
        changes["display_name"] = [principal.display_name, display_name]
        principal.display_name = display_name

    if role is not None and (principal.role is None or role != principal.role.name):
        if is_self:
            raise HTTPException(409, "You cannot change your own role")
        tenant = db.get(Tenant, principal.tenant_id)
        role_obj = get_role(db, tenant, role)
        if role_obj is None:
            raise HTTPException(422, f"Unknown role '{role}'")
        # No promoting a user into a role more privileged than your own.
        _assert_can_grant(actor, role_obj.permissions or [])
        if (
            _admin_capable(principal.role)
            and not _admin_capable(role_obj)
            and not other_admins_exist(db, principal)
        ):
            raise HTTPException(409, "Cannot demote the last admin-capable user")
        changes["role"] = [principal.role.name if principal.role else None, role_obj.name]
        principal.role_id = role_obj.id

    if active is not None and active != principal.active:
        if is_self:
            raise HTTPException(409, "You cannot deactivate your own account")
        if not active and _admin_capable(principal.role) and not other_admins_exist(db, principal):
            raise HTTPException(409, "Cannot deactivate the last admin-capable user")
        changes["active"] = [principal.active, active]
        principal.active = active

    if changes:
        db.commit()
        audit.record_request(
            db, request, "user.updated", tenant_id=principal.tenant_id,
            actor=actor.label, detail={"email": principal.email, "changes": changes},
        )
    return principal


def delete_principal(db: Session, request: Request, actor: Actor, principal_id: str) -> dict:
    """Soft-delete a user and revoke every agent they own."""
    principal = db.get(Principal, principal_id)
    if not _in_tenant(actor, principal) or principal.deleted_at is not None:
        raise HTTPException(404, "User not found")
    if actor.principal is not None and actor.principal.id == principal.id:
        raise HTTPException(409, "You cannot delete your own account")
    if _admin_capable(principal.role) and not other_admins_exist(db, principal):
        raise HTTPException(409, "Cannot delete the last admin-capable user")

    owned = db.scalars(select(Agent).where(Agent.owner_id == principal.id)).all()
    revoked = []
    for agent in owned:
        if agent.active:
            agent.active = False
            agent.revoked_at = _now()
            revoked.append(agent.id)
    principal.active = False
    principal.deleted_at = _now()
    db.commit()

    for agent_id in revoked:
        audit.record_request(
            db, request, "agent.revoked", tenant_id=principal.tenant_id,
            agent_id=agent_id, actor=actor.label, detail={"reason": "owner_deleted"},
        )
    audit.record_request(
        db, request, "user.deleted", tenant_id=principal.tenant_id,
        actor=actor.label, detail={"email": principal.email, "agents_revoked": len(revoked)},
    )
    return {"deleted": principal.email, "agents_revoked": len(revoked)}


def list_principals(db: Session, actor: Actor, include_deleted: bool = False) -> list[Principal]:
    q = select(Principal).where(Principal.tenant_id == actor.tenant_id).order_by(
        Principal.created_at
    )
    if not include_deleted:
        q = q.where(Principal.deleted_at.is_(None))
    return list(db.scalars(q).all())


# -------------------------------------------------------------------- agents


def visible_agents(db: Session, actor: Actor) -> list[Agent]:
    q = select(Agent).where(Agent.tenant_id == actor.tenant_id).order_by(Agent.created_at)
    if not actor.has("agents:read:all"):
        if actor.principal is None or not actor.has("agents:read"):
            return []
        q = q.where(Agent.owner_id == actor.principal.id)
    return list(db.scalars(q).all())


def get_visible_agent(db: Session, actor: Actor, agent_id: str, action: str = "read") -> Agent:
    """404 unless the actor owns the agent (with the bare permission) or holds
    the :all variant, and it lives in the actor's tenant. 404 — not 403 — so
    existence never leaks across users or tenants."""
    agent = db.get(Agent, agent_id)
    if not _in_tenant(actor, agent):
        agent = None
    if agent is not None:
        if actor.has(f"agents:{action}:all"):
            return agent
        if (
            actor.principal is not None
            and agent.owner_id == actor.principal.id
            and actor.has(f"agents:{action}")
        ):
            return agent
    raise HTTPException(404, "Agent not found")


def _validate_keyring(keyring: str) -> str:
    from .config import get_settings
    from .keystore import DEFAULT_KEYRING, supports_named_keyrings, validate_keyring_name

    keyring = (keyring or DEFAULT_KEYRING).strip() or DEFAULT_KEYRING
    validate_keyring_name(keyring)
    if keyring != DEFAULT_KEYRING and not supports_named_keyrings(get_settings().keystore):
        raise HTTPException(
            422, f"The {get_settings().keystore} keystore supports only the default keyring"
        )
    return keyring


def _validate_federated(issuer: str | None, subject: str | None) -> tuple[str | None, str | None]:
    """Both-or-neither; the issuer must be platform-allowlisted."""
    from .federation import allowed_issuers

    issuer = (issuer or "").strip().rstrip("/")
    subject = (subject or "").strip()
    if not issuer and not subject:
        return None, None
    if not issuer or not subject:
        raise HTTPException(
            422, "federated_issuer and federated_subject must be set together"
        )
    if issuer not in allowed_issuers():
        raise HTTPException(
            422, "federated_issuer is not in BROKER_FEDERATED_ISSUERS"
        )
    return issuer, subject


def create_agent(
    db: Session,
    request: Request,
    actor: Actor,
    *,
    name: str,
    description: str = "",
    icon: str = "",
    allowed_scopes: list[str] | None = None,
    allowed_resources: list[str] | None = None,
    owner_email: str | None = None,
    keyring: str = "default",
    federated_issuer: str | None = None,
    federated_subject: str | None = None,
) -> tuple[Agent, str | None]:
    tenant = actor_tenant(db, actor)
    icon = _clean_icon(icon)
    keyring = _validate_keyring(keyring)
    federated_issuer, federated_subject = _validate_federated(federated_issuer, federated_subject)

    self_email = actor.principal.email if actor.principal else None
    if owner_email and owner_email.lower() != self_email:
        if not actor.has("agents:create:all"):
            raise HTTPException(403, "Missing permission: agents:create:all")
        owner = find_principal_by_email(db, tenant, owner_email)
        if owner is None or owner.deleted_at is not None:
            raise HTTPException(422, f"Owner '{owner_email}' is not a known user")
    elif actor.principal is not None:
        if not actor.has("agents:create"):
            raise HTTPException(403, "Missing permission: agents:create")
        owner = actor.principal
    else:
        raise HTTPException(422, "owner_email is required when using the admin key")

    if db.scalar(select(Agent).where(Agent.tenant_id == tenant.id, Agent.name == name)):
        raise HTTPException(409, f"Agent '{name}' already exists")

    # Secretless bootstrap: with a federated binding, no usable secret exists.
    # The stored digest is of a random value that is discarded, never shown —
    # secret auth can't succeed, and there is nothing to leak or rotate out.
    secret: str | None = None if federated_issuer else new_client_secret()
    agent = Agent(
        tenant_id=tenant.id,
        owner_id=owner.id,
        name=name,
        description=description,
        icon=icon,
        client_id=new_client_id(),
        secret_hash=hash_secret(secret if secret is not None else new_client_secret()),
        allowed_scopes=allowed_scopes or [],
        allowed_resources=allowed_resources or [],
        keyring=keyring,
        federated_issuer=federated_issuer,
        federated_subject=federated_subject,
    )
    db.add(agent)
    db.commit()
    audit.record_request(
        db, request, "agent.created", tenant_id=tenant.id, agent_id=agent.id,
        actor=actor.label,
        detail={"name": name, "owner": owner.email, "scopes": agent.allowed_scopes,
                "keyring": keyring, "federated": bool(federated_issuer)},
    )
    return agent, secret


def update_agent(
    db: Session,
    request: Request,
    actor: Actor,
    agent_id: str,
    *,
    description: str | None = None,
    allowed_scopes: list[str] | None = None,
    allowed_resources: list[str] | None = None,
    keyring: str | None = None,
    federated_issuer: str | None = None,
    federated_subject: str | None = None,
    icon: str | None = None,
) -> Agent:
    agent = get_visible_agent(db, actor, agent_id, action="update")
    changes: dict = {}
    if icon is not None:
        nv = _clean_icon(icon)
        if nv != agent.icon:
            changes["icon"] = True
            agent.icon = nv
    if federated_issuer is not None or federated_subject is not None:
        # "" for both clears the binding; anything else must validate as a pair.
        issuer, subject = _validate_federated(federated_issuer, federated_subject)
        if (issuer, subject) != (agent.federated_issuer, agent.federated_subject):
            changes["federated"] = [bool(agent.federated_issuer), bool(issuer)]
            agent.federated_issuer = issuer
            agent.federated_subject = subject
    if keyring is not None:
        keyring = _validate_keyring(keyring)
        if keyring != agent.keyring:
            changes["keyring"] = [agent.keyring, keyring]
            agent.keyring = keyring
    if description is not None and description != agent.description:
        changes["description"] = True
        agent.description = description
    if allowed_scopes is not None and allowed_scopes != (agent.allowed_scopes or []):
        changes["allowed_scopes"] = [agent.allowed_scopes, allowed_scopes]
        agent.allowed_scopes = allowed_scopes
    if allowed_resources is not None and allowed_resources != (agent.allowed_resources or []):
        changes["allowed_resources"] = [agent.allowed_resources, allowed_resources]
        agent.allowed_resources = allowed_resources
    if changes:
        db.commit()
        audit.record_request(
            db, request, "agent.updated", tenant_id=agent.tenant_id, agent_id=agent.id,
            actor=actor.label, detail={"name": agent.name, "changes": changes},
        )
    return agent


def rotate_agent_secret(db: Session, request: Request, actor: Actor, agent_id: str) -> tuple[Agent, str]:
    agent = get_visible_agent(db, actor, agent_id, action="rotate")
    secret = new_client_secret()
    agent.secret_hash = hash_secret(secret)
    agent.failed_attempts = 0
    agent.locked_until = None
    db.commit()
    audit.record_request(
        db, request, "agent.rotated", tenant_id=agent.tenant_id, agent_id=agent.id,
        actor=actor.label, detail={"name": agent.name},
    )
    return agent, secret


def revoke_agent(db: Session, request: Request, actor: Actor, agent_id: str) -> Agent:
    agent = get_visible_agent(db, actor, agent_id, action="revoke")
    if agent.active:
        agent.active = False
        agent.revoked_at = _now()
        db.commit()
        audit.record_request(
            db, request, "agent.revoked", tenant_id=agent.tenant_id, agent_id=agent.id,
            actor=actor.label, detail={"name": agent.name},
        )
    return agent


def unrevoke_agent(db: Session, request: Request, actor: Actor, agent_id: str) -> Agent:
    """Reactivate a revoked agent. Gated by the same authority that revokes
    (agents:revoke) — the operation is its inverse. Tokens minted before the
    revocation stay dead (token_gen bumped on unrevoke, so old tokens can't
    resurrect with the agent)."""
    agent = get_visible_agent(db, actor, agent_id, action="revoke")
    if not agent.active:
        agent.active = True
        agent.revoked_at = None
        agent.token_gen = (agent.token_gen or 0) + 1
        db.commit()
        audit.record_request(
            db, request, "agent.unrevoked", tenant_id=agent.tenant_id, agent_id=agent.id,
            actor=actor.label, detail={"name": agent.name},
        )
    return agent


def archive_agent(db: Session, request: Request, actor: Actor, agent_id: str) -> dict:
    """Archive (hard-delete) a REVOKED agent: remove the row — freeing its name
    for reuse — and leave a graveyard tombstone so the audit trail stays
    resolvable. Two-step by design: revoke first, then archive."""
    from .models import CredentialGrant, RouteGrant, Tombstone

    agent = get_visible_agent(db, actor, agent_id, action="revoke")
    if agent.active:
        raise HTTPException(409, "Agent is active — revoke it before archiving")

    snapshot = {
        "name": agent.name,
        "description": agent.description,
        "client_id": agent.client_id,
        "owner": agent.owner.email if agent.owner else None,
        "allowed_scopes": agent.allowed_scopes or [],
        "allowed_resources": agent.allowed_resources or [],
        "federated_issuer": agent.federated_issuer,
        "federated_subject": agent.federated_subject,
        "revoked_at": agent.revoked_at.isoformat() if agent.revoked_at else None,
    }
    tomb = Tombstone(
        tenant_id=agent.tenant_id, kind="agent", original_id=agent.id,
        name=agent.name, snapshot=snapshot, original_created_at=agent.created_at,
        archived_by=actor.label,
    )
    db.add(tomb)
    # Grants reference the agent without cascade — clear them explicitly.
    for grant in db.scalars(select(CredentialGrant).where(CredentialGrant.agent_id == agent.id)):
        db.delete(grant)
    for grant in db.scalars(select(RouteGrant).where(RouteGrant.agent_id == agent.id)):
        db.delete(grant)
    name, tenant_id, original_id = agent.name, agent.tenant_id, agent.id
    db.delete(agent)
    db.commit()
    audit.record_request(
        db, request, "agent.archived", tenant_id=tenant_id, agent_id=original_id,
        actor=actor.label, detail={"name": name, "tombstone": tomb.id},
    )
    return {"archived": name, "tombstone": tomb.id}


def archive_principal(db: Session, request: Request, actor: Actor, principal_id: str) -> dict:
    """Archive (hard-delete) a soft-DELETED user: remove the row — freeing the
    email for reuse — behind a tombstone. Refused while the user still owns
    objects (agents/credentials/routes/policies reference owner_id); archive or
    reassign those first."""
    from .models import DownstreamCredential, GatewayRoute, Policy, Tombstone

    principal = db.get(Principal, principal_id)
    if not _in_tenant(actor, principal):
        raise HTTPException(404, "User not found")
    if not actor.has("users:manage"):
        raise HTTPException(403, "Missing permission: users:manage")
    if principal.deleted_at is None:
        raise HTTPException(409, "User is not deleted — delete first, then archive")

    owned = {
        "agents": db.scalar(select(func.count()).select_from(Agent).where(
            Agent.owner_id == principal.id)),
        "credentials": db.scalar(select(func.count()).select_from(DownstreamCredential).where(
            DownstreamCredential.owner_id == principal.id)),
        "routes": db.scalar(select(func.count()).select_from(GatewayRoute).where(
            GatewayRoute.owner_id == principal.id)),
        "policies": db.scalar(select(func.count()).select_from(Policy).where(
            Policy.owner_id == principal.id)),
    }
    blocking = {k: v for k, v in owned.items() if v}
    if blocking:
        raise HTTPException(
            409, "User still owns objects: "
            + ", ".join(f"{v} {k}" for k, v in blocking.items())
            + ". Archive or reassign them first."
        )

    snapshot = {
        "email": principal.email,
        "display_name": principal.display_name,
        "sub": principal.sub,
        "role": principal.role.name if principal.role else None,
        "deleted_at": principal.deleted_at.isoformat() if principal.deleted_at else None,
        "last_login_at": principal.last_login_at.isoformat() if principal.last_login_at else None,
    }
    tomb = Tombstone(
        tenant_id=principal.tenant_id, kind="user", original_id=principal.id,
        name=principal.email, snapshot=snapshot, original_created_at=principal.created_at,
        archived_by=actor.label,
    )
    db.add(tomb)
    email, tenant_id = principal.email, principal.tenant_id
    db.delete(principal)
    db.commit()
    audit.record_request(
        db, request, "user.archived", tenant_id=tenant_id, actor=actor.label,
        detail={"email": email, "tombstone": tomb.id},
    )
    return {"archived": email, "tombstone": tomb.id}


def list_graveyard(db: Session, actor: Actor):
    from .models import Tombstone

    if not actor.has("audit:read:all"):
        raise HTTPException(404, "Not found")
    return db.scalars(
        select(Tombstone).where(Tombstone.tenant_id == actor.tenant_id)
        .order_by(Tombstone.archived_at.desc())
    ).all()


def tombstone_names(db: Session, tenant_id: str | None = None) -> dict[str, str]:
    """original_id -> display name for resolving audit rows whose object was
    archived."""
    from .models import Tombstone

    q = select(Tombstone)
    if tenant_id is not None:
        q = q.where(Tombstone.tenant_id == tenant_id)
    return {t.original_id: f"{t.name} (archived)" for t in db.scalars(q).all()}


def revoke_agent_tokens(db: Session, request: Request, actor: Actor, agent_id: str) -> Agent:
    """Mass-revoke: invalidate every token already issued to this agent by
    bumping its token generation. The agent stays usable (can mint new
    tokens); use revoke_agent to disable it entirely."""
    agent = get_visible_agent(db, actor, agent_id, action="rotate")
    agent.token_gen = (agent.token_gen or 0) + 1
    db.commit()
    audit.record_request(
        db, request, "agent.tokens_revoked", tenant_id=agent.tenant_id, agent_id=agent.id,
        actor=actor.label, detail={"name": agent.name},
    )
    return agent


def set_agent_auth_key(
    db: Session, request: Request, actor: Actor, agent_id: str, jwk: dict | None
) -> Agent:
    """Register (or clear) the agent's public key for private_key_jwt auth."""
    agent = get_visible_agent(db, actor, agent_id, action="update")
    if jwk is not None:
        if not isinstance(jwk, dict) or jwk.get("kty") not in ("EC", "RSA", "OKP") or "d" in jwk:
            raise HTTPException(422, "auth key must be a public JWK (EC/RSA/OKP, no private 'd')")
    agent.auth_public_jwk = jwk
    db.commit()
    audit.record_request(
        db, request, "agent.auth_key_set" if jwk else "agent.auth_key_cleared",
        tenant_id=agent.tenant_id, agent_id=agent.id, actor=actor.label,
        detail={"name": agent.name},
    )
    return agent


# --------------------------------------------------------------- credentials


def _cred_visible(actor: Actor, cred, action: str = "read") -> bool:
    if actor.has(f"credentials:{action}:all"):
        return True
    return (
        actor.principal is not None
        and cred.owner_id == actor.principal.id
        and actor.has(f"credentials:{action}")
    )


def visible_credentials(db: Session, actor: Actor):
    from .models import DownstreamCredential

    q = (
        select(DownstreamCredential)
        .where(DownstreamCredential.tenant_id == actor.tenant_id)
        .order_by(DownstreamCredential.created_at)
    )
    if not actor.has("credentials:read:all"):
        if actor.principal is None or not actor.has("credentials:read"):
            return []
        q = q.where(DownstreamCredential.owner_id == actor.principal.id)
    return list(db.scalars(q).all())


def get_visible_credential(db: Session, actor: Actor, credential_id: str, action: str = "read"):
    from .models import DownstreamCredential

    cred = db.get(DownstreamCredential, credential_id)
    if not _in_tenant(actor, cred) or not _cred_visible(actor, cred, action):
        raise HTTPException(404, "Credential not found")
    return cred


def _validate_provider(provider: str | None, provider_config: dict | None, seed: str) -> None:
    """A provider-backed credential's config + seed must be usable at create
    time, not at exchange time. Static credentials (provider=None) skip this."""
    if provider is None:
        return
    from . import credential_providers as cp

    if provider not in cp.VALID_PROVIDERS:
        raise HTTPException(422, f"Unknown credential provider '{provider}'")
    try:
        cp.get_provider(provider).validate_config(provider_config or {}, seed)
    except cp.ProviderError as exc:
        raise HTTPException(422, f"provider config invalid: {exc}")


def create_credential(
    db: Session,
    request: Request,
    actor: Actor,
    *,
    name: str,
    description: str,
    secret: str,
    icon: str = "",
    owner_email: str | None = None,
    provider: str | None = None,
    provider_config: dict | None = None,
) -> "DownstreamCredential":
    from . import secretbox
    from .models import DownstreamCredential

    tenant = actor_tenant(db, actor)
    name = name.strip()
    if not name:
        raise HTTPException(422, "Credential name is required")
    if not secret:
        # For a provider, `secret` carries the seed (e.g. the CA private key).
        raise HTTPException(422, "Secret value is required"
                            + (" (the provider seed)" if provider else ""))
    _validate_provider(provider, provider_config, secret)

    self_email = actor.principal.email if actor.principal else None
    if owner_email and owner_email.lower() != self_email:
        if not actor.has("credentials:update:all"):
            raise HTTPException(403, "Missing permission: credentials:update:all")
        owner = find_principal_by_email(db, tenant, owner_email)
        if owner is None or owner.deleted_at is not None:
            raise HTTPException(422, f"Owner '{owner_email}' is not a known user")
    elif actor.principal is not None:
        if not actor.has("credentials:create"):
            raise HTTPException(403, "Missing permission: credentials:create")
        owner = actor.principal
    else:
        raise HTTPException(422, "owner_email is required when using the admin key")

    from sqlalchemy import select as _select

    if db.scalar(
        _select(DownstreamCredential).where(
            DownstreamCredential.tenant_id == tenant.id, DownstreamCredential.name == name
        )
    ):
        raise HTTPException(409, f"Credential '{name}' already exists")

    cred = DownstreamCredential(
        tenant_id=tenant.id,
        owner_id=owner.id,
        name=name,
        description=description.strip(),
        icon=_clean_icon(icon),
        secret_encrypted=secretbox.encrypt(secret),
        provider=provider,
        provider_config=provider_config,
    )
    db.add(cred)
    db.commit()
    audit.record_request(
        db, request, "credential.created", tenant_id=tenant.id, actor=actor.label,
        detail={"name": name, "owner": owner.email, "provider": provider},
    )
    return cred


def update_credential(
    db: Session,
    request: Request,
    actor: Actor,
    credential_id: str,
    *,
    description: str | None = None,
    secret: str | None = None,
    icon: str | None = None,
    provider_config: dict | None = None,
):
    from . import secretbox

    cred = get_visible_credential(db, actor, credential_id, action="update")
    changes: dict = {}
    if description is not None and description != cred.description:
        changes["description"] = True
        cred.description = description
    if icon is not None:
        nv = _clean_icon(icon)
        if nv != cred.icon:
            changes["icon"] = True
            cred.icon = nv
    # A new config only applies to provider-backed credentials, and must be
    # usable with the seed it will run against (the replacement seed if one
    # is being set in the same call, else the stored one).
    new_config = provider_config if (provider_config is not None and cred.provider) else None
    if secret:
        _validate_provider(
            cred.provider,
            new_config if new_config is not None else cred.provider_config,
            secret,
        )
        cred.secret_encrypted = secretbox.encrypt(secret)
        changes["secret_replaced"] = True
    elif new_config is not None:
        _validate_provider(cred.provider, new_config, secretbox.decrypt(cred.secret_encrypted))
    if new_config is not None and new_config != cred.provider_config:
        changes["provider_config"] = True
        cred.provider_config = new_config
    if changes:
        db.commit()
        audit.record_request(
            db, request, "credential.updated", tenant_id=cred.tenant_id, actor=actor.label,
            detail={"name": cred.name, "changes": changes},
        )
    return cred


def delete_credential(db: Session, request: Request, actor: Actor, credential_id: str) -> dict:
    cred = get_visible_credential(db, actor, credential_id, action="delete")
    name, tenant_id = cred.name, cred.tenant_id
    db.delete(cred)  # grants cascade
    db.commit()
    audit.record_request(
        db, request, "credential.deleted", tenant_id=tenant_id, actor=actor.label,
        detail={"name": name},
    )
    return {"deleted": name}


def grant_credential(
    db: Session, request: Request, actor: Actor, credential_id: str, agent_id: str
):
    from .models import CredentialGrant

    cred = get_visible_credential(db, actor, credential_id, action="grant")
    agent = db.get(Agent, agent_id)
    if not _in_tenant(actor, agent):
        raise HTTPException(404, "Agent not found")
    existing = db.scalar(
        select(CredentialGrant).where(
            CredentialGrant.credential_id == cred.id, CredentialGrant.agent_id == agent.id
        )
    )
    if existing is None:
        db.add(CredentialGrant(credential_id=cred.id, agent_id=agent.id))
        db.commit()
        audit.record_request(
            db, request, "credential.granted", tenant_id=cred.tenant_id,
            agent_id=agent.id, actor=actor.label,
            detail={"credential": cred.name, "agent": agent.name},
        )
    return cred


def revoke_credential_grant(
    db: Session, request: Request, actor: Actor, credential_id: str, agent_id: str
):
    from .models import CredentialGrant

    cred = get_visible_credential(db, actor, credential_id, action="grant")
    grant = db.scalar(
        select(CredentialGrant).where(
            CredentialGrant.credential_id == cred.id, CredentialGrant.agent_id == agent_id
        )
    )
    if grant is not None:
        agent_name = grant.agent.name if grant.agent else agent_id
        db.delete(grant)
        db.commit()
        audit.record_request(
            db, request, "credential.grant_revoked", tenant_id=cred.tenant_id,
            agent_id=agent_id, actor=actor.label,
            detail={"credential": cred.name, "agent": agent_name},
        )
    return cred


# ------------------------------------------------------------- gateway routes


def _route_visible(actor: Actor, route, action: str = "read") -> bool:
    if actor.has(f"routes:{action}:all"):
        return True
    return (
        actor.principal is not None
        and route.owner_id == actor.principal.id
        and actor.has(f"routes:{action}")
    )


def visible_routes(db: Session, actor: Actor):
    from .models import GatewayRoute

    q = (
        select(GatewayRoute)
        .where(GatewayRoute.tenant_id == actor.tenant_id)
        .order_by(GatewayRoute.created_at)
    )
    if not actor.has("routes:read:all"):
        if actor.principal is None or not actor.has("routes:read"):
            return []
        q = q.where(GatewayRoute.owner_id == actor.principal.id)
    return list(db.scalars(q).all())


def get_visible_route(db: Session, actor: Actor, route_id: str, action: str = "read"):
    from .models import GatewayRoute

    route = db.get(GatewayRoute, route_id)
    if not _in_tenant(actor, route) or not _route_visible(actor, route, action):
        raise HTTPException(404, "Route not found")
    return route


def _clean_icon(icon: str) -> str:
    """User-facing icons are short emoji strings. data: URIs are set only by
    favicon auto-detection, never accepted from a form/API caller."""
    icon = (icon or "").strip()
    if icon.startswith("data:"):
        raise HTTPException(422, "icon must be a short emoji, not a data URI")
    if len(icon) > 32:
        raise HTTPException(422, "icon too long — use a single emoji")
    return icon


def create_route(
    db: Session,
    request: Request,
    actor: Actor,
    *,
    slug: str,
    description: str,
    icon: str = "",
    upstream_base: str,
    credential_name: str,
    inject_mode: str = "bearer",
    inject_header: str = "Authorization",
    allowed_methods: list[str] | None = None,
    allowed_path_prefixes: list[str] | None = None,
    owner_email: str | None = None,
    rate_limit_per_minute: int = 0,
    daily_quota: int = 0,
    verify_tls: bool = True,
    git_http: bool = False,
    passthrough: dict | None = None,
):
    from . import gateway_policy as gp
    from .models import DownstreamCredential, GatewayRoute

    tenant = actor_tenant(db, actor)

    self_email = actor.principal.email if actor.principal else None
    if owner_email and owner_email.lower() != self_email:
        if not actor.has("routes:update:all"):
            raise HTTPException(403, "Missing permission: routes:update:all")
        owner = find_principal_by_email(db, tenant, owner_email)
        if owner is None or owner.deleted_at is not None:
            raise HTTPException(422, f"Owner '{owner_email}' is not a known user")
    elif actor.principal is not None:
        if not actor.has("routes:create"):
            raise HTTPException(403, "Missing permission: routes:create")
        owner = actor.principal
    else:
        raise HTTPException(422, "owner_email is required when using the admin key")

    slug = gp.validate_slug(slug.strip())
    icon = _clean_icon(icon)
    upstream_base = gp.validate_upstream(upstream_base)
    inject_mode, inject_header = gp.validate_inject(inject_mode, inject_header)
    methods = gp.normalize_methods(allowed_methods or [])
    prefixes = gp.normalize_prefixes(allowed_path_prefixes or [])
    rate_limit_per_minute = _validate_limit(rate_limit_per_minute, "rate_limit_per_minute")
    daily_quota = _validate_limit(daily_quota, "daily_quota")
    passthrough = gp.validate_passthrough(passthrough)

    if db.scalar(select(GatewayRoute).where(GatewayRoute.tenant_id == tenant.id, GatewayRoute.slug == slug)):
        raise HTTPException(409, f"Route '{slug}' already exists")

    # The route's credential must be one the actor can see (own or :all).
    cred = db.scalar(
        select(DownstreamCredential).where(
            DownstreamCredential.tenant_id == tenant.id,
            DownstreamCredential.name == credential_name,
        )
    )
    if cred is None or not _cred_visible(actor, cred, "read"):
        raise HTTPException(422, f"Unknown or inaccessible credential '{credential_name}'")
    # The gateway injects the credential as an HTTP header. Provider-backed
    # material that isn't header-shaped (e.g. an SSH cert) can't ride a route.
    if cred.provider is not None:
        from . import credential_providers as cp

        if not cp.get_provider(cred.provider).injectable_as_header():
            raise HTTPException(
                422, f"Credential '{credential_name}' is provider-backed "
                f"({cred.provider}) and cannot be injected by the gateway; it "
                "is only obtainable via token exchange."
            )

    route = GatewayRoute(
        tenant_id=tenant.id,
        owner_id=owner.id,
        slug=slug,
        description=description.strip(),
        icon=icon,
        upstream_base=upstream_base,
        credential_id=cred.id,
        inject_mode=inject_mode,
        inject_header=inject_header,
        allowed_methods=methods,
        allowed_path_prefixes=prefixes,
        rate_limit_per_minute=rate_limit_per_minute,
        daily_quota=daily_quota,
        verify_tls=verify_tls,
        git_http=git_http,
        passthrough_config=passthrough,
    )
    db.add(route)
    db.commit()
    audit.record_request(
        db, request, "route.created", tenant_id=tenant.id, actor=actor.label,
        detail={"slug": slug, "upstream": upstream_base, "credential": credential_name,
                "methods": methods, "prefixes": prefixes,
                "rate_limit_per_minute": rate_limit_per_minute, "daily_quota": daily_quota,
                "verify_tls": verify_tls, "git_http": git_http,
                "passthrough": bool(passthrough)},
    )
    return route


def detect_route_icon(db: Session, request: Request, actor: Actor, route_id: str,
                      *, only_if_empty: bool = False) -> "object":
    """Best-effort: set the route's icon from the upstream's favicon. Honors the
    route's verify_tls. A user-set icon is preserved when only_if_empty=True
    (used right after create); the manual re-detect passes only_if_empty=False."""
    from . import favicon

    route = get_visible_route(db, actor, route_id, "update")
    if only_if_empty and route.icon:
        return route
    data_uri = favicon.fetch_favicon(route.upstream_base, route.verify_tls)
    if data_uri and data_uri != route.icon:
        route.icon = data_uri
        db.commit()
        audit.record_request(
            db, request, "route.icon_detected", tenant_id=route.tenant_id,
            actor=actor.label, detail={"slug": route.slug},
        )
    return route


def set_route_icon_from_url(db: Session, request: Request, actor: Actor, route_id: str,
                            url: str) -> tuple["object", bool]:
    """Fetch a user-supplied image URL and store it as the route's icon. Returns
    (route, ok) — ok is False if the URL didn't yield a usable image."""
    from . import favicon

    route = get_visible_route(db, actor, route_id, "update")
    data_uri = favicon.fetch_icon_url(url, route.verify_tls)
    if data_uri:
        route.icon = data_uri
        db.commit()
        audit.record_request(
            db, request, "route.icon_set", tenant_id=route.tenant_id,
            actor=actor.label, detail={"slug": route.slug},
        )
    return route, bool(data_uri)


def set_agent_icon_from_url(db: Session, request: Request, actor: Actor, agent_id: str,
                            url: str) -> tuple["object", bool]:
    """Fetch a user-supplied image URL and store it as the agent's icon."""
    from . import favicon

    agent = get_visible_agent(db, actor, agent_id, action="update")
    data_uri = favicon.fetch_icon_url(url)
    if data_uri:
        agent.icon = data_uri
        db.commit()
        audit.record_request(
            db, request, "agent.icon_set", tenant_id=agent.tenant_id, agent_id=agent.id,
            actor=actor.label, detail={"name": agent.name},
        )
    return agent, bool(data_uri)


def set_credential_icon_from_url(db: Session, request: Request, actor: Actor,
                                 credential_id: str, url: str) -> tuple["object", bool]:
    """Fetch a user-supplied image URL and store it as the credential's icon."""
    from . import favicon

    cred = get_visible_credential(db, actor, credential_id, action="update")
    data_uri = favicon.fetch_icon_url(url)
    if data_uri:
        cred.icon = data_uri
        db.commit()
        audit.record_request(
            db, request, "credential.icon_set", tenant_id=cred.tenant_id,
            actor=actor.label, detail={"name": cred.name},
        )
    return cred, bool(data_uri)


def set_icon_upload(db: Session, request: Request, actor: Actor, kind: str,
                    obj_id: str, data_uri: str) -> None:
    """Store a client-uploaded icon (canvas-resized data: URI) on an agent,
    route, or credential. Uploads ride a dedicated field so the generic `icon`
    form field can keep rejecting data: URIs outright (see _clean_icon)."""
    from . import favicon

    checked = favicon.validate_upload(data_uri)
    if checked is None:
        raise HTTPException(422, "Not a valid PNG, JPEG, WebP, GIF, or ICO image (max 50 KB)")
    if kind == "agent":
        obj = get_visible_agent(db, actor, obj_id, action="update")
        event, agent_id, detail = "agent.icon_set", obj.id, {"name": obj.name}
    elif kind == "route":
        obj = get_visible_route(db, actor, obj_id, "update")
        event, agent_id, detail = "route.icon_set", None, {"slug": obj.slug}
    elif kind == "credential":
        obj = get_visible_credential(db, actor, obj_id, action="update")
        event, agent_id, detail = "credential.icon_set", None, {"name": obj.name}
    else:
        raise HTTPException(422, f"Unknown icon target '{kind}'")
    obj.icon = checked
    db.commit()
    audit.record_request(
        db, request, event, tenant_id=obj.tenant_id, agent_id=agent_id,
        actor=actor.label, detail=detail,
    )


def _validate_limit(value: int, name: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or value < 0:
        raise HTTPException(422, f"{name} must be a non-negative integer (0 = unlimited)")
    return value


def update_route(
    db: Session, request: Request, actor: Actor, route_id: str, *,
    description: str | None = None, upstream_base: str | None = None,
    inject_mode: str | None = None, inject_header: str | None = None,
    allowed_methods: list[str] | None = None, allowed_path_prefixes: list[str] | None = None,
    active: bool | None = None,
    rate_limit_per_minute: int | None = None, daily_quota: int | None = None,
    credential_name: str | None = None, verify_tls: bool | None = None,
    git_http: bool | None = None, icon: str | None = None,
    passthrough: dict | str | None = None,
):
    # passthrough: None = untouched; {} or "" = clear; a dict = validate + set.
    from . import gateway_policy as gp
    from .models import DownstreamCredential

    route = get_visible_route(db, actor, route_id, "update")
    changes: dict = {}
    if credential_name is not None and (
        route.credential is None or credential_name != route.credential.name
    ):
        cred = db.scalar(
            select(DownstreamCredential).where(
                DownstreamCredential.tenant_id == route.tenant_id,
                DownstreamCredential.name == credential_name,
            )
        )
        if cred is None or not _cred_visible(actor, cred, "read"):
            raise HTTPException(422, f"Unknown or inaccessible credential '{credential_name}'")
        changes["credential"] = [route.credential.name if route.credential else None, cred.name]
        route.credential_id = cred.id
    if rate_limit_per_minute is not None:
        nv = _validate_limit(rate_limit_per_minute, "rate_limit_per_minute")
        if nv != (route.rate_limit_per_minute or 0):
            changes["rate_limit_per_minute"] = [route.rate_limit_per_minute, nv]
            route.rate_limit_per_minute = nv
    if daily_quota is not None:
        nv = _validate_limit(daily_quota, "daily_quota")
        if nv != (route.daily_quota or 0):
            changes["daily_quota"] = [route.daily_quota, nv]
            route.daily_quota = nv
    if description is not None and description != route.description:
        changes["description"] = True
        route.description = description
    if upstream_base is not None:
        nb = gp.validate_upstream(upstream_base)
        if nb != route.upstream_base:
            changes["upstream_base"] = [route.upstream_base, nb]
            route.upstream_base = nb
    if inject_mode is not None or inject_header is not None:
        mode, header = gp.validate_inject(
            inject_mode or route.inject_mode, inject_header or route.inject_header
        )
        if (mode, header) != (route.inject_mode, route.inject_header):
            changes["inject"] = [route.inject_mode, mode]
            route.inject_mode, route.inject_header = mode, header
    if allowed_methods is not None:
        nm = gp.normalize_methods(allowed_methods)
        if nm != (route.allowed_methods or []):
            changes["allowed_methods"] = [route.allowed_methods, nm]
            route.allowed_methods = nm
    if allowed_path_prefixes is not None:
        np = gp.normalize_prefixes(allowed_path_prefixes)
        if np != (route.allowed_path_prefixes or []):
            changes["allowed_path_prefixes"] = [route.allowed_path_prefixes, np]
            route.allowed_path_prefixes = np
    if verify_tls is not None and verify_tls != route.verify_tls:
        changes["verify_tls"] = [route.verify_tls, verify_tls]
        route.verify_tls = verify_tls
    if git_http is not None and git_http != route.git_http:
        changes["git_http"] = [route.git_http, git_http]
        route.git_http = git_http
    if passthrough is not None:
        nv = gp.validate_passthrough(passthrough)
        if nv != route.passthrough_config:
            changes["passthrough"] = [bool(route.passthrough_config), bool(nv)]
            route.passthrough_config = nv
    if icon is not None:
        nv = _clean_icon(icon)
        if nv != route.icon:
            changes["icon"] = True  # value may be a data URI — don't log it
            route.icon = nv
    if active is not None and active != route.active:
        changes["active"] = [route.active, active]
        route.active = active
    if changes:
        db.commit()
        audit.record_request(
            db, request, "route.updated", tenant_id=route.tenant_id, actor=actor.label,
            detail={"slug": route.slug, "changes": changes},
        )
    return route


def probe_route(db: Session, request: Request, actor: Actor, route_id: str,
                path: str = "/", method: str = "GET") -> dict:
    """Owner-side connectivity test: fire one real request through the route's
    exact config (inject the credential, honor verify_tls) and report what came
    back. Bypasses the agent-grant/path policy — the owner is testing their own
    route. GET only, so it can't mutate the upstream."""
    import base64

    import httpx

    from . import gateway_policy as gp, secretbox

    route = get_visible_route(db, actor, route_id)
    secret = secretbox.decrypt(route.credential.secret_encrypted) if route.credential else ""
    if route.git_http:
        userpass = secret if ":" in secret else f"oauth2:{secret}"
        headers = {"Authorization": "Basic " + base64.b64encode(userpass.encode()).decode()}
    else:
        name, value = gp.injected_auth_header(route.inject_mode, route.inject_header, secret)
        headers = {name: value}
    url = gp.build_upstream_url(route, (path or "/").lstrip("/"))

    result: dict
    try:
        with httpx.Client(verify=route.verify_tls, timeout=10.0) as client:
            resp = client.request("GET", url, headers=headers)
        ok = resp.status_code < 400
        note = "" if ok else (" — credential rejected? check the injected format"
                              if resp.status_code in (401, 403) else "")
        result = {"ok": ok, "reached": True, "status": resp.status_code,
                  "detail": f"HTTP {resp.status_code} from upstream{note}"}
    except httpx.ConnectError as exc:
        msg = str(exc).lower()
        if "certificate" in msg or "ssl" in msg or "verify failed" in msg:
            detail = ("TLS verification failed — the upstream certificate isn't trusted. "
                      "For a self-signed / internal endpoint, enable 'Disable upstream TLS verification'.")
        else:
            detail = "could not reach the upstream (connection refused, DNS, or wrong host)"
        result = {"ok": False, "reached": False, "status": None, "detail": detail}
    except httpx.TimeoutException:
        result = {"ok": False, "reached": False, "status": None, "detail": "upstream timed out"}
    except httpx.HTTPError as exc:
        result = {"ok": False, "reached": False, "status": None,
                  "detail": f"request failed ({type(exc).__name__})"}

    audit.record_request(
        db, request, "route.tested", tenant_id=route.tenant_id, actor=actor.label,
        detail={"slug": route.slug, "path": path, "status": result.get("status"),
                "ok": result["ok"]},
    )
    return result


def delete_route(db: Session, request: Request, actor: Actor, route_id: str) -> dict:
    route = get_visible_route(db, actor, route_id, "delete")
    slug, tenant_id = route.slug, route.tenant_id
    db.delete(route)  # grants cascade
    db.commit()
    audit.record_request(
        db, request, "route.deleted", tenant_id=tenant_id, actor=actor.label,
        detail={"slug": slug},
    )
    return {"deleted": slug}


def grant_route(db: Session, request: Request, actor: Actor, route_id: str, agent_id: str):
    from .models import RouteGrant

    route = get_visible_route(db, actor, route_id, "grant")
    agent = db.get(Agent, agent_id)
    if not _in_tenant(actor, agent):
        raise HTTPException(404, "Agent not found")
    if not db.scalar(
        select(RouteGrant).where(RouteGrant.route_id == route.id, RouteGrant.agent_id == agent.id)
    ):
        db.add(RouteGrant(route_id=route.id, agent_id=agent.id))
        db.commit()
        audit.record_request(
            db, request, "route.granted", tenant_id=route.tenant_id, agent_id=agent.id,
            actor=actor.label, detail={"route": route.slug, "agent": agent.name},
        )
    return route


def revoke_route_grant(db: Session, request: Request, actor: Actor, route_id: str, agent_id: str):
    from .models import RouteGrant

    route = get_visible_route(db, actor, route_id, "grant")
    grant = db.scalar(
        select(RouteGrant).where(RouteGrant.route_id == route.id, RouteGrant.agent_id == agent_id)
    )
    if grant is not None:
        agent_name = grant.agent.name if grant.agent else agent_id
        db.delete(grant)
        db.commit()
        audit.record_request(
            db, request, "route.grant_revoked", tenant_id=route.tenant_id, agent_id=agent_id,
            actor=actor.label, detail={"route": route.slug, "agent": agent_name},
        )
    return route


# -------------------------------------------------------------------- policies


def _policy_visible(actor: Actor, policy, action: str = "read") -> bool:
    if actor.has(f"policies:{action}:all"):
        return True
    return (
        actor.principal is not None
        and policy.owner_id == actor.principal.id
        and actor.has(f"policies:{action}")
    )


def visible_policies(db: Session, actor: Actor):
    from .models import Policy

    q = select(Policy).where(Policy.tenant_id == actor.tenant_id).order_by(Policy.created_at)
    if not actor.has("policies:read:all"):
        if actor.principal is None or not actor.has("policies:read"):
            return []
        q = q.where(Policy.owner_id == actor.principal.id)
    return db.scalars(q).all()


def get_visible_policy(db: Session, actor: Actor, policy_id: str, action: str = "read"):
    from .models import Policy

    policy = db.get(Policy, policy_id)
    if policy is None or policy.tenant_id != actor.tenant_id or not _policy_visible(
        actor, policy, action
    ):
        raise HTTPException(404, "Policy not found")
    return policy


def create_policy(
    db: Session, request: Request, actor: Actor, *,
    name: str, type: str, params: dict, description: str = "",
    owner_email: str | None = None,
):
    from . import policy_native
    from .models import Policy

    tenant = actor_tenant(db, actor)
    self_email = actor.principal.email if actor.principal else None
    if owner_email and owner_email.lower() != self_email:
        if not actor.has("policies:update:all"):
            raise HTTPException(403, "Missing permission: policies:update:all")
        owner = find_principal_by_email(db, tenant, owner_email)
        if owner is None or owner.deleted_at is not None:
            raise HTTPException(422, f"Owner '{owner_email}' is not a known user")
    elif actor.principal is not None:
        if not actor.has("policies:create"):
            raise HTTPException(403, "Missing permission: policies:create")
        owner = actor.principal
    else:
        raise HTTPException(422, "owner_email is required when using the admin key")

    name = name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    if db.scalar(select(Policy).where(Policy.tenant_id == tenant.id, Policy.name == name)):
        raise HTTPException(409, f"Policy '{name}' already exists")
    params = policy_native.validate_params(type, params or {})

    policy = Policy(
        tenant_id=tenant.id, owner_id=owner.id, name=name,
        description=description.strip(), type=type, params=params,
    )
    db.add(policy)
    db.commit()
    audit.record_request(
        db, request, "policy.created", tenant_id=tenant.id, actor=actor.label,
        detail={"name": name, "type": type, "params": params},
    )
    return policy


def update_policy(
    db: Session, request: Request, actor: Actor, policy_id: str, *,
    description: str | None = None, params: dict | None = None,
    active: bool | None = None,
):
    from . import policy_native

    policy = get_visible_policy(db, actor, policy_id, "update")
    changes: dict = {}
    if params is not None:
        nv = policy_native.validate_params(policy.type, params)
        if nv != policy.params:
            changes["params"] = [policy.params, nv]
            policy.params = nv
    if description is not None and description != policy.description:
        changes["description"] = True
        policy.description = description
    if active is not None and active != policy.active:
        changes["active"] = [policy.active, active]
        policy.active = active
    if changes:
        db.commit()
        audit.record_request(
            db, request, "policy.updated", tenant_id=policy.tenant_id, actor=actor.label,
            detail={"name": policy.name, "changes": changes},
        )
    return policy


def delete_policy(db: Session, request: Request, actor: Actor, policy_id: str) -> dict:
    policy = get_visible_policy(db, actor, policy_id, "delete")
    name, tenant_id = policy.name, policy.tenant_id
    detached = len(policy.attachments)
    db.delete(policy)  # attachments cascade
    db.commit()
    audit.record_request(
        db, request, "policy.deleted", tenant_id=tenant_id, actor=actor.label,
        detail={"name": name, "attachments_removed": detached},
    )
    return {"deleted": name, "attachments_removed": detached}


def _policy_target(db: Session, actor: Actor, target_type: str, target_id: str):
    """Resolve + name an attachment target inside the actor's tenant."""
    from .models import GatewayRoute

    if target_type == "route":
        target = db.get(GatewayRoute, target_id)
        label = f"/gw/{target.slug}" if target is not None else None
    elif target_type == "agent":
        target = db.get(Agent, target_id)
        label = target.name if target is not None else None
    else:
        raise HTTPException(422, "target_type must be 'route' or 'agent'")
    if target is None or not _in_tenant(actor, target):
        raise HTTPException(404, "Target not found")
    return target, label


def attach_policy(
    db: Session, request: Request, actor: Actor, policy_id: str,
    target_type: str, target_id: str,
):
    from .models import PolicyAttachment

    policy = get_visible_policy(db, actor, policy_id, "apply")
    _, label = _policy_target(db, actor, target_type, target_id)
    existing = db.scalar(
        select(PolicyAttachment).where(
            PolicyAttachment.policy_id == policy.id,
            PolicyAttachment.target_type == target_type,
            PolicyAttachment.target_id == target_id,
        )
    )
    if existing is None:
        db.add(PolicyAttachment(policy_id=policy.id, target_type=target_type,
                                target_id=target_id))
        db.commit()
        audit.record_request(
            db, request, "policy.attached", tenant_id=policy.tenant_id, actor=actor.label,
            detail={"policy": policy.name, "target_type": target_type, "target": label},
        )
    return policy


def detach_policy(
    db: Session, request: Request, actor: Actor, policy_id: str,
    target_type: str, target_id: str,
):
    from .models import PolicyAttachment

    policy = get_visible_policy(db, actor, policy_id, "apply")
    attachment = db.scalar(
        select(PolicyAttachment).where(
            PolicyAttachment.policy_id == policy.id,
            PolicyAttachment.target_type == target_type,
            PolicyAttachment.target_id == target_id,
        )
    )
    if attachment is not None:
        db.delete(attachment)
        db.commit()
        audit.record_request(
            db, request, "policy.detached", tenant_id=policy.tenant_id, actor=actor.label,
            detail={"policy": policy.name, "target_type": target_type,
                    "target_id": target_id},
        )
    return policy


# --------------------------------------------------------------------- tenants


TENANT_SLUG_RE = None  # lazy


def _valid_tenant_slug(slug: str) -> str:
    import re

    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", slug or ""):
        raise HTTPException(422, "tenant slug must be lowercase alphanumeric/dash/underscore")
    return slug


def list_tenants(db: Session) -> list[Tenant]:
    """Platform-admin only: the full cross-tenant list."""
    return list(db.scalars(select(Tenant).order_by(Tenant.created_at)).all())


def create_tenant(db: Session, request: Request, actor: Actor, *, slug: str, name: str) -> Tenant:
    slug = _valid_tenant_slug(slug.strip())
    if db.scalar(select(Tenant).where(Tenant.slug == slug)):
        raise HTTPException(409, f"Tenant '{slug}' already exists")
    tenant = Tenant(slug=slug, name=(name.strip() or slug))
    db.add(tenant)
    db.flush()
    seed_builtin_roles(db, tenant)  # every tenant gets the built-in roles
    db.commit()
    audit.record_request(
        db, request, "tenant.created", tenant_id=tenant.id, actor=actor.label,
        detail={"slug": slug, "name": tenant.name},
    )
    return tenant


def delete_tenant(db: Session, request: Request, actor: Actor, slug: str) -> dict:
    if slug == DEFAULT_TENANT_SLUG:
        raise HTTPException(409, "The default tenant cannot be deleted")
    tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
    if tenant is None:
        raise HTTPException(404, "Tenant not found")
    # Refuse if the tenant still holds principals or agents — no silent cascade
    # of live identities.
    if db.scalar(select(Principal.id).where(Principal.tenant_id == tenant.id).limit(1)):
        raise HTTPException(409, "Tenant still has users; remove them first")
    if db.scalar(select(Agent.id).where(Agent.tenant_id == tenant.id).limit(1)):
        raise HTTPException(409, "Tenant still has agents; remove them first")
    db.query(Role).filter(Role.tenant_id == tenant.id).delete()
    db.delete(tenant)
    db.commit()
    audit.record_request(
        db, request, "tenant.deleted", actor=actor.label, detail={"slug": slug},
    )
    return {"deleted": slug}


# ----------------------------------------------------------------- access map


def build_access_graph(db: Session, actor: Actor, routes: list, creds: list) -> dict:
    """Nodes + weighted edges for the Access Map: agents → routes → credentials,
    plus direct credential grants (token exchange with no route in between).

    The route/credential lists arrive already permission-filtered; agent nodes
    are included when they appear on a visible grant — the same exposure the
    list pages already give. Edge weights are 7-day activity counts from the
    audit log (gateway.proxied / token.exchanged), best-effort and capped; a
    grant with no traffic renders at baseline width.
    """
    from collections import Counter
    from datetime import timedelta

    from .models import AuditEvent

    agents: dict[str, dict] = {}
    route_nodes: list[dict] = []
    cred_nodes: list[dict] = []
    links_ar: list[dict] = []
    links_rc: list[dict] = []
    direct: list[dict] = []

    def _agent(a) -> str:
        if a.id not in agents:
            agents[a.id] = {"id": "a:" + a.id, "label": a.name,
                            "icon": a.icon or "", "active": a.active}
        return "a:" + a.id

    seen_creds: set[str] = set()

    def _cred(c) -> str:
        if c.id not in seen_creds:
            seen_creds.add(c.id)
            cred_nodes.append({"id": "c:" + c.id, "label": c.name,
                               "icon": c.icon or "", "provider": c.provider or ""})
        return "c:" + c.id

    for c in creds:
        _cred(c)
    for r in routes:
        route_nodes.append({"id": "r:" + r.id, "label": "/gw/" + r.slug,
                            "icon": r.icon or "", "active": r.active})
        for g in r.grants:
            links_ar.append({"from": _agent(g.agent), "to": "r:" + r.id, "w": 0,
                             "_agent": g.agent.id, "_slug": r.slug})
        if r.credential is not None:
            # The routes page already names the route's credential to anyone
            # who can see the route; the map exposes exactly the same.
            links_rc.append({"from": "r:" + r.id, "to": _cred(r.credential), "w": 0})
    for c in creds:
        for g in c.grants:
            direct.append({"from": _agent(g.agent), "to": "c:" + c.id, "w": 0,
                           "_agent": g.agent.id, "_cred": c.name})

    since = datetime.now(timezone.utc) - timedelta(days=7)
    rows = db.execute(
        select(AuditEvent.agent_id, AuditEvent.event, AuditEvent.detail)
        .where(
            AuditEvent.tenant_id == actor.tenant_id,
            AuditEvent.event.in_(("gateway.proxied", "token.exchanged")),
            AuditEvent.created_at >= since,
        )
        .order_by(AuditEvent.created_at.desc())
        .limit(20_000)
    ).all()
    by_slug: Counter = Counter()
    by_cred: Counter = Counter()
    for agent_id, event, detail in rows:
        detail = detail or {}
        if event == "gateway.proxied" and detail.get("slug"):
            by_slug[(agent_id, detail["slug"])] += 1
        elif event == "token.exchanged" and detail.get("credential"):
            by_cred[(agent_id, detail["credential"])] += 1
    for link in links_ar:
        link["w"] = by_slug.get((link.pop("_agent"), link.pop("_slug")), 0)
    route_in: Counter = Counter()
    for link in links_ar:
        route_in[link["to"]] += link["w"]
    for link in links_rc:
        link["w"] = route_in.get(link["from"], 0)
    for link in direct:
        link["w"] = by_cred.get((link.pop("_agent"), link.pop("_cred")), 0)

    return {"agents": list(agents.values()), "routes": route_nodes,
            "credentials": cred_nodes, "links_ar": links_ar,
            "links_rc": links_rc, "direct": direct, "window_days": 7}
