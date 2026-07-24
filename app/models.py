import os
import threading
import time as _time
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


_uuid7_lock = threading.Lock()
_uuid7_last_ms = -1
_uuid7_counter = 0


def _uuid7() -> str:
    """RFC 9562 UUIDv7: 48-bit unix-ms timestamp + 12-bit monotonic counter +
    random. Time-ordered *even within a millisecond*, so tombstones index/sort
    by deletion time for free and keyset pagination over same-ms rows is stable.

    rand_a carries the counter (RFC 9562 §6.2, "Monotonic Random" / method 2):
    reseeded from CSPRNG each new millisecond with the top bit clear, then
    incremented on same-ms collisions, so back-to-back ids strictly increase.
    A clock stepping backwards is pinned to the last ms and keeps incrementing,
    which never regresses ordering. rand_b stays fully random every call, so id
    guessability is unchanged (and these are DB keys, not secrets, regardless).
    stdlib uuid.uuid7 (Python >= 3.14) uses the same scheme; this matches it so
    3.13 and 3.14 behave identically."""
    if hasattr(uuid, "uuid7"):  # pragma: no cover — Python >= 3.14
        return str(uuid.uuid7())
    global _uuid7_last_ms, _uuid7_counter
    with _uuid7_lock:
        ts_ms = int(_time.time() * 1000) & ((1 << 48) - 1)
        if ts_ms > _uuid7_last_ms:
            # New millisecond: reseed. Top bit clear leaves >= 2048 guaranteed
            # increments before the 12-bit counter can overflow.
            _uuid7_last_ms = ts_ms
            _uuid7_counter = int.from_bytes(os.urandom(2), "big") & 0x7FF
        else:
            # Same ms, or the clock went backwards: hold the last ts and bump.
            ts_ms = _uuid7_last_ms
            _uuid7_counter += 1
            if _uuid7_counter > 0xFFF:
                # >4096 ids in one ms: borrow from the next ms and reseed.
                ts_ms = (_uuid7_last_ms + 1) & ((1 << 48) - 1)
                _uuid7_last_ms = ts_ms
                _uuid7_counter = int.from_bytes(os.urandom(2), "big") & 0x7FF
        counter = _uuid7_counter & 0xFFF
        rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (
        (ts_ms << 80)
        | (0x7 << 76)        # version 7
        | (counter << 64)    # rand_a = 12-bit monotonic counter
        | (0x2 << 62)        # variant 10
        | rand_b             # rand_b (62 random bits)
    )
    return str(uuid.UUID(int=value))


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    # SHA-256 digest of the tenant's SCIM bearer token (None = SCIM disabled).
    scim_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    agents: Mapped[list["Agent"]] = relationship(back_populates="tenant")


class Role(Base):
    """A named permission set. Built-ins are seeded per tenant and immutable."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Principal(Base):
    """A human. Bound to an OIDC identity by `sub` on first login."""

    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email"),
        UniqueConstraint("tenant_id", "sub"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    # Optional profile photo, stored as a small (client-resized, size-capped)
    # image data URI. NULL = fall back to the initials avatar.
    avatar: Mapped[str | None] = mapped_column(Text, nullable=True)
    sub: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    role: Mapped[Role] = relationship()
    tenant: Mapped[Tenant] = relationship()


class ServiceKey(Base):
    """A scoped machine credential for the control plane. Carries a Role (any
    role, built-in or custom) and authenticates via the X-Api-Key header with
    that role's permissions — the least-privilege alternative to sharing the
    platform X-Admin-Key. Tenant-scoped and never platform admin: it can do
    within one tenant exactly what its role permits, no more. The first
    consumer is Nightlatch (audit:read:all + agents:revoke:all); the design is
    general so any future product integrates the same way. Only the key hash
    is stored; the secret is shown once at creation."""

    __tablename__ = "service_keys"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_service_keys_tenant_name"),
        UniqueConstraint("key_hash", name="uq_service_keys_key_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), default="")
    key_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    role: Mapped[Role] = relationship()
    tenant: Mapped[Tenant] = relationship()


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # Display icon: an emoji or a data: URI fetched from a user-supplied URL.
    # Agents have no upstream, so there is no favicon auto-detection here.
    icon: Mapped[str] = mapped_column(Text, default="")

    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String(64))

    # Scopes this agent is allowed to request (granted by an admin/owner).
    allowed_scopes: Mapped[list] = mapped_column(JSON, default=list)
    # Signing keyring: agents on different keyrings are isolated from each
    # other's key rotations.
    keyring: Mapped[str] = mapped_column(String(64), default="default")
    # RFC 8707: resources (audience URIs) this agent may request tokens for.
    # Empty list = any well-formed resource URI is accepted.
    allowed_resources: Mapped[list] = mapped_column(JSON, default=list)

    # NIST 800-63B throttling state.
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Optional public key (JWK) for private_key_jwt client auth (RFC 7523).
    # When set, the agent authenticates with a signed assertion instead of
    # (or in addition to) its client secret.
    auth_public_jwk: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Workload identity federation (SPIFFE/OIDC): when both are set, a JWT
    # from this issuer with this subject authenticates the agent — no broker
    # secret needs to exist at all (secretless bootstrap).
    federated_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    federated_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Mass revocation: tokens carry this generation; bumping it invalidates
    # every token minted before the bump (deterministic, no timestamp races).
    token_gen: Mapped[int] = mapped_column(Integer, default=0)

    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="agents")
    owner: Mapped[Principal] = relationship()


class DownstreamCredential(Base):
    """A downstream secret (API key, PAT, long-lived token) that granted
    agents may obtain via RFC 8693 token exchange. Encrypted at rest;
    write-only through the management API."""

    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_credentials_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # Display icon: an emoji, or an uploaded/fetched image stored as a data: URI.
    icon: Mapped[str] = mapped_column(Text, default="")
    # For a static credential, the encrypted downstream secret. For a
    # provider-backed one, the encrypted *seed* (e.g. an SSH CA private key).
    secret_encrypted: Mapped[str] = mapped_column(Text)
    # NULL = static secret (returned as-is on exchange). Otherwise a
    # dynamic credential provider that mints short-lived material on exchange.
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    last_exchanged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped[Principal] = relationship()
    grants: Mapped[list["CredentialGrant"]] = relationship(
        back_populates="credential", cascade="all, delete-orphan"
    )


class CredentialGrant(Base):
    __tablename__ = "credential_grants"
    __table_args__ = (
        UniqueConstraint("credential_id", "agent_id", name="uq_credential_grants_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    credential: Mapped[DownstreamCredential] = relationship(back_populates="grants")
    agent: Mapped[Agent] = relationship()


class RevokedToken(Base):
    """A single revoked token by jti (RFC 7009). Rows past `expires_at` are
    dead weight and periodically pruned — after natural expiry the JWT fails
    on `exp` anyway."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GatewayRoute(Base):
    """An enforcing proxy route: a slug on Cipherlatch (/gw/<slug>/...) bound to an
    upstream base URL, a stored credential injected server-side, and a policy
    (allowed methods + path-prefix allowlist). Granted agents call through it
    without ever seeing the credential."""

    __tablename__ = "gateway_routes"
    __table_args__ = (UniqueConstraint("tenant_id", "slug", name="uq_gateway_routes_tenant_slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    slug: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    # Display icon: an emoji, or a data: URI auto-detected from the upstream's
    # favicon on creation. User-set values win and are never overwritten.
    icon: Mapped[str] = mapped_column(Text, default="")
    upstream_base: Mapped[str] = mapped_column(String(1024))
    credential_id: Mapped[str] = mapped_column(ForeignKey("credentials.id"), index=True)
    # How the injected secret is presented to the upstream.
    inject_mode: Mapped[str] = mapped_column(String(16), default="bearer")  # bearer|header|basic
    inject_header: Mapped[str] = mapped_column(String(64), default="Authorization")

    # Policy.
    allowed_methods: Mapped[list] = mapped_column(JSON, default=list)  # [] = GET only
    allowed_path_prefixes: Mapped[list] = mapped_column(JSON, default=list)  # [] = any subpath
    # Rate/budget limits, per granted agent (0 = unlimited). Enforced with
    # in-process counters — per-replica, like the IP rate limiter.
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=0)
    daily_quota: Mapped[int] = mapped_column(Integer, default=0)
    # TLS verification for the upstream connection. Disabling it is a
    # testing-only escape hatch for self-signed / internal upstreams; the UI
    # flags turning it off as risky.
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    # Git smart-HTTP mode: stream clone/fetch/push through this route. The agent
    # authenticates with its Cipherlatch token as the Basic-auth password (git
    # can't send a Bearer), the stored credential is injected as HTTP Basic, and
    # both directions stream without the body cap (packfiles are large).
    git_http: Mapped[bool] = mapped_column(Boolean, default=False)
    # Ephemeral-credential passthrough (credential lineage). Some upstream flows
    # mint a short-lived downstream credential mid-protocol (a Pages upload JWT,
    # a registry token) and re-authenticate later requests with it — those
    # requests cannot carry an agent token, and injecting would clobber them.
    # Config: {"prefixes": [...], "capture": {"prefixes": [...], "fields": [...]},
    # "ttl_seconds": N}. The gateway *witnesses* credentials minted in brokered
    # responses on the capture prefixes (hash only) and then relays requests on
    # the passthrough prefixes ONLY when they bear a witnessed, unexpired
    # credential — attributed in the audit log to the agent whose brokered call
    # minted it. NULL = disabled. Provider-agnostic by design.
    passthrough_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    owner: Mapped[Principal] = relationship()
    credential: Mapped[DownstreamCredential] = relationship()
    grants: Mapped[list["RouteGrant"]] = relationship(
        back_populates="route", cascade="all, delete-orphan"
    )


class WitnessedCredential(Base):
    """Credential lineage: an ephemeral downstream credential the gateway saw
    being minted inside a brokered response (stored as a hash, never the value).
    Passthrough prefixes relay ONLY requests bearing one of these, attributed to
    the agent whose brokered call minted it. Rows expire on the route's
    configured TTL and are pruned opportunistically."""

    __tablename__ = "witnessed_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    route_id: Mapped[str] = mapped_column(
        ForeignKey("gateway_routes.id", ondelete="CASCADE"), index=True
    )
    # Plain string (like AuditEvent.agent_id), so lineage survives agent removal.
    agent_id: Mapped[str] = mapped_column(String(36), index=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    route: Mapped[GatewayRoute] = relationship()


class RouteGrant(Base):
    __tablename__ = "route_grants"
    __table_args__ = (UniqueConstraint("route_id", "agent_id", name="uq_route_grants_pair"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    route_id: Mapped[str] = mapped_column(
        ForeignKey("gateway_routes.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    route: Mapped[GatewayRoute] = relationship(back_populates="grants")
    agent: Mapped[Agent] = relationship()


class Tombstone(Base):
    """The graveyard: an archived (hard-deleted) agent or user. Deleting is
    really archiving — the row is removed (freeing its unique name/email for
    reuse) but a tombstone keeps the final state, so the audit trail stays
    resolvable forever. Tombstone ids are UUIDv7 (time-ordered)."""

    __tablename__ = "graveyard"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid7)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # agent | user
    # The archived object's original immutable id — what audit events carry.
    original_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(255))  # agent name / user email
    # Final serialized state (no secrets — hashes and encrypted blobs excluded).
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    original_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    archived_by: Mapped[str] = mapped_column(String(255), default="")
    archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Policy(Base):
    """A native contextual policy: a curated control type with typed parameters
    (config, not a language). Policies are first-class governed objects — their
    own permissions (policies:*) keep the controlled party from weakening the
    control (separation of duties, DECISIONS.md 2026-07-16). Evaluation composes
    with the built-in route checks and the external OPA/Cedar hook as additive
    vetoes: any layer can deny, fail-closed."""

    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_policies_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # Curated types: change_freeze | business_hours | cidr_fence.
    type: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    owner: Mapped[Principal] = relationship()
    attachments: Mapped[list["PolicyAttachment"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyAttachment(Base):
    """Binds a policy to a route or an agent. Attachment is its own permission
    (policies:apply) so a resource owner can't detach a control someone with
    governance authority placed on them."""

    __tablename__ = "policy_attachments"
    __table_args__ = (
        UniqueConstraint("policy_id", "target_type", "target_id",
                         name="uq_policy_attachments_target"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True
    )
    target_type: Mapped[str] = mapped_column(String(16))  # route | agent
    # Plain string (like AuditEvent.agent_id): attachments must not block
    # target removal, and stale rows are simply inert.
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    policy: Mapped[Policy] = relationship(back_populates="attachments")


class MCPClient(Base):
    """An OAuth public client identified by a Client ID Metadata Document URL
    (draft-ietf-oauth-client-id-metadata-document; the MCP-mandated
    registration mechanism). The URL *is* the identity — rows exist to cache
    the fetched document and to give admins a revocation lever (`active`).
    Global, not tenant-scoped: the same MCP client software identity may be
    used by users of any tenant; consent is what binds it to a tenant's data."""

    __tablename__ = "mcp_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # The https URL the client presented as client_id, verbatim.
    client_id_url: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    # client_name from the metadata document (display only).
    name: Mapped[str] = mapped_column(String(255), default="")
    # The fetched metadata document, as served (redirect_uris et al.).
    metadata_doc: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class MCPResource(Base):
    """A registered MCP server (an OAuth resource, RFC 8707) that this broker
    is willing to mint user-delegated tokens for. Registration is deliberate:
    tokens are never issued for an audience an admin hasn't enrolled."""

    __tablename__ = "mcp_resources"
    __table_args__ = (UniqueConstraint("tenant_id", "resource_uri",
                                       name="uq_mcp_resources_tenant_uri"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Canonical MCP server URI (RFC 8707 §2): absolute http(s), no fragment.
    resource_uri: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    # Scopes a user may delegate for this resource. Empty = any requested scope.
    allowed_scopes: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    tenant: Mapped[Tenant] = relationship()


class AuthorizationCode(Base):
    """A pending authorization-code grant (OAuth 2.1). Stored hashed and
    single-use; ~60s lifetime. `issued_jti` remembers the token minted on
    redemption so a replayed code revokes it (OAuth 2.1 §4.1.2 SHOULD)."""

    __tablename__ = "authorization_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    code_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    client_id_url: Mapped[str] = mapped_column(String(1024))
    redirect_uri: Mapped[str] = mapped_column(String(1024))
    resource: Mapped[str] = mapped_column(String(1024))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    code_challenge: Mapped[str] = mapped_column(String(128))  # PKCE S256 only
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    issued_jti: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    principal: Mapped[Principal] = relationship()


class ConsentGrant(Base):
    """A user's remembered approval: this MCP client may obtain tokens for
    this resource with these scopes, until revoked. Checked on every authorize
    (skips the consent screen) AND on every token verification (revoking
    consent kills outstanding tokens wherever verify_token runs)."""

    __tablename__ = "consent_grants"
    __table_args__ = (
        UniqueConstraint("principal_id", "client_id_url", "resource",
                         name="uq_consent_grants_triple"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), index=True)
    client_id_url: Mapped[str] = mapped_column(String(1024))
    resource: Mapped[str] = mapped_column(String(1024))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    principal: Mapped[Principal] = relationship()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    event: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="", index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
