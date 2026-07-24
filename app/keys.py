"""Facade over the configured keystore backend (see app/keystore/)."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .keystore import DEFAULT_KEYRING, get_provider, reset_provider_cache, resolve_storage_ring


def get_signing_key(keyring: str = DEFAULT_KEYRING):
    """Initialize a keyring's provider (generates/loads key material)."""
    return get_provider(keyring)


def get_kid(keyring: str = DEFAULT_KEYRING) -> str:
    return get_provider(keyring).kid()


def sign_jwt(header: dict, claims: dict, keyring: str = DEFAULT_KEYRING) -> str:
    return get_provider(keyring).sign_jwt(header, claims)


def active_keyrings(db: Session) -> list[str]:
    """Every storage ring referenced by an agent, plus default. Named rings
    are tenant-scoped, so the same agent-facing name in two tenants is two
    distinct storage rings."""
    from .models import Agent, Tenant

    rings = {DEFAULT_KEYRING}
    pairs = db.execute(
        select(Tenant.slug, Agent.keyring).join(Tenant, Agent.tenant_id == Tenant.id).distinct()
    )
    rings.update(resolve_storage_ring(slug, ring) for slug, ring in pairs)
    return sorted(rings)


def tenant_keyrings(db: Session, tenant_slug: str) -> dict[str, str]:
    """Agent-facing ring name -> storage ring, for one tenant (default included)."""
    from .models import Agent, Tenant

    names = {DEFAULT_KEYRING}
    rows = db.execute(
        select(Agent.keyring).join(Tenant, Agent.tenant_id == Tenant.id)
        .where(Tenant.slug == tenant_slug).distinct()
    )
    names.update(r for (r,) in rows if r)
    return {name: resolve_storage_ring(tenant_slug, name) for name in sorted(names)}


def public_jwks(db: Session) -> dict:
    """Union of all active keyrings' public keys, so downstream verifiers
    never need to know which ring signed a token."""
    keys: list[dict] = []
    seen: set[str] = set()
    for ring in active_keyrings(db):
        for jwk in get_provider(ring).public_jwks():
            if jwk["kid"] not in seen:
                seen.add(jwk["kid"])
                keys.append(jwk)
    return {"keys": keys}


def keys_info(db: Session) -> dict:
    """Platform view: every active storage ring."""
    return {ring: get_provider(ring).keys_info() for ring in active_keyrings(db)}


def tenant_keys_info(db: Session, tenant_slug: str) -> dict:
    """Tenant view: the tenant's rings keyed by agent-facing name."""
    return {
        name: get_provider(storage).keys_info()
        for name, storage in tenant_keyrings(db, tenant_slug).items()
    }


def rotate_key(keyring: str = DEFAULT_KEYRING) -> str:
    """Returns the new active kid. Raises 409 for externally managed backends."""
    return get_provider(keyring).rotate()


def maybe_auto_rotate(max_age_seconds: int) -> str | None:
    """Startup hook: rotate the default ring if its active key is too old.
    (Named rings rotate via the API/cron; startup rotation is best-effort.)"""
    if max_age_seconds <= 0:
        return None
    provider = get_provider(DEFAULT_KEYRING)
    if provider.active_age_seconds() > max_age_seconds:
        try:
            return provider.rotate()
        except Exception:
            return None  # externally managed backends: nothing to do
    return None


def keystore_healthy() -> bool:
    try:
        return get_provider(DEFAULT_KEYRING).healthy()
    except Exception:
        return False


def reset_key_cache() -> None:
    """Used by tests when the keystore config changes."""
    reset_provider_cache()
