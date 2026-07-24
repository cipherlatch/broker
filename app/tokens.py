import time
import uuid

from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .keys import get_kid, public_jwks, sign_jwt
from .keystore import resolve_storage_ring
from .models import Agent, ConsentGrant, Principal, RevokedToken


def mint_token(
    agent: Agent,
    scopes: list[str],
    ttl: int | None = None,
    audience: str | None = None,
    cnf_jkt: str | None = None,
) -> tuple[str, str, int]:
    """Sign a short-lived access token for an agent.

    Returns (jwt, jti, expires_in). `cnf_jkt` binds the token to a DPoP proof
    key (RFC 9449 §6): the resource server / gateway then requires a matching
    DPoP proof."""
    settings = get_settings()
    expires_in = min(ttl or settings.token_ttl_seconds, settings.token_ttl_max_seconds)
    now = int(time.time())
    jti = str(uuid.uuid4())

    # Named rings are tenant-scoped in storage; `default` is the shared ring.
    keyring = resolve_storage_ring(agent.tenant.slug, agent.keyring)
    header = {"alg": "ES256", "kid": get_kid(keyring), "typ": "JWT"}
    payload = {
        "iss": settings.issuer,
        "sub": f"agent:{agent.id}",
        "client_id": agent.client_id,
        "owner": agent.owner.email,
        "tenant": agent.tenant.slug,
        "agent_name": agent.name,
        "scope": " ".join(scopes),
        "aud": audience or settings.audience,
        "iat": now,
        "exp": now + expires_in,
        "jti": jti,
        "gen": agent.token_gen or 0,
    }
    if cnf_jkt:
        payload["cnf"] = {"jkt": cnf_jkt}
    return sign_jwt(header, payload, keyring), jti, expires_in


def mint_user_token(
    principal: Principal,
    client_id_url: str,
    scopes: list[str],
    resource: str,
    cnf_jkt: str | None = None,
) -> tuple[str, str, int]:
    """Sign a user-delegated token for an MCP client (authorization_code
    grant). sub identifies the human; client_id carries the CIMD URL of the
    software acting for them; aud is the registered MCP server (RFC 8707).
    Uses the mcp TTL class — longer than agent tokens, since there are no
    refresh tokens, and bounded by consent revocation at verify time."""
    settings = get_settings()
    expires_in = settings.mcp_token_ttl_seconds
    now = int(time.time())
    jti = str(uuid.uuid4())

    keyring = resolve_storage_ring(principal.tenant.slug, "default")
    header = {"alg": "ES256", "kid": get_kid(keyring), "typ": "JWT"}
    payload = {
        "iss": settings.issuer,
        "sub": f"user:{principal.id}",
        "client_id": client_id_url,
        "owner": principal.email,
        "tenant": principal.tenant.slug,
        "scope": " ".join(scopes),
        "aud": resource,
        "iat": now,
        "exp": now + expires_in,
        "jti": jti,
    }
    if cnf_jkt:
        payload["cnf"] = {"jkt": cnf_jkt}
    return sign_jwt(header, payload, keyring), jti, expires_in


def verify_token(db: Session, token: str) -> dict | None:
    """Validate a Cipherlatch access token: signature, iss, exp, and revocation
    (per-jti denylist + per-agent tokens_valid_after). Returns claims, or None
    if the token is invalid/revoked. Used by the gateway and introspection."""
    settings = get_settings()
    try:
        claims = jwt.decode(
            token, KeySet.import_key_set(public_jwks(db)), algorithms=["ES256"]
        ).claims
    except Exception:
        return None
    if claims.get("iss") != settings.issuer or claims.get("exp", 0) < time.time():
        return None

    jti = claims.get("jti")
    if jti and db.get(RevokedToken, jti) is not None:
        return None

    # User-delegated MCP tokens (sub "user:<id>", authorization_code grant):
    # valid only while the human is active AND their consent for this
    # (client, resource) pair stands — revoking consent kills outstanding
    # tokens here, at introspection and at the gateway, without waiting out exp.
    sub = claims.get("sub", "")
    if sub.startswith("user:"):
        principal = db.get(Principal, sub.removeprefix("user:"))
        if principal is None or not principal.active or principal.deleted_at is not None:
            return None
        consent = db.scalar(
            select(ConsentGrant).where(
                ConsentGrant.principal_id == principal.id,
                ConsentGrant.client_id_url == claims.get("client_id"),
                ConsentGrant.resource == claims.get("aud"),
                ConsentGrant.revoked_at.is_(None),
            )
        )
        if consent is None:
            return None
        return claims

    agent = db.scalar(select(Agent).where(Agent.client_id == claims.get("client_id")))
    if agent is None or not agent.active:
        return None
    # A suspended/deleted owner suspends every outstanding delegation too.
    owner = agent.owner
    if owner is None or not owner.active or owner.deleted_at is not None:
        return None
    # Mass-revocation: reject tokens from a superseded generation.
    if claims.get("gen", 0) < (agent.token_gen or 0):
        return None
    return claims
