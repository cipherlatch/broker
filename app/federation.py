"""Workload identity federation: secretless agent authentication.

An agent bound to (federated_issuer, federated_subject) authenticates by
presenting a JWT minted by its *platform* — a SPIFFE JWT-SVID (via SPIRE's
OIDC discovery provider), a Kubernetes service-account token, a GitLab CI
id_token, a cloud workload identity — instead of a broker-issued secret.
This kills "secret zero": nothing needs to be provisioned to the workload,
because the platform already attests it.

Trust is anchored twice: the issuer must be in the platform-level
BROKER_FEDERATED_ISSUERS allowlist (so tenants can't point agents at
arbitrary URLs), and the assertion must verify against the issuer's
published JWKS (standard OIDC discovery), match the agent's bound subject,
be audience-restricted to this broker, and be unexpired.

Module-level _fetch_jwks_uri/_fetch_jwks are seams for tests.
"""

import base64
import json
import time

import httpx
from joserfc import jwt
from joserfc.jwk import KeySet

from .config import get_settings


class FederationError(Exception):
    pass


_CACHE_TTL = 300
_jwks_cache: dict[str, tuple[float, dict]] = {}


def allowed_issuers() -> list[str]:
    return [
        i.strip().rstrip("/")
        for i in get_settings().federated_issuers.split(",")
        if i.strip()
    ]


def _fetch_jwks_uri(issuer: str) -> str:
    resp = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    return resp.json()["jwks_uri"]


def _fetch_jwks(jwks_uri: str) -> dict:
    resp = httpx.get(jwks_uri, timeout=10)
    resp.raise_for_status()
    return resp.json()


def issuer_jwks(issuer: str) -> dict:
    now = time.time()
    cached = _jwks_cache.get(issuer)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]
    jwks = _fetch_jwks(_fetch_jwks_uri(issuer))
    _jwks_cache[issuer] = (now, jwks)
    return jwks


def reset_cache() -> None:
    _jwks_cache.clear()


def peek_issuer(assertion: str) -> str | None:
    """The unverified iss claim — used only to route the assertion to the
    right verifier (private_key_jwt uses iss == client_id); every security
    decision happens after signature verification."""
    try:
        payload = assertion.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("iss")
    except Exception:
        return None


def verify_federated_assertion(assertion: str, agent) -> dict:
    """Validate a platform-issued assertion against the agent's federated
    binding. Returns the verified claims; raises FederationError."""
    settings = get_settings()
    issuer = (agent.federated_issuer or "").rstrip("/")
    if not issuer:
        raise FederationError("agent has no federated identity binding")
    if issuer not in allowed_issuers():
        raise FederationError("issuer is not in BROKER_FEDERATED_ISSUERS")

    try:
        key_set = KeySet.import_key_set(issuer_jwks(issuer))
    except FederationError:
        raise
    except Exception as exc:
        raise FederationError(f"could not load issuer JWKS: {exc}")
    try:
        from .proof import ASYMMETRIC_ALGS

        claims = jwt.decode(assertion, key_set, algorithms=ASYMMETRIC_ALGS).claims
    except Exception:
        raise FederationError("assertion signature invalid")

    if (claims.get("iss") or "").rstrip("/") != issuer:
        raise FederationError("assertion iss does not match the agent's binding")
    if claims.get("sub") != agent.federated_subject:
        raise FederationError("assertion sub does not match the agent's binding")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if not any(a in (settings.issuer, f"{settings.issuer}/oauth/token") for a in auds):
        raise FederationError("assertion audience must be the broker issuer")
    exp = claims.get("exp")
    if not exp or exp < time.time():
        raise FederationError("assertion expired (or has no exp)")
    return claims
