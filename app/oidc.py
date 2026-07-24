"""Minimal OIDC relying-party client (authorization code + PKCE).

Module-level functions are intentionally simple seams: tests monkeypatch
get_discovery / exchange_code / verify_id_token to avoid network access.
"""

import base64
import hashlib
import secrets
import time

import httpx
from joserfc import jwt
from joserfc.jwk import KeySet

from .config import get_settings

_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, KeySet]] = {}
_CACHE_TTL = 3600


def get_discovery() -> dict:
    issuer = get_settings().oidc_issuer.rstrip("/")
    now = time.time()
    cached = _discovery_cache.get(issuer)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]
    resp = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    _discovery_cache[issuer] = (now, doc)
    return doc


def _get_jwks(jwks_uri: str) -> KeySet:
    now = time.time()
    cached = _jwks_cache.get(jwks_uri)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]
    resp = httpx.get(jwks_uri, timeout=10)
    resp.raise_for_status()
    key_set = KeySet.import_key_set(resp.json())
    _jwks_cache[jwks_uri] = (now, key_set)
    return key_set


def build_auth_request(redirect_uri: str) -> tuple[str, str, str, str]:
    """Returns (authorization_url, state, nonce, code_verifier)."""
    settings = get_settings()
    doc = get_discovery()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    params = httpx.QueryParams(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{doc['authorization_endpoint']}?{params}", state, nonce, code_verifier


def exchange_code(code: str, redirect_uri: str, code_verifier: str) -> dict:
    settings = get_settings()
    doc = get_discovery()
    resp = httpx.post(
        doc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def verify_id_token(id_token: str, nonce: str) -> dict:
    """Validate signature, iss, aud, exp, nonce. Returns the claims dict."""
    settings = get_settings()
    doc = get_discovery()
    key_set = _get_jwks(doc["jwks_uri"])
    from .proof import ASYMMETRIC_ALGS

    claims = jwt.decode(id_token, key_set, algorithms=ASYMMETRIC_ALGS).claims

    if claims.get("iss", "").rstrip("/") != settings.oidc_issuer.rstrip("/"):
        raise ValueError("id_token issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if settings.oidc_client_id not in auds:
        raise ValueError("id_token audience mismatch")
    if claims.get("exp", 0) < time.time():
        raise ValueError("id_token expired")
    if claims.get("nonce") != nonce:
        raise ValueError("id_token nonce mismatch")
    return claims
