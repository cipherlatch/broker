"""Proof-of-possession helpers: DPoP (RFC 9449) and private_key_jwt (RFC 7523).

DPoP: the client sends a `DPoP` header — a JWT signed by a key it holds,
covering the HTTP method + URL. At the token endpoint we bind the issued
access token to that key via `cnf.jkt` (RFC 7638 thumbprint). At the gateway
we require a fresh DPoP proof whose key matches the token's `cnf.jkt`, so a
stolen bearer token is useless without the private key.

private_key_jwt: the agent authenticates with a `client_assertion` JWT signed
by its registered key instead of sending a client secret — no shared secret in
transit.
"""

import base64
import hashlib
import json
import threading
import time

from joserfc import jwt
from joserfc.jwk import ECKey, KeySet, OctKey, RSAKey

# DPoP proofs are single-use (RFC 9449 §11.1): a seen jti is rejected for the
# remainder of its freshness window. Per-process (like rate limiting); a
# shared store is the multi-replica upgrade. Entries self-expire.
_seen_jti: dict[str, float] = {}
_seen_lock = threading.Lock()
_MAX_JTI = 100_000  # memory bound for the replay set


def _register_jti(jti: str, now: float, ttl: int) -> bool:
    """Record a proof jti; return False if it was already seen (a replay)."""
    with _seen_lock:
        expired = [j for j, exp in _seen_jti.items() if exp <= now]
        for j in expired:
            del _seen_jti[j]
        # Bound memory WITHOUT flushing the whole set: clearing it would fail
        # OPEN — a flood of ~100k cheap self-signed proofs inside the freshness
        # window would erase the replay record and re-enable replay of a
        # captured proof. Instead, once past the cap, evict the entries closest
        # to expiry (they protect the shortest remaining window), keeping the
        # freshest proofs enforced.
        if len(_seen_jti) > _MAX_JTI:
            for j, _ in sorted(_seen_jti.items(), key=lambda kv: kv[1])[: len(_seen_jti) - _MAX_JTI]:
                del _seen_jti[j]
        if jti in _seen_jti:
            return False
        _seen_jti[jti] = now + ttl
        return True


def reset_seen_jti() -> None:
    """Test helper: clear the replay cache."""
    with _seen_lock:
        _seen_jti.clear()

# Externally-signed JWTs (DPoP proofs, client assertions, IdP id_tokens,
# federation assertions) are always asymmetric. Pinning the allowlist keeps a
# symmetric alg (HS*) or `none` from ever being honored — defeating algorithm
# confusion regardless of what a key set happens to contain.
ASYMMETRIC_ALGS = [
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "EdDSA",
]


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of a public JWK (the DPoP `jkt`)."""
    if jwk.get("kty") == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif jwk.get("kty") == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk.get("kty") == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError("unsupported key type for thumbprint")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _import_public(jwk: dict):
    kty = jwk.get("kty")
    if kty == "EC":
        return ECKey.import_key(jwk)
    if kty == "RSA":
        return RSAKey.import_key(jwk)
    if kty == "OKP":
        from joserfc.jwk import OKPKey

        return OKPKey.import_key(jwk)
    raise ValueError("unsupported key type")


class ProofError(Exception):
    pass


def verify_dpop(dpop_header: str, method: str, url: str, max_age_seconds: int = 300) -> str:
    """Validate a DPoP proof JWT for this request. Returns the proof key's
    thumbprint (jkt). Raises ProofError on any problem."""
    if not dpop_header:
        raise ProofError("missing DPoP header")
    try:
        # The proof is self-signed by the key embedded in its own header.
        protected = json.loads(_b64url_decode(dpop_header.split(".")[0]))
    except Exception:
        raise ProofError("malformed DPoP proof")
    if protected.get("typ") != "dpop+jwt":
        raise ProofError("wrong DPoP typ")
    jwk = protected.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        raise ProofError("DPoP header must carry a public jwk")

    try:
        key = _import_public(jwk)
        claims = jwt.decode(dpop_header, KeySet([key]), algorithms=ASYMMETRIC_ALGS).claims
    except Exception:
        raise ProofError("DPoP signature invalid")

    if claims.get("htm", "").upper() != method.upper():
        raise ProofError("DPoP htm mismatch")
    if not _url_matches(claims.get("htu", ""), url):
        raise ProofError("DPoP htu mismatch")
    now = time.time()
    iat = claims.get("iat", 0)
    if abs(now - iat) > max_age_seconds:
        raise ProofError("DPoP proof stale")
    jti = claims.get("jti")
    if not jti or not isinstance(jti, str):
        raise ProofError("DPoP proof missing jti")
    if not _register_jti(jti, now, max_age_seconds):
        raise ProofError("DPoP proof replayed")
    return jwk_thumbprint(jwk)


def verify_client_assertion(assertion: str, public_jwk: dict, issuer: str, client_id: str) -> None:
    """Validate a private_key_jwt client assertion (RFC 7523). Raises
    ProofError on failure."""
    try:
        key = _import_public(public_jwk)
        claims = jwt.decode(assertion, KeySet([key]), algorithms=ASYMMETRIC_ALGS).claims
    except Exception:
        raise ProofError("client_assertion signature invalid")
    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise ProofError("client_assertion iss/sub must equal client_id")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    # Audience is the token endpoint or the issuer.
    if not any(a in (issuer, f"{issuer}/oauth/token") for a in auds):
        raise ProofError("client_assertion audience mismatch")
    if claims.get("exp", 0) < time.time():
        raise ProofError("client_assertion expired")


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _url_matches(htu: str, url: str) -> bool:
    # Compare scheme+host+path, ignoring query/fragment.
    from urllib.parse import urlparse

    a, b = urlparse(htu), urlparse(url)
    return (a.scheme, a.netloc, a.path) == (b.scheme, b.netloc, b.path)
