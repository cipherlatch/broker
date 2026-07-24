"""Credential lineage: witness ephemeral downstream credentials minted inside
brokered responses, then let the gateway relay ONLY witnessed credentials on a
route's passthrough prefixes.

Why this exists: some upstream protocols mint a short-lived credential
mid-flow and re-authenticate later requests with it (Cloudflare Pages upload
JWTs, Docker registry tokens, presigned-upload schemes). Those later requests
carry the ephemeral credential — not an agent token — so the inject-mode
gateway would clobber them. A naive "just pass auth through" mode would be an
unauthenticated relay. Lineage closes that hole: the gateway records a hash of
each credential it saw being born in a brokered (agent-authenticated) response,
and passthrough requests are relayed only when their Authorization value hashes
to a live witness — attributed in the audit log to the minting agent. Network
isolation is preserved: the client still needs no route to the upstream, and
every byte still traverses (and is capped/audited by) the gateway.

Only hashes are stored; the credential value itself is never persisted.
"""

import hashlib
import json
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import WitnessedCredential, _now

DEFAULT_TTL_SECONDS = 1800
MAX_TTL_SECONDS = 86400
# Guardrails on what gets witnessed: real ephemeral credentials are long,
# whitespace-free strings; and one response should never mint dozens.
MIN_TOKEN_LENGTH = 20
MAX_CAPTURES_PER_RESPONSE = 10


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _harvest(node, fields: set[str], out: list[str]) -> None:
    """Collect string values under any of `fields` keys, anywhere in the JSON
    tree (APIs wrap payloads — e.g. Cloudflare's {"result": {"jwt": ...}})."""
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                key in fields
                and isinstance(value, str)
                and len(value) >= MIN_TOKEN_LENGTH
                and not any(c.isspace() for c in value)
            ):
                out.append(value)
            else:
                _harvest(value, fields, out)
    elif isinstance(node, list):
        for value in node:
            _harvest(value, fields, out)


def capture(db: Session, route, agent, path: str, body: bytes, content_type: str | None) -> int:
    """Witness ephemeral credentials minted in a brokered response. Returns the
    number captured (0 when the path/config/body doesn't apply)."""
    cfg = route.passthrough_config or {}
    cap_cfg = cfg.get("capture") or {}
    prefixes = cap_cfg.get("prefixes") or []
    if not prefixes or not any(path.startswith(p) for p in prefixes):
        return 0
    if "json" not in (content_type or ""):
        return 0
    try:
        data = json.loads(body)
    except Exception:
        return 0

    found: list[str] = []
    _harvest(data, set(cap_cfg.get("fields") or ["jwt"]), found)
    found = found[:MAX_CAPTURES_PER_RESPONSE]
    if not found:
        return 0

    ttl = int(cfg.get("ttl_seconds") or DEFAULT_TTL_SECONDS)
    expires = _now() + timedelta(seconds=min(ttl, MAX_TTL_SECONDS))
    for token in found:
        digest = _sha256(token)
        existing = db.scalar(
            select(WitnessedCredential).where(WitnessedCredential.token_sha256 == digest)
        )
        if existing is not None:
            existing.expires_at = expires
            existing.route_id = route.id
            existing.agent_id = agent.id
        else:
            db.add(
                WitnessedCredential(
                    route_id=route.id,
                    agent_id=agent.id,
                    token_sha256=digest,
                    expires_at=expires,
                )
            )
    prune_expired(db)
    db.commit()
    return len(found)


def lookup(db: Session, token: str) -> WitnessedCredential | None:
    """Resolve a presented credential to its live witness, or None."""
    if not token or len(token) < MIN_TOKEN_LENGTH:
        return None
    return db.scalar(
        select(WitnessedCredential).where(
            WitnessedCredential.token_sha256 == _sha256(token),
            WitnessedCredential.expires_at > _now(),
        )
    )


def prune_expired(db: Session) -> None:
    db.execute(delete(WitnessedCredential).where(WitnessedCredential.expires_at <= _now()))
