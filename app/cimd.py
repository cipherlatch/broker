"""Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

The MCP-mandated client registration mechanism: an OAuth client identifies
itself with an https URL as client_id; the authorization server fetches a JSON
metadata document from that URL and pins redirect_uris to it. The URL *is* the
client identity — no registration round-trip, no shared secret (public client).

Fetching an attacker-supplied URL from the broker is an SSRF vector, so this
module is deliberately paranoid: https only, DNS-resolved addresses checked
against private/reserved ranges before connecting, redirects refused, response
size capped. `fetch_document` is a module-level seam (like app.oidc) so tests
monkeypatch it instead of the network.
"""

import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import MCPClient


class CIMDError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime | None) -> datetime | None:
    # SQLite round-trips naive datetimes; treat stored values as UTC.
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _addresses_public(host: str) -> bool:
    """Resolve `host` and require every answer to be a global address. Checking
    all answers (not the first) closes the multi-record dodge; redirects are
    refused outright and the cache TTL bounds re-fetch frequency, which
    together keep the residual DNS-rebinding window narrow for a fetch that
    only ever lands in a parsed-then-validated JSON document."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise CIMDError("client_id host does not resolve")
    if not infos:
        raise CIMDError("client_id host does not resolve")
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not addr.is_global:
            return False
    return True


def validate_client_id_url(url: str) -> None:
    """Structural checks on a client_id URL, before any network activity."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise CIMDError("client_id must be an https URL")
    if not parsed.netloc or parsed.fragment:
        raise CIMDError("client_id must be an absolute https URL without fragment")
    if parsed.username or parsed.password:
        raise CIMDError("client_id must not carry userinfo")


def fetch_document(url: str) -> dict:
    """Fetch and parse a metadata document. Module-level seam for tests."""
    settings = get_settings()
    validate_client_id_url(url)
    host = urlparse(url).hostname or ""
    if not settings.cimd_allow_private_ips and not _addresses_public(host):
        raise CIMDError("client_id resolves to a non-public address")

    try:
        with httpx.stream(
            "GET", url,
            timeout=settings.cimd_timeout_seconds,
            follow_redirects=False,  # a redirect could bounce into private space
            headers={"Accept": "application/json"},
        ) as resp:
            if resp.status_code != 200:
                raise CIMDError(f"metadata fetch returned {resp.status_code}")
            ctype = resp.headers.get("content-type", "").split(";")[0].strip()
            if ctype != "application/json":
                raise CIMDError("metadata document must be application/json")
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > settings.cimd_max_bytes:
                    raise CIMDError("metadata document too large")
    except httpx.HTTPError as exc:
        raise CIMDError(f"metadata fetch failed: {exc.__class__.__name__}")

    import json

    try:
        doc = json.loads(body)
    except ValueError:
        raise CIMDError("metadata document is not valid JSON")
    if not isinstance(doc, dict):
        raise CIMDError("metadata document must be a JSON object")
    return doc


def _validate_document(url: str, doc: dict) -> None:
    # The document must claim the URL it was fetched from as its client_id —
    # otherwise any JSON on the internet could be waved around as a client.
    if doc.get("client_id") != url:
        raise CIMDError("metadata client_id does not match the document URL")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        raise CIMDError("metadata must declare a non-empty redirect_uris list")


def _is_loopback(uri: str) -> bool:
    host = (urlparse(uri).hostname or "").lower()
    return host in ("127.0.0.1", "::1", "localhost")


def redirect_uri_allowed(registered: list[str], presented: str) -> bool:
    """Exact match, with the OAuth 2.1 §8.4.2 loopback exception: native apps
    bind an ephemeral port, so for loopback redirect URIs the port may vary at
    runtime while scheme/host/path must still match. `localhost` is included
    alongside the IP literals because the MCP client ecosystem uses it."""
    presented_p = urlparse(presented)
    for reg in registered:
        if reg == presented:
            return True
        reg_p = urlparse(reg)
        if (
            _is_loopback(reg) and _is_loopback(presented)
            and reg_p.scheme == presented_p.scheme
            and (reg_p.hostname or "").lower() == (presented_p.hostname or "").lower()
            and reg_p.path == presented_p.path
        ):
            return True
    return False


def get_or_refresh_client(db: Session, url: str) -> MCPClient:
    """Return the (cached) client record for a client_id URL, fetching or
    refreshing its metadata document as needed. An admin-deactivated client is
    refused without touching the network — that's the revocation lever."""
    settings = get_settings()
    validate_client_id_url(url)

    client = db.scalar(select(MCPClient).where(MCPClient.client_id_url == url))
    if client is not None and not client.active:
        raise CIMDError("client is revoked")

    fresh = (
        client is not None
        and _as_aware(client.fetched_at) > _now() - timedelta(seconds=settings.cimd_cache_seconds)
    )
    if fresh:
        return client

    doc = fetch_document(url)
    _validate_document(url, doc)
    name = doc.get("client_name") or ""
    if client is None:
        client = MCPClient(client_id_url=url, name=name[:255], metadata_doc=doc,
                           fetched_at=_now())
        db.add(client)
    else:
        client.name = name[:255]
        client.metadata_doc = doc
        client.fetched_at = _now()
    db.commit()
    db.refresh(client)
    return client
