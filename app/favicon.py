"""Best-effort icon detection/fetch for routes and agents.

Two entry points:
  - fetch_favicon(upstream): try <upstream>/favicon.ico, falling back to the
    registrable apex (api.anthropic.com -> anthropic.com) since API hosts often
    have no favicon of their own.
  - fetch_icon_url(url): fetch a user-supplied image URL (routes without a
    discoverable favicon, or agents, which have no upstream at all).

Results are strictly validated (small, raster image, non-SVG) before use.
Route/agent admins already configure upstreams the gateway fetches, so a
server-side image fetch adds no capability they don't already have.
"""

import base64
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

from .config import get_settings

# Raster types only; SVG excluded on purpose (matches the avatar feature).
_OK_TYPES = {
    "image/x-icon", "image/vnd.microsoft.icon", "image/png",
    "image/gif", "image/jpeg", "image/webp",
}
_MAX_BYTES = 50_000
_MAX_REDIRECTS = 4


def _host_is_public(host: str) -> bool:
    """Resolve `host` and require every answer to be a global address — the same
    SSRF guard the CIMD fetcher uses. False if it doesn't resolve or any address
    is private/loopback/link-local/reserved/metadata. Checking every answer
    closes the multi-record dodge."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    return bool(infos) and all(
        ipaddress.ip_address(info[4][0]).is_global for info in infos
    )


def _fetch_image(url: str, verify_tls: bool, guard_ssrf: bool = True) -> str | None:
    """GET `url` and return a data: URI if it's a small raster image, else None.
    Follows redirects MANUALLY. When `guard_ssrf` (the arbitrary user-supplied
    URL path), every hop's host must resolve to a public address — a public URL
    must not be able to 302 into the LAN (metadata service, internal host).
    Favicon auto-detection from an already-configured upstream passes
    guard_ssrf=False: that host is operator-authorized (the gateway fetches it
    anyway), so it is no new capability. Never raises."""
    allow_private = get_settings().cimd_allow_private_ips
    resp = None
    try:
        with httpx.Client(verify=verify_tls, timeout=5.0, follow_redirects=False) as client:
            current = url
            for _ in range(_MAX_REDIRECTS + 1):
                host = urlparse(current).hostname or ""
                if guard_ssrf and not allow_private and not _host_is_public(host):
                    return None
                resp = client.get(current)
                if resp.is_redirect and resp.headers.get("location"):
                    current = urljoin(current, resp.headers["location"])
                    continue
                break
            else:
                return None  # too many redirects
    except Exception:
        return None
    if resp is None or resp.status_code != 200:
        return None
    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    data = resp.content
    if ctype in _OK_TYPES and 0 < len(data) <= _MAX_BYTES:
        return f"data:{ctype};base64,{base64.b64encode(data).decode('ascii')}"
    return None


def _is_ipv4(host: str) -> bool:
    return host.replace(".", "").isdigit()


def fetch_favicon(upstream_base: str, verify_tls: bool = True) -> str | None:
    """Try the upstream host's favicon, then its registrable apex domain."""
    base = upstream_base.rstrip("/")
    candidates = [urljoin(base + "/", "favicon.ico")]
    host = urlparse(base).hostname or ""
    labels = host.split(".")
    if len(labels) >= 3 and not _is_ipv4(host):
        apex = ".".join(labels[-2:])  # api.anthropic.com -> anthropic.com
        candidates.append(f"https://{apex}/favicon.ico")
    for url in candidates:
        # Auto-detect targets the operator-configured upstream host, so it is
        # not the SSRF vector the arbitrary-URL path is — fetch without the
        # private-address guard (redirects are still bounded).
        icon = _fetch_image(url, verify_tls, guard_ssrf=False)
        if icon:
            return icon
    return None


def fetch_icon_url(url: str, verify_tls: bool = True) -> str | None:
    """Fetch a user-supplied image URL (http/https only). This is an arbitrary
    caller-controlled URL (route/agent/credential icon-from-URL), so it is
    SSRF-guarded: private/loopback/link-local targets and redirects into them
    are refused (unless cimd_allow_private_ips is set)."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return _fetch_image(url, verify_tls, guard_ssrf=True)


# The strict base64 charset means the value can't escape the img src / CSS
# context it's rendered in (same reasoning as the avatar endpoint).
_UPLOAD_RE = re.compile(
    r"^data:(image/(?:png|jpeg|webp|gif|x-icon|vnd\.microsoft\.icon));base64,"
    r"([A-Za-z0-9+/=]+)$"
)


def validate_upload(data_uri: str) -> str | None:
    """Validate a client-uploaded icon (a canvas-resized data: URI) against the
    same constraints as fetched favicons: small raster image, SVG excluded.
    Returns the data URI unchanged, or None if it isn't acceptable."""
    m = _UPLOAD_RE.match((data_uri or "").strip())
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(2), validate=True)
    except Exception:
        return None
    if not 0 < len(raw) <= _MAX_BYTES:
        return None
    return m.group(0)
