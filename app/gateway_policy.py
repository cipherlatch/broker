"""Gateway route policy: validation of route definitions and per-request
enforcement (method + path allowlists), plus safe upstream URL assembly.

Kept dependency-free and pure so it's trivially testable and the proxy path
stays fast.
"""

import re
from urllib.parse import urljoin, urlparse

from fastapi import HTTPException

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
INJECT_MODES = ("bearer", "header", "basic")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
# Hop-by-hop headers (RFC 7230 §6.1) plus ones we set ourselves; never forwarded.
_STRIP_REQUEST_HEADERS = {
    "host", "authorization", "connection", "keep-alive", "proxy-authorization",
    "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
    "content-length", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "cookie",
}
_STRIP_RESPONSE_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-encoding",
    "content-length", "set-cookie",
}


def validate_slug(slug: str) -> str:
    if not SLUG_RE.match(slug or ""):
        raise HTTPException(422, "slug must be lowercase alphanumeric/dash/underscore, max 64 chars")
    return slug


def validate_upstream(base: str) -> str:
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(422, "upstream_base must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise HTTPException(422, "upstream_base must not contain a query or fragment")
    # Normalize to end without a trailing slash; subpaths join predictably.
    return base.rstrip("/")


def normalize_methods(methods: list[str]) -> list[str]:
    out = []
    for m in methods or []:
        mu = m.strip().upper()
        if mu not in _METHODS:
            raise HTTPException(422, f"Unsupported method: {m}")
        out.append(mu)
    return sorted(set(out)) or ["GET"]


def normalize_prefixes(prefixes: list[str]) -> list[str]:
    out = []
    for p in prefixes or []:
        p = p.strip()
        if p and not p.startswith("/"):
            p = "/" + p
        if p:
            out.append(p)
    return out


def validate_inject(mode: str, header: str) -> tuple[str, str]:
    mode = (mode or "bearer").lower()
    if mode not in INJECT_MODES:
        raise HTTPException(422, f"inject_mode must be one of {INJECT_MODES}")
    if mode == "header" and not header:
        raise HTTPException(422, "inject_header is required for inject_mode=header")
    return mode, header or "Authorization"


def validate_passthrough(cfg) -> dict | None:
    """Validate + normalize a route's ephemeral-credential passthrough config.

    Shape: {"prefixes": [...], "capture": {"prefixes": [...], "fields": [...]},
    "ttl_seconds": N}. Both prefix lists are required — passthrough without
    capture could never match anything (nothing would be witnessed), so we fail
    early instead of shipping an inert config."""
    if cfg in (None, "", {}):
        return None
    if not isinstance(cfg, dict):
        raise HTTPException(422, "passthrough must be a JSON object")
    unknown = set(cfg) - {"prefixes", "capture", "ttl_seconds"}
    if unknown:
        raise HTTPException(422, f"passthrough: unknown keys {sorted(unknown)}")

    prefixes = cfg.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes or not all(
        isinstance(p, str) and p.strip() for p in prefixes
    ):
        raise HTTPException(422, "passthrough.prefixes must be a non-empty list of paths")

    capture = cfg.get("capture")
    if not isinstance(capture, dict):
        raise HTTPException(422, "passthrough.capture is required (prefixes + fields)")
    cap_prefixes = capture.get("prefixes")
    if not isinstance(cap_prefixes, list) or not cap_prefixes or not all(
        isinstance(p, str) and p.strip() for p in cap_prefixes
    ):
        raise HTTPException(422, "passthrough.capture.prefixes must be a non-empty list of paths")
    fields = capture.get("fields") or ["jwt"]
    if not isinstance(fields, list) or not all(
        isinstance(f, str) and 0 < len(f) <= 64 and f.isprintable() for f in fields
    ):
        raise HTTPException(422, "passthrough.capture.fields must be short JSON key names")

    ttl = cfg.get("ttl_seconds", 1800)
    if not isinstance(ttl, int) or not (60 <= ttl <= 86400):
        raise HTTPException(422, "passthrough.ttl_seconds must be an integer 60..86400")

    return {
        "prefixes": normalize_prefixes(prefixes),
        "capture": {"prefixes": normalize_prefixes(cap_prefixes), "fields": fields},
        "ttl_seconds": ttl,
    }


def check_request_allowed(route, method: str, subpath: str) -> None:
    """Enforce the route policy for a single request. Raises 403 on violation."""
    if method.upper() not in (route.allowed_methods or ["GET"]):
        raise HTTPException(403, f"Method {method} not allowed on this route")
    prefixes = route.allowed_path_prefixes or []
    if prefixes:
        candidate = subpath if subpath.startswith("/") else "/" + subpath
        if not any(candidate.startswith(p) for p in prefixes):
            raise HTTPException(403, "Path not allowed by route policy")


def build_upstream_url(route, subpath: str) -> str:
    """Join the route's upstream base with the request subpath, defeating
    traversal/absolute-URL escapes so a request can never leave the base."""
    sub = subpath.lstrip("/")
    # urljoin with a guaranteed trailing slash keeps the base path intact.
    target = urljoin(route.upstream_base + "/", sub)
    base = urlparse(route.upstream_base)
    got = urlparse(target)
    if (got.scheme, got.netloc) != (base.scheme, base.netloc):
        raise HTTPException(400, "Resolved upstream URL escapes the route base")
    if not got.path.startswith(base.path or "/"):
        raise HTTPException(400, "Resolved path escapes the route base path")
    return target


def injected_auth_header(mode: str, header: str, secret: str) -> tuple[str, str]:
    if mode == "bearer":
        return "Authorization", f"Bearer {secret}"
    if mode == "basic":
        return "Authorization", f"Basic {secret}"
    return header, secret


def inject_credential_header(fwd: dict, name: str, value: str) -> dict:
    """Set the injected credential header, first dropping any client-supplied
    copy under *any* casing. Header dicts are case-sensitive, so without this a
    client could smuggle e.g. `x-api-key` alongside the injected `X-API-Key`
    and have the upstream honor the attacker's (earlier) value. Returns a new
    dict; `name`/`value` win outright."""
    lower = name.lower()
    out = {k: v for k, v in fwd.items() if k.lower() != lower}
    out[name] = value
    return out


def forward_request_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _STRIP_REQUEST_HEADERS}


def forward_response_headers(headers) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _STRIP_RESPONSE_HEADERS}
