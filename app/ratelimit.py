"""Per-client-IP rate limiting for the token and gateway endpoints.

Fixed-window counter held in process memory. It is per-replica: with N
replicas the effective limit is N × the configured value. That is acceptable
as a first line of defense (the per-agent lockout in the token endpoint is the
credential-stuffing control; this caps raw request volume per source). A
shared/Redis limiter is the upgrade path if precise cluster-wide limits are
needed.
"""

import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse

from .authz import client_ip
from .config import get_settings
from .observability import AUDIT_EVENTS

_lock = threading.Lock()
# (ip, bucket_key) -> [window_start, count]
_windows: dict[tuple[str, str], list] = {}
_last_sweep = 0.0
# Hard ceiling so a flood of distinct source IPs can't grow the map without
# bound; past it, expired entries are dropped and, failing that, the whole map
# is reset (fail-open on accounting, never on memory).
_MAX_WINDOWS = 100_000

# Only these path prefixes are limited; management/UI traffic is not.
_LIMITED_PREFIXES = ("/oauth/", "/gw/")


def _bucket_for(path: str) -> str | None:
    for p in _LIMITED_PREFIXES:
        if path.startswith(p):
            return p
    return None


def _client_ip(request: Request) -> str:
    return client_ip(request) or "unknown"


def _sweep_locked(now: float, window: int) -> None:
    """Drop windows whose period has elapsed. Caller holds _lock."""
    global _last_sweep
    expired = [k for k, v in _windows.items() if now - v[0] >= window]
    for k in expired:
        del _windows[k]
    _last_sweep = now
    if len(_windows) > _MAX_WINDOWS:
        _windows.clear()  # pathological cardinality: reset rather than leak


def _allow(ip: str, bucket: str, limit: int, window: int) -> bool:
    now = time.time()
    key = (ip, bucket)
    with _lock:
        # Periodic eviction keeps the map proportional to *active* sources, not
        # to every IP ever seen (bounded memory under a distributed flood).
        if now - _last_sweep >= window or len(_windows) > _MAX_WINDOWS:
            _sweep_locked(now, window)
        entry = _windows.get(key)
        if entry is None or now - entry[0] >= window:
            _windows[key] = [now, 1]
            return True
        if entry[1] >= limit:
            return False
        entry[1] += 1
        return True


async def rate_limit_middleware(request: Request, call_next):
    settings = get_settings()
    limit = settings.rate_limit_per_minute
    bucket = _bucket_for(request.url.path)
    if limit > 0 and bucket is not None:
        ip = _client_ip(request)
        if not _allow(ip, bucket, limit, settings.rate_limit_window_seconds):
            AUDIT_EVENTS.labels(event="rate_limited").inc()
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "error_description": "Too many requests"},
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )
    return await call_next(request)


def reset_windows() -> None:
    """Test helper: clear the in-process counters."""
    global _last_sweep
    with _lock:
        _windows.clear()
        _last_sweep = 0.0
