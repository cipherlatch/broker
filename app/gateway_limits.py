"""Per-route, per-agent rate limits and daily quotas for the gateway.

Fixed-window counters in process memory, one minute window for the rate
limit and a UTC-day window for the quota. Like the per-IP limiter
(app/ratelimit.py) this is per-replica: with N replicas the effective limit
is N × the configured value — acceptable as a request-volume control; a
shared store is the cluster-precise upgrade. Restarts reset the counters
(a deploy mid-day refunds the day's quota), which is the documented
trade-off for keeping the hot path free of DB writes.
"""

import threading
import time

_lock = threading.Lock()
# (route_id, agent_id) -> [window_start, count]
_minute: dict[tuple[str, str], list] = {}
# (route_id, agent_id, yyyymmdd) -> count
_daily: dict[tuple[str, str, str], int] = {}


def _today() -> str:
    return time.strftime("%Y%m%d", time.gmtime())


def check_and_count(route, agent_id: str) -> str | None:
    """Enforce the route's limits for one request. Returns a denial reason
    ("rate_limited" / "quota_exceeded") or None — and counts the request
    only when it is allowed."""
    rpm = route.rate_limit_per_minute or 0
    quota = route.daily_quota or 0
    if not rpm and not quota:
        return None

    now = time.time()
    day = _today()
    mkey = (route.id, agent_id)
    dkey = (route.id, agent_id, day)
    with _lock:
        entry = _minute.get(mkey)
        if entry is None or now - entry[0] >= 60:
            entry = [now, 0]
            _minute[mkey] = entry
        if rpm and entry[1] >= rpm:
            return "rate_limited"
        if quota and _daily.get(dkey, 0) >= quota:
            return "quota_exceeded"

        entry[1] += 1
        if quota:
            new = _daily.get(dkey, 0) + 1
            _daily[dkey] = new
            if new == 1:  # first hit of a new day: drop stale day buckets
                for k in [k for k in _daily if k[2] != day]:
                    del _daily[k]
    return None


def reset() -> None:
    """Test hook."""
    with _lock:
        _minute.clear()
        _daily.clear()
