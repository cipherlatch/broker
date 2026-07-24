"""Metrics (Prometheus) and structured logging.

Every audit event increments cipherlatch_audit_events_total{event} and emits a log
line on the `cipherlatch.audit` logger — so token issuance/denial/lockout, logins,
and all lifecycle changes are observable from /metrics and stdout without
touching the database. With BROKER_LOG_JSON=true, logs are one JSON object
per line for SIEM/log-shipper ingestion.

The log MIRROR is configurable (the DB audit trail is always complete and
unmasked — it is the access-controlled authoritative record; the mirror is
what leaves the security boundary):
- BROKER_LOG_LEVEL / BROKER_LOG_FORMAT — level and text-mode format.
- BROKER_LOG_EVENTS / BROKER_LOG_EVENTS_EXCLUDE — fnmatch patterns choosing
  which audit events are mirrored ("token.*,gateway.*"). Metrics count all
  events regardless.
- BROKER_LOG_MASK_FIELDS + BROKER_LOG_MASK_MODE — mask sensitive fields
  (recursively, including inside detail) as sha256 prefixes (correlatable)
  or "[masked]".
"""

import fnmatch
import hashlib
import json
import logging
import time

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

AUDIT_EVENTS = Counter("cipherlatch_audit_events_total", "Audit events by type", ["event"])
HTTP_REQUESTS = Histogram(
    "cipherlatch_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path", "status"],
    buckets=(0.005, 0.025, 0.1, 0.25, 1.0, 5.0),
)
HTTP_IN_FLIGHT = Gauge("cipherlatch_http_requests_in_flight", "In-flight HTTP requests")

audit_logger = logging.getLogger("cipherlatch.audit")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "cipherlatch"):
            entry.update(record.cipherlatch)
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
           "warning": logging.WARNING, "warn": logging.WARNING,
           "error": logging.ERROR}


def setup_logging(log_json: bool, level: str = "info", fmt: str = "") -> None:
    handler = logging.StreamHandler()
    if log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(fmt or "%(asctime)s %(levelname)-5s %(name)s %(message)s")
        )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(_LEVELS.get((level or "info").strip().lower(), logging.INFO))


def _patterns(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def event_mirrored(event: str) -> bool:
    """Does this audit event reach the log mirror? (The DB record and the
    metrics counter are unconditional.)"""
    from .config import get_settings

    s = get_settings()
    include = _patterns(s.log_events)
    if include and not any(fnmatch.fnmatch(event, p) for p in include):
        return False
    exclude = _patterns(s.log_events_exclude)
    return not any(fnmatch.fnmatch(event, p) for p in exclude)


def _mask_value(value, mode: str) -> str:
    if mode == "redact":
        return "[masked]"
    digest = hashlib.sha256(str(value).encode()).hexdigest()[:12]
    return f"sha256:{digest}"


def mask_fields(fields: dict) -> dict:
    """Mask configured sensitive fields recursively (top level and inside
    nested dicts like `detail`). Returns a new dict; the input — which is
    also headed for the DB audit trail — is never mutated."""
    from .config import get_settings

    s = get_settings()
    names = {f.strip().lower() for f in s.log_mask_fields.split(",") if f.strip()}
    if not names:
        return fields
    mode = (s.log_mask_mode or "hash").strip().lower()

    def walk(d: dict) -> dict:
        out = {}
        for k, v in d.items():
            if k.lower() in names and v not in (None, ""):
                out[k] = _mask_value(v, mode)
            elif isinstance(v, dict):
                out[k] = walk(v)
            else:
                out[k] = v
        return out

    return walk(fields)


def observe_audit_event(event: str, fields: dict) -> None:
    AUDIT_EVENTS.labels(event=event).inc()
    if not event_mirrored(event):
        return
    fields = mask_fields(fields)
    audit_logger.info("audit %s", event, extra={"cipherlatch": {"event": event, **fields}})


async def http_metrics_middleware(request: Request, call_next):
    if request.url.path == "/metrics":
        return await call_next(request)
    HTTP_IN_FLIGHT.inc()
    start = time.perf_counter()
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    except Exception:
        status = 500
        raise
    finally:
        HTTP_IN_FLIGHT.dec()
        route = request.scope.get("route")
        path = getattr(route, "path", request.url.path if status != 404 else "<unmatched>")
        HTTP_REQUESTS.labels(
            method=request.method, path=path, status=str(status)
        ).observe(time.perf_counter() - start)


def metrics_endpoint() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
