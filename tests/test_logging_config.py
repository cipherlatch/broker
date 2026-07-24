"""Configurable log mirror: level/format, event include/exclude patterns,
and sensitive-field masking (hash and redact modes). The DB audit trail
stays complete and unmasked, and metrics count everything regardless.

Capture note: app startup replaces the ROOT handlers (setup_logging), which
wipes pytest's caplog handler — so these tests attach their own handler to
the `cipherlatch.audit` logger, which setup_logging never touches."""

import logging

import pytest
from fastapi.testclient import TestClient


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture()
def audit_log():
    handler = _Capture()
    logger = logging.getLogger("cipherlatch.audit")
    logger.addHandler(handler)
    yield handler.records
    logger.removeHandler(handler)


def _boot_admin(app):
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = "test-admin-key"
    return c


def test_mask_fields_hash_mode(make_app, audit_log):
    app = make_app(BROKER_LOG_MASK_FIELDS="actor,ip,owner")
    admin = _boot_admin(app)
    admin.post("/v1/users", json={"email": "owner@example.com"})
    admin.post("/v1/agents", json={
        "name": "log-agent", "owner_email": "owner@example.com",
        "allowed_scopes": ["a:b"],
    })

    created = next(r for r in audit_log if r.cipherlatch["event"] == "agent.created")
    # Top-level actor masked; nested detail.owner masked; both correlatable.
    assert created.cipherlatch["actor"].startswith("sha256:")
    assert created.cipherlatch["detail"]["owner"].startswith("sha256:")
    # Unmasked fields survive.
    assert created.cipherlatch["detail"]["name"] == "log-agent"

    # The DB audit record stays unmasked.
    events = admin.get("/v1/audit", params={"event": "agent.created"}).json()
    assert events[0]["actor"] == "admin-key"
    assert events[0]["detail"]["owner"] == "owner@example.com"


def test_mask_redact_mode(make_app, audit_log):
    app = make_app(BROKER_LOG_MASK_FIELDS="actor", BROKER_LOG_MASK_MODE="redact")
    admin = _boot_admin(app)
    admin.post("/v1/users", json={"email": "x@example.com"})
    rec = [r for r in audit_log if r.cipherlatch["event"] == "user.created"][-1]
    assert rec.cipherlatch["actor"] == "[masked]"


def test_event_include_patterns(make_app, audit_log):
    app = make_app(BROKER_LOG_EVENTS="token.*")
    admin = _boot_admin(app)
    admin.post("/v1/users", json={"email": "y@example.com"})  # user.created
    agent = admin.post("/v1/agents", json={
        "name": "tok-agent", "owner_email": "y@example.com",
        "allowed_scopes": ["a:b"],
    }).json()
    admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    })

    mirrored = {r.cipherlatch["event"] for r in audit_log}
    assert "token.issued" in mirrored
    assert "user.created" not in mirrored  # filtered from the mirror...

    # ...but still in the DB audit trail.
    events = admin.get("/v1/audit", params={"event": "user.created"}).json()
    assert len(events) == 1


def test_event_exclude_patterns(make_app, audit_log):
    app = make_app(BROKER_LOG_EVENTS_EXCLUDE="user.*,agent.*")
    admin = _boot_admin(app)
    admin.post("/v1/users", json={"email": "z@example.com"})
    admin.post("/v1/scim-token")
    mirrored = {r.cipherlatch["event"] for r in audit_log}
    assert "user.created" not in mirrored
    assert "scim.token.issued" in mirrored


def test_log_level_and_format_config(make_app):
    app = make_app(BROKER_LOG_LEVEL="warning",
                   BROKER_LOG_FORMAT="%(levelname)s :: %(message)s")
    with TestClient(app):
        pass
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert root.handlers[0].formatter._fmt == "%(levelname)s :: %(message)s"


def test_defaults_unchanged(make_app, audit_log):
    app = make_app()
    admin = _boot_admin(app)
    admin.post("/v1/users", json={"email": "d@example.com"})
    rec = [r for r in audit_log if r.cipherlatch["event"] == "user.created"][-1]
    assert rec.cipherlatch["actor"] == "admin-key"  # no masking by default
    assert logging.getLogger().level == logging.INFO
