"""Standing-root hardening for the machine admin key: every use audited,
comma-list rotation, and the /readyz warning when the broker is keyless with
no active admin login left."""

from fastapi.testclient import TestClient

from app import admin as admin_cli
from app.testing import ADMIN_KEY


def _client(app, key=None):
    c = TestClient(app)
    with c:
        pass
    if key is not None:
        c.headers["X-Admin-Key"] = key
    return c


# --- every use is audited -----------------------------------------------------


def test_admin_key_use_is_audited_including_reads(admin):
    admin.get("/v1/agents")  # a pure read

    events = admin.get("/v1/audit", params={"event": "admin_key.used"}).json()
    assert any(
        e["actor"] == "admin-key" and e["detail"].get("path") == "/v1/agents"
        for e in events
    )


def test_session_requests_do_not_emit_admin_key_events(login, admin):
    baseline = len(admin.get("/v1/audit", params={"event": "admin_key.used"}).json())
    c, _ = login("human@example.com")
    c.get("/v1/agents")
    c.get("/ui/agents")

    events = admin.get("/v1/audit", params={"event": "admin_key.used"}).json()
    # Only the two admin-key audit *reads* themselves were added, nothing from
    # the human session.
    assert all(e["actor"] == "admin-key" for e in events)
    assert len(events) == baseline + 1  # the baseline read itself


def test_invalid_key_still_401s(client):
    r = client.get("/v1/agents", headers={"X-Admin-Key": "wrong"})
    assert r.status_code == 401


# --- comma-list rotation --------------------------------------------------------


def test_any_key_in_the_list_authenticates(make_app):
    app = make_app(BROKER_ADMIN_API_KEY="old-key, new-key")
    for key in ("old-key", "new-key"):
        assert _client(app, key).get("/v1/agents").status_code == 200
    assert _client(app, "retired-key").get("/v1/agents").status_code == 401


def test_single_key_config_unchanged(admin):
    assert admin.headers["X-Admin-Key"] == ADMIN_KEY
    assert admin.get("/v1/agents").status_code == 200


# --- keyless posture / readyz ---------------------------------------------------


def test_readyz_warns_when_keyless_and_adminless(make_app):
    app = make_app(BROKER_ADMIN_API_KEY="")
    c = _client(app)
    body = c.get("/readyz").json()
    assert body["database"] == "ok"
    assert body["admin_access"].startswith("warning: no admin key")
    assert "app.admin promote" in body["admin_access"]
    # A warning, never a readiness failure.
    assert c.get("/readyz").status_code == 200


def test_readyz_ok_once_cli_recovers_an_admin(make_app):
    app = make_app(BROKER_ADMIN_API_KEY="")
    c = _client(app)
    assert c.get("/readyz").json()["admin_access"].startswith("warning")

    assert admin_cli.main(["promote", "boss@example.com"]) == 0
    assert c.get("/readyz").json()["admin_access"] == "ok"


def test_readyz_has_no_admin_access_field_when_key_configured(admin):
    body = admin.get("/readyz").json()
    assert "admin_access" not in body


def test_keyless_broker_rejects_the_header_entirely(make_app):
    app = make_app(BROKER_ADMIN_API_KEY="")
    # Even a correct-looking key is anonymous when the feature is off: the
    # endpoint requires auth, so the request is a clean 401.
    assert _client(app, ADMIN_KEY).get("/v1/agents").status_code == 401
