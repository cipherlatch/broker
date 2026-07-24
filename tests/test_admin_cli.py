"""Break-glass recovery CLI (app.admin): recover an admin against the DB with
no network credential, the way `docker exec ... python -m app.admin` would."""

from fastapi.testclient import TestClient

from app import admin as admin_cli
from app.testing import ADMIN_KEY


def _schema(app):
    # Entering the client runs the lifespan, which creates the schema; the CLI
    # then reuses the same cached engine / DB file.
    with TestClient(app):
        pass


def _machine(app):
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return c


def _user(machine, email):
    return next((u for u in machine.get("/v1/users").json() if u["email"] == email), None)


def test_promote_creates_admin_when_none_exists(make_app, capsys):
    app = make_app()
    _schema(app)

    assert admin_cli.main(["promote", "boss@example.com", "--name", "Boss"]) == 0
    assert "Created boss@example.com as broker-admin" in capsys.readouterr().out

    machine = _machine(app)
    u = _user(machine, "boss@example.com")
    assert u is not None and u["role"] == "broker-admin" and u["active"] is True
    # The break-glass action is in the audit trail under a distinct actor.
    events = machine.get("/v1/audit").json()
    assert any(e["actor"] == "admin-cli" for e in events)


def test_promote_reactivates_and_promotes_existing(make_app, monkeypatch, capsys):
    app = make_app()
    _schema(app)
    machine = _machine(app)
    # A normal, disabled, non-admin user (needs a second admin to allow disable).
    machine.post("/v1/users", json={"email": "keeper@example.com", "role": "broker-admin"})
    machine.post("/v1/users", json={"email": "user@example.com", "role": "agent-manager"})
    uid = _user(machine, "user@example.com")["id"]
    assert machine.patch(f"/v1/users/{uid}", json={"active": False}).status_code == 200

    assert admin_cli.main(["promote", "user@example.com"]) == 0
    out = capsys.readouterr().out
    assert "reactivated" in out and "promoted to broker-admin" in out

    u = _user(machine, "user@example.com")
    assert u["active"] is True and u["role"] == "broker-admin"


def test_promote_is_idempotent(make_app, capsys):
    app = make_app()
    _schema(app)
    admin_cli.main(["promote", "boss@example.com"])
    capsys.readouterr()

    assert admin_cli.main(["promote", "boss@example.com"]) == 0
    assert "already an active broker-admin" in capsys.readouterr().out


def test_promote_restores_soft_deleted_account(make_app, capsys):
    """The recovery case behind the whole feature: the last admin was deleted,
    leaving a soft-deleted row whose email blocks a fresh create."""
    app = make_app()
    _schema(app)
    machine = _machine(app)
    # Two admins so one can be deleted; then delete it to leave a tombstone.
    machine.post("/v1/users", json={"email": "keeper@example.com", "role": "broker-admin"})
    machine.post("/v1/users", json={"email": "gone@example.com", "role": "broker-admin"})
    uid = _user(machine, "gone@example.com")["id"]
    assert machine.delete(f"/v1/users/{uid}").status_code == 200
    assert _user(machine, "gone@example.com") is None  # soft-deleted, hidden

    assert admin_cli.main(["promote", "gone@example.com"]) == 0
    assert "Restored soft-deleted gone@example.com" in capsys.readouterr().out

    u = _user(machine, "gone@example.com")
    assert u is not None and u["role"] == "broker-admin" and u["active"] is True


def test_list_warns_when_no_active_admin(make_app, monkeypatch, capsys):
    # JIT-provision a single non-admin user, no admin anywhere.
    app = make_app()
    import app.oidc as oidc_module
    from urllib.parse import parse_qs, urlparse
    from tests.conftest import FAKE_DISCOVERY

    claims = {"sub": "s1", "email": "lonely@example.com", "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    with c:
        pass
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)

    assert admin_cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "0 active admin-capable" in out
    assert "WARNING: no active admin-capable user" in out


def test_promote_respects_tenant_scope(make_app, capsys):
    app = make_app()
    _schema(app)
    assert admin_cli.main(["promote", "boss@acme.example", "--tenant", "acme"]) == 0
    capsys.readouterr()

    # The account lands in the named tenant, not default.
    machine = _machine(app)
    assert _user(machine, "boss@acme.example") is None  # default tenant is empty
    acme = machine.get("/v1/users", headers={"X-Tenant": "acme"}).json()
    assert any(u["email"] == "boss@acme.example" and u["role"] == "broker-admin" for u in acme)
