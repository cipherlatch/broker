"""Lifecycle of the bootstrap ("default") admin from BROKER_ADMIN_EMAILS:
pinned re-promotion vs. BROKER_ADMIN_EMAIL_PINNING=false, and that disable /
delete stick — including when the IdP later rotates the account's subject.
"""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.testing import ADMIN_KEY
from tests.conftest import FAKE_DISCOVERY

BOSS = "boss@example.com"


def _login(app, monkeypatch, email, sub=None):
    import app.oidc as oidc_module

    claims = {
        "sub": sub or f"sub-{email}",
        "email": email,
        "email_verified": True,
        "name": "",
    }
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    with c:
        pass  # run lifespan once (schema)
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    resp = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    return c, resp


def _machine(app):
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return c


def _user(machine, email):
    return next(u for u in machine.get("/v1/users").json() if u["email"] == email)


def _add_second_admin(machine):
    r = machine.post(
        "/v1/users",
        json={"email": "backup-admin@example.com", "role": "broker-admin"},
    )
    assert r.status_code == 201


def test_pinned_default_admin_is_repromoted_on_login(make_app, monkeypatch):
    """Default behavior: while listed in ADMIN_EMAILS, a demotion lasts only
    until the next login."""
    app = make_app(BROKER_ADMIN_EMAILS=BOSS)
    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 302
    machine = _machine(app)
    assert _user(machine, BOSS)["role"] == "broker-admin"

    _add_second_admin(machine)
    boss = _user(machine, BOSS)
    assert machine.patch(f"/v1/users/{boss['id']}", json={"role": "agent-manager"}).status_code == 200
    assert _user(machine, BOSS)["role"] == "agent-manager"

    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 302
    assert _user(machine, BOSS)["role"] == "broker-admin"  # pinned: promotion is back


def test_unpinned_default_admin_demotion_sticks(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS=BOSS, BROKER_ADMIN_EMAIL_PINNING="false")
    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 302
    machine = _machine(app)
    # JIT still seeds broker-admin on first login even without pinning.
    assert _user(machine, BOSS)["role"] == "broker-admin"

    _add_second_admin(machine)
    boss = _user(machine, BOSS)
    assert machine.patch(f"/v1/users/{boss['id']}", json={"role": "agent-manager"}).status_code == 200

    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 302
    assert _user(machine, BOSS)["role"] == "agent-manager"  # demotion survived a login


def test_default_admin_disable_sticks_and_kills_session(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS=BOSS)
    session, _ = _login(app, monkeypatch, BOSS)
    machine = _machine(app)
    _add_second_admin(machine)

    boss = _user(machine, BOSS)
    assert machine.patch(f"/v1/users/{boss['id']}", json={"active": False}).status_code == 200

    # Live session dies immediately; re-login is denied even though the email
    # is still listed in ADMIN_EMAILS (pinning promotes, it never reactivates).
    assert session.get("/v1/agents").status_code == 401
    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 403
    denials = machine.get("/v1/audit", params={"event": "login.denied"}).json()
    assert any(d["detail"].get("reason") == "account_disabled" for d in denials)


def test_default_admin_delete_sticks_even_when_idp_sub_rotates(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS=BOSS)
    _login(app, monkeypatch, BOSS)
    machine = _machine(app)
    _add_second_admin(machine)

    boss = _user(machine, BOSS)
    assert machine.delete(f"/v1/users/{boss['id']}").status_code == 200

    # Same subject: found by sub, denied as disabled.
    _, resp = _login(app, monkeypatch, BOSS)
    assert resp.status_code == 403

    # Rotated subject: must not resurrect the account through JIT (which
    # would also collide with the soft-deleted row's email) — clean denial.
    _, resp = _login(app, monkeypatch, BOSS, sub="sub-rotated-by-idp")
    assert resp.status_code == 403
    denials = machine.get("/v1/audit", params={"event": "login.denied"}).json()
    assert any(d["detail"].get("reason") == "account_deleted" for d in denials)
    assert BOSS not in {u["email"] for u in machine.get("/v1/users").json()}


def test_sole_default_admin_still_protected_by_last_admin_guard(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS=BOSS, BROKER_ADMIN_EMAIL_PINNING="false")
    _login(app, monkeypatch, BOSS)
    machine = _machine(app)

    boss = _user(machine, BOSS)
    assert machine.patch(f"/v1/users/{boss['id']}", json={"active": False}).status_code == 409
    assert machine.patch(f"/v1/users/{boss['id']}", json={"role": "agent-manager"}).status_code == 409
    assert machine.delete(f"/v1/users/{boss['id']}").status_code == 409
