"""IdP group -> role mapping at login."""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY

GROUP_ENV = {"BROKER_GROUP_ROLE_MAP": "cipherlatch-admins=broker-admin,cipherlatch-auditors=auditor"}


def _login(app, monkeypatch, email, groups):
    import app.oidc as oidc_module

    claims = {
        "sub": f"sub-{email}",
        "email": email,
        "email_verified": True,
        "name": "",
        "groups": groups,
    }
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    with c:
        pass
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    resp = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    return c, resp


def _role_of(app_client, email):
    app_client.headers["X-Admin-Key"] = "test-admin-key"
    return next(
        u["role"] for u in app_client.get("/v1/users").json() if u["email"] == email
    )


def test_jit_uses_group_mapping(make_app, monkeypatch):
    app = make_app(**GROUP_ENV)
    c, resp = _login(app, monkeypatch, "aud@example.com", ["staff", "cipherlatch-auditors"])
    assert resp.status_code == 302
    assert _role_of(c, "aud@example.com") == "auditor"


def test_group_change_resyncs_role(make_app, monkeypatch):
    app = make_app(**GROUP_ENV)
    c, _ = _login(app, monkeypatch, "mover@example.com", ["cipherlatch-auditors"])
    assert _role_of(c, "mover@example.com") == "auditor"

    # Group membership changes in the IdP; next login re-syncs.
    c2, _ = _login(app, monkeypatch, "mover@example.com", ["cipherlatch-admins"])
    assert _role_of(c2, "mover@example.com") == "broker-admin"

    # And the sync is audited with the idp-groups actor.
    events = c2.get("/v1/audit", params={"event": "user.updated"}).json()
    assert any(e["actor"] == "idp-groups" for e in events)


def test_no_matching_group_leaves_role_alone(make_app, monkeypatch):
    app = make_app(**GROUP_ENV)
    c, _ = _login(app, monkeypatch, "plain@example.com", ["unrelated-group"])
    assert _role_of(c, "plain@example.com") == "agent-manager"  # default


def test_first_match_wins(make_app, monkeypatch):
    app = make_app(**GROUP_ENV)
    c, _ = _login(app, monkeypatch, "both@example.com", ["cipherlatch-auditors", "cipherlatch-admins"])
    # Map order is cipherlatch-admins first, so membership in both -> broker-admin.
    assert _role_of(c, "both@example.com") == "broker-admin"


def test_last_admin_protected_from_group_demotion(make_app, monkeypatch):
    app = make_app(**GROUP_ENV)
    c, _ = _login(app, monkeypatch, "solo@example.com", ["cipherlatch-admins"])
    assert _role_of(c, "solo@example.com") == "broker-admin"

    # IdP drops them to auditors while they are the only admin: sync is skipped.
    c2, resp = _login(app, monkeypatch, "solo@example.com", ["cipherlatch-auditors"])
    assert resp.status_code == 302
    assert _role_of(c2, "solo@example.com") == "broker-admin"
    skipped = c2.get("/v1/audit", params={"event": "login.role_sync_skipped"}).json()
    assert any(e["detail"]["reason"] == "last_admin_guard" for e in skipped)
