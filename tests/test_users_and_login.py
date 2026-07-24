"""Human user lifecycle: JIT, manual add, modify, delete, and login gating."""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY


def _stub_and_login(app, monkeypatch, email, extra=None):
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    claims.update(extra or {})
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


def test_jit_provisions_and_audits(login, admin):
    c, resp = login("new@example.com", name="New Person")
    assert resp.status_code == 302

    users = admin.get("/v1/users").json()
    me = next(u for u in users if u["email"] == "new@example.com")
    assert me["provisioned"] is True
    assert me["role"] == "agent-manager"

    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert {"login.jit_provisioned", "login.success"} <= events


def test_jit_disabled_denies_unknown_users(make_app, monkeypatch):
    app = make_app(BROKER_JIT_PROVISIONING="false")
    c, resp = _stub_and_login(app, monkeypatch, "stranger@example.com")
    assert resp.status_code == 403

    # Denial is audited.
    c.headers["X-Admin-Key"] = "test-admin-key"
    denials = c.get("/v1/audit", params={"event": "login.denied"}).json()
    assert any(d["actor"] == "stranger@example.com" for d in denials)


def test_manual_add_then_login_links_by_email(make_app, monkeypatch):
    app = make_app(BROKER_JIT_PROVISIONING="false")

    boot = TestClient(app)
    with boot:
        pass
    boot.headers["X-Admin-Key"] = "test-admin-key"
    created = boot.post(
        "/v1/users", json={"email": "invited@example.com", "display_name": "Invited", "role": "agent-manager"}
    )
    assert created.status_code == 201
    assert created.json()["provisioned"] is False

    c, resp = _stub_and_login(app, monkeypatch, "invited@example.com")
    assert resp.status_code == 302  # linked, not denied

    users = boot.get("/v1/users").json()
    me = next(u for u in users if u["email"] == "invited@example.com")
    assert me["provisioned"] is True

    events = {e["event"] for e in boot.get("/v1/audit").json()}
    assert "account.linked" in events


def test_disable_user_blocks_login_and_api(login, admin):
    c, _ = login("victim@example.com")
    users = admin.get("/v1/users").json()
    victim = next(u for u in users if u["email"] == "victim@example.com")

    updated = admin.patch(f"/v1/users/{victim['id']}", json={"active": False})
    assert updated.status_code == 200

    # Existing session is dead immediately (actor resolution checks active).
    assert c.get("/v1/agents").status_code == 401


def test_delete_user_revokes_their_agents(login, admin):
    c, _ = login("leaver@example.com")
    agent = c.post("/v1/agents", json={"name": "leaver-agent", "allowed_scopes": ["x:y"]}).json()

    users = admin.get("/v1/users").json()
    leaver = next(u for u in users if u["email"] == "leaver@example.com")
    result = admin.delete(f"/v1/users/{leaver['id']}").json()
    assert result == {"deleted": "leaver@example.com", "agents_revoked": 1}

    # Gone from the user list; agent revoked; audit trail complete.
    emails = {u["email"] for u in admin.get("/v1/users").json()}
    assert "leaver@example.com" not in emails
    assert admin.get(f"/v1/agents/{agent['id']}").json()["active"] is False
    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert "user.deleted" in events

    # Their tokens stop minting.
    tok = admin.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        },
    )
    assert tok.status_code == 401


def test_user_modify_is_audited_with_changes(login, admin):
    login("target@example.com")
    users = admin.get("/v1/users").json()
    target = next(u for u in users if u["email"] == "target@example.com")

    admin.patch(f"/v1/users/{target['id']}", json={"role": "broker-admin", "display_name": "Promoted"})
    events = admin.get("/v1/audit", params={"event": "user.updated"}).json()
    assert any(e["detail"].get("changes", {}).get("role") == ["agent-manager", "broker-admin"] for e in events)


def test_ui_requires_login_and_login_page_renders(client):
    resp = client.get("/ui/agents", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"

    page = client.get("/login")
    assert page.status_code == 200
    assert "Sign in with SSO" in page.text


def test_ui_pages_render_for_logged_in_user(login):
    c, _ = login("uiuser@example.com")
    c.post("/v1/agents", json={"name": "ui-agent", "allowed_scopes": ["a:b"]})

    agents_page = c.get("/ui/agents")
    assert agents_page.status_code == 200
    assert "ui-agent" in agents_page.text

    audit_page = c.get("/ui/audit")
    assert audit_page.status_code == 200

    # Non-admin must not see the users page (hidden as 404).
    assert c.get("/ui/users").status_code == 404


def test_cross_origin_session_post_rejected(login):
    c, _ = login("csrf@example.com")
    resp = c.post(
        "/v1/agents",
        json={"name": "evil", "allowed_scopes": []},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_login_relinks_when_idp_subject_rotates(make_app, monkeypatch):
    """If the IdP's `sub` for an existing account changes (subject-mode change
    or SCIM rewriting externalId), a verified-email login re-binds the new sub
    instead of dead-ending at JIT with a 409 'already exists'."""
    app = make_app()
    boot = TestClient(app)
    with boot:
        pass
    boot.headers["X-Admin-Key"] = "test-admin-key"

    # First login establishes the account with the original sub.
    c1, r1 = _stub_and_login(app, monkeypatch, "owner@example.com",
                             extra={"sub": "old-subject-id"})
    assert r1.status_code == 302

    # Authentik now sends a different sub for the same verified email.
    c2, r2 = _stub_and_login(app, monkeypatch, "owner@example.com",
                             extra={"sub": "new-uuid-subject"})
    assert r2.status_code == 302  # re-linked, NOT 409

    # Still one account, and the new session works.
    users = boot.get("/v1/users").json()
    assert sum(u["email"] == "owner@example.com" for u in users) == 1
    assert c2.get("/v1/agents").status_code == 200
    events = {e["event"] for e in boot.get("/v1/audit").json()}
    assert "account.relinked" in events
