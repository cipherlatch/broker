"""Configurable roles and permission enforcement."""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY


def _login_on(app, monkeypatch, email):
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    with c:
        pass
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    return c


def test_builtin_roles_seeded(admin):
    admin.post("/v1/users", json={"email": "seed@example.com"})  # forces tenant creation
    roles = {r["name"]: r for r in admin.get("/v1/roles").json()}
    assert {"broker-admin", "agent-manager", "auditor"} <= set(roles)
    assert all(roles[n]["builtin"] for n in ("broker-admin", "agent-manager", "auditor"))
    assert roles["broker-admin"]["permissions"] == ["*"]


def test_custom_role_lifecycle(admin):
    created = admin.post(
        "/v1/roles",
        json={
            "name": "read-only-agents",
            "description": "sees own agents only",
            "permissions": ["agents:read", "audit:read"],
        },
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["id"]

    updated = admin.patch(
        f"/v1/roles/{role_id}", json={"permissions": ["agents:read", "agents:create", "audit:read"]}
    )
    assert updated.status_code == 200
    assert "agents:create" in updated.json()["permissions"]

    events = admin.get("/v1/audit", params={"event": "role.updated"}).json()
    assert any("permissions" in e["detail"].get("changes", {}) for e in events)

    assert admin.delete(f"/v1/roles/{role_id}").status_code == 200


def test_unknown_permission_rejected(admin):
    resp = admin.post(
        "/v1/roles", json={"name": "bogus", "permissions": ["agents:launch-missiles"]}
    )
    assert resp.status_code == 422


def test_builtin_roles_immutable(admin):
    admin.post("/v1/users", json={"email": "seed2@example.com"})
    roles = {r["name"]: r for r in admin.get("/v1/roles").json()}
    rid = roles["agent-manager"]["id"]
    assert admin.patch(f"/v1/roles/{rid}", json={"permissions": ["*"]}).status_code == 409
    assert admin.delete(f"/v1/roles/{rid}").status_code == 409


def test_role_in_use_cannot_be_deleted(admin):
    admin.post("/v1/roles", json={"name": "temp-role", "permissions": ["agents:read"]})
    admin.post("/v1/users", json={"email": "holder@example.com", "role": "temp-role"})
    roles = {r["name"]: r for r in admin.get("/v1/roles").json()}
    assert admin.delete(f"/v1/roles/{roles['temp-role']['id']}").status_code == 409


def test_auditor_is_read_only_but_sees_everything(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS="root@example.com")
    owner = _login_on(app, monkeypatch, "owner@example.com")
    agent = owner.post("/v1/agents", json={"name": "owned", "allowed_scopes": ["x:y"]}).json()

    root = _login_on(app, monkeypatch, "root@example.com")
    root.post("/v1/users", json={"email": "auditor@example.com", "role": "auditor"})
    auditor = _login_on(app, monkeypatch, "auditor@example.com")

    # Sees every agent and the full audit log...
    names = {a["name"] for a in auditor.get("/v1/agents").json()}
    assert "owned" in names
    events = auditor.get("/v1/audit").json()
    assert any(e["agent_id"] == agent["id"] for e in events)
    assert auditor.get("/v1/users").status_code == 200
    assert auditor.get("/v1/roles").status_code == 200

    # ...but cannot change anything.
    assert auditor.post("/v1/agents", json={"name": "nope"}).status_code == 403
    assert auditor.patch(f"/v1/agents/{agent['id']}", json={"description": "x"}).status_code == 404
    assert auditor.post(f"/v1/agents/{agent['id']}/rotate").status_code == 404
    assert auditor.delete(f"/v1/agents/{agent['id']}").status_code == 404
    assert auditor.post("/v1/users", json={"email": "x@example.com"}).status_code == 403
    assert auditor.post("/v1/roles", json={"name": "x", "permissions": []}).status_code == 403


def test_custom_role_enforced_at_runtime(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS="root@example.com")
    root = _login_on(app, monkeypatch, "root@example.com")
    root.post(
        "/v1/roles",
        json={"name": "creator", "permissions": ["agents:create", "agents:read"]},
    )
    root.post("/v1/users", json={"email": "maker@example.com", "role": "creator"})
    maker = _login_on(app, monkeypatch, "maker@example.com")

    agent = maker.post("/v1/agents", json={"name": "made", "allowed_scopes": []})
    assert agent.status_code == 201
    # No rotate/revoke/update permission — even on their own agent.
    aid = agent.json()["id"]
    assert maker.post(f"/v1/agents/{aid}/rotate").status_code == 404
    assert maker.delete(f"/v1/agents/{aid}").status_code == 404

    # Live permission edit takes effect on the next request.
    roles = {r["name"]: r for r in root.get("/v1/roles").json()}
    root.patch(
        f"/v1/roles/{roles['creator']['id']}",
        json={"permissions": ["agents:create", "agents:read", "agents:rotate"]},
    )
    assert maker.post(f"/v1/agents/{aid}/rotate").status_code == 200


def test_delegated_manager_cannot_escalate_beyond_own_permissions(make_app, monkeypatch):
    """A holder of users:/roles:/service_keys:manage (but not `*`) must not be
    able to confer broker-admin — via a new user, a new role, or a service key —
    which would be a self-escalation to full tenant control."""
    app = make_app(BROKER_ADMIN_EMAILS="root@example.com")
    root = _login_on(app, monkeypatch, "root@example.com")
    root.post("/v1/roles", json={
        "name": "delegated-admin",
        "permissions": ["users:manage", "roles:manage", "service_keys:manage"],
    })
    root.post("/v1/users", json={"email": "delegate@example.com", "role": "delegated-admin"})
    delegate = _login_on(app, monkeypatch, "delegate@example.com")

    # Cannot mint a user carrying a role more privileged than the delegate.
    assert delegate.post(
        "/v1/users", json={"email": "puppet@example.com", "role": "broker-admin"}
    ).status_code == 403
    # Cannot author a role holding permissions the delegate lacks (here, `*`).
    assert delegate.post(
        "/v1/roles", json={"name": "superpower", "permissions": ["*"]}
    ).status_code == 403
    # Cannot mint a service key carrying broker-admin.
    assert delegate.post(
        "/v1/service-keys", json={"name": "sk", "role": "broker-admin"}
    ).status_code == 403

    # Positive control: granting within its own permission set still works.
    assert delegate.post(
        "/v1/roles", json={"name": "helper", "permissions": ["users:manage"]}
    ).status_code == 201


def test_multiple_admins_and_last_admin_guard(make_app, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS="a1@example.com,a2@example.com")
    a1 = _login_on(app, monkeypatch, "a1@example.com")
    a2 = _login_on(app, monkeypatch, "a2@example.com")

    # Both admins see the users surface.
    assert a1.get("/v1/users").status_code == 200
    assert a2.get("/v1/users").status_code == 200

    users = {u["email"]: u for u in a1.get("/v1/users").json()}

    # Demoting one admin is fine while another remains.
    resp = a1.patch(f"/v1/users/{users['a2@example.com']['id']}", json={"role": "agent-manager"})
    assert resp.status_code == 200

    # Now a1 is the last admin-capable user: cannot be demoted/disabled/deleted.
    boot = TestClient(app)
    boot.headers["X-Admin-Key"] = "test-admin-key"
    assert boot.patch(
        f"/v1/users/{users['a1@example.com']['id']}", json={"role": "agent-manager"}
    ).status_code == 409
    assert boot.patch(
        f"/v1/users/{users['a1@example.com']['id']}", json={"active": False}
    ).status_code == 409
    assert boot.delete(f"/v1/users/{users['a1@example.com']['id']}").status_code == 409
