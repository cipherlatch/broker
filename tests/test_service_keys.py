"""Service keys: scoped machine credentials for the control plane.

A service key carries a Role and authenticates via X-Api-Key with that role's
permissions — within its tenant, never platform admin. First consumer:
Nightlatch (a monitor role = audit:read:all + agents:revoke:all).
"""

from fastapi.testclient import TestClient

from app.testing import ADMIN_KEY


def _admin(app) -> TestClient:
    c = TestClient(app)
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return c


def _svc(app, key: str) -> TestClient:
    c = TestClient(app)
    c.headers["X-Api-Key"] = key
    return c


def _make_key(admin, *, role="auditor", name="svc"):
    r = admin.post("/v1/service-keys", json={"name": name, "role": role})
    assert r.status_code == 201, r.text
    return r.json()


def test_key_shape_and_role_scoped_auth(app):
    with _admin(app) as admin:
        created = _make_key(admin, role="auditor", name="mon")
        assert created["api_key"].startswith("csk_")
        assert created["role"] == "auditor" and created["active"] is True
        with _svc(app, created["api_key"]) as svc:
            # auditor grants read across the tenant...
            assert svc.get("/v1/audit").status_code == 200
            assert svc.get("/v1/agents").status_code == 200
            # ...but not create (no agents:create in the auditor role)
            r = svc.post("/v1/agents", json={"name": "x", "owner_email": "owner@example.com"})
            assert r.status_code == 403


def test_service_key_is_never_platform_admin(app):
    """Even a service key carrying broker-admin ('*') is tenant-plane only:
    it can manage users in its tenant but cannot touch the platform plane."""
    with _admin(app) as admin:
        created = _make_key(admin, role="broker-admin", name="super")
        with _svc(app, created["api_key"]) as svc:
            assert svc.get("/v1/users").status_code == 200  # '*' within tenant
            r = svc.post("/v1/tenants", json={"slug": "evil", "name": "Evil"})
            assert r.status_code == 403  # platform admin (X-Admin-Key) only


def test_invalid_and_revoked_keys_rejected(app):
    with _admin(app) as admin:
        created = _make_key(admin, name="tmp")
        with _svc(app, "csk_not-a-real-key") as bad:
            assert bad.get("/v1/audit").status_code == 401
        with _svc(app, created["api_key"]) as svc:
            assert svc.get("/v1/audit").status_code == 200
        resp = admin.post(f"/v1/service-keys/{created['id']}/revoke")
        assert resp.status_code == 200 and resp.json()["active"] is False
        with _svc(app, created["api_key"]) as svc:
            assert svc.get("/v1/audit").status_code == 401  # dead immediately


def test_admin_key_takes_precedence_over_service_key(app):
    """If both headers are present the platform admin key wins (checked first)."""
    with _admin(app) as admin:
        created = _make_key(admin, role="auditor", name="both")
        c = TestClient(app)
        c.headers["X-Admin-Key"] = ADMIN_KEY
        c.headers["X-Api-Key"] = created["api_key"]
        with c:
            # tenant management would 403 for the service key but succeeds for admin
            assert c.post("/v1/tenants", json={"slug": "t2", "name": "T2"}).status_code == 201


def test_nightlatch_monitor_role_reads_audit_and_revokes(app):
    with _admin(app) as admin:
        admin.post("/v1/roles", json={
            "name": "monitor",
            "description": "Nightlatch: watch + circuit-break",
            "permissions": ["audit:read:all", "agents:revoke:all"],
        })
        admin.post("/v1/users", json={"email": "owner@test.co", "role": "agent-manager"})
        agent = admin.post("/v1/agents", json={"name": "target", "owner_email": "owner@test.co"})
        assert agent.status_code == 201, agent.text
        agent_id = agent.json()["id"]

        created = _make_key(admin, role="monitor", name="nightlatch")
        with _svc(app, created["api_key"]) as svc:
            assert svc.get("/v1/audit").status_code == 200
            r = svc.delete(f"/v1/agents/{agent_id}")  # agents:revoke:all crosses ownership
            assert r.status_code == 200, r.text
            assert r.json()["active"] is False

        events = admin.get("/v1/audit").json()
        assert any(e["actor"] == "svc:nightlatch" for e in events), \
            "revoke must be attributed to the service key label"


def test_last_used_tracked(app):
    with _admin(app) as admin:
        created = _make_key(admin, name="used")
        assert created["last_used_at"] is None
        with _svc(app, created["api_key"]) as svc:
            svc.get("/v1/audit")
        rec = next(k for k in admin.get("/v1/service-keys").json() if k["name"] == "used")
        assert rec["last_used_at"] is not None


def test_validation_and_role_delete_guard(app):
    with _admin(app) as admin:
        _make_key(admin, name="dup")
        assert admin.post("/v1/service-keys",
                          json={"name": "dup", "role": "auditor"}).status_code == 409
        assert admin.post("/v1/service-keys",
                          json={"name": "y", "role": "ghost"}).status_code == 422

        admin.post("/v1/roles", json={"name": "temp", "permissions": ["audit:read:all"]})
        _make_key(admin, role="temp", name="usestemp")
        rid = next(r for r in admin.get("/v1/roles").json() if r["name"] == "temp")["id"]
        # a role a service key carries can't be deleted out from under it
        assert admin.delete(f"/v1/roles/{rid}").status_code == 409


def test_manage_permission_required(app):
    """A service key without service_keys:manage can't mint or revoke keys —
    minting is a privilege-granting act."""
    with _admin(app) as admin:
        # auditor has service_keys:read but not :manage
        reader = _make_key(admin, role="auditor", name="reader")
        with _svc(app, reader["api_key"]) as svc:
            assert svc.get("/v1/service-keys").status_code == 200
            assert svc.post("/v1/service-keys",
                            json={"name": "sneaky", "role": "broker-admin"}).status_code == 403
