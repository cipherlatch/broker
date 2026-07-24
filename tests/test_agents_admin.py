"""Machine-admin (X-Admin-Key) surface: agent lifecycle via the JSON API."""


def _ensure_owner(admin, email="owner@example.com"):
    admin.post("/v1/users", json={"email": email})


def _create(admin, name="ha-bridge", scopes=None):
    _ensure_owner(admin)
    resp = admin.post(
        "/v1/agents",
        json={
            "name": name,
            "owner_email": "owner@example.com",
            "allowed_scopes": scopes or ["ha:read"],
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_admin_requires_key(client):
    assert client.get("/v1/agents").status_code == 401
    client.headers["X-Admin-Key"] = "wrong"
    assert client.get("/v1/agents").status_code == 401


def test_non_ascii_admin_key_is_401_not_500(client):
    resp = client.get("/v1/agents", headers={b"X-Admin-Key": "kläff".encode("latin-1")})
    assert resp.status_code == 401


def test_admin_key_create_requires_known_owner(admin):
    resp = admin.post(
        "/v1/agents",
        json={"name": "orphan", "owner_email": "ghost@example.com"},
    )
    assert resp.status_code == 422


def test_create_returns_secret_once(admin):
    created = _create(admin)
    assert created["client_id"].startswith("aib_")
    assert created["client_secret"].startswith("aibs_")
    assert created["owner_email"] == "owner@example.com"
    listed = admin.get("/v1/agents").json()
    assert len(listed) == 1
    assert "client_secret" not in listed[0]


def test_duplicate_name_conflicts(admin):
    _create(admin)
    resp = admin.post(
        "/v1/agents",
        json={"name": "ha-bridge", "owner_email": "owner@example.com"},
    )
    assert resp.status_code == 409


def test_rotate_invalidates_old_secret(admin):
    created = _create(admin)
    rotated = admin.post(f"/v1/agents/{created['id']}/rotate").json()
    assert rotated["client_secret"] != created["client_secret"]

    old = admin.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": created["client_id"],
            "client_secret": created["client_secret"],
        },
    )
    assert old.status_code == 401

    new = admin.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": created["client_id"],
            "client_secret": rotated["client_secret"],
        },
    )
    assert new.status_code == 200


def test_audit_trail_with_actor(admin):
    created = _create(admin)
    admin.delete(f"/v1/agents/{created['id']}")
    events = admin.get("/v1/audit").json()
    kinds = {e["event"] for e in events}
    assert {"agent.created", "agent.revoked", "user.created"} <= kinds
    lifecycle = [e for e in events if e["event"].startswith("agent.")]
    assert all(e["actor"] == "admin-key" for e in lifecycle)
