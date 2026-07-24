"""Token-endpoint throttling (NIST 800-63B) and RFC 8707 resource binding."""

from joserfc import jwt
from joserfc.jwk import KeySet


def _create(admin, name="worker", scopes=None, resources=None):
    resp = admin.post(
        "/v1/agents",
        json={
            "name": name,
            "owner_email": "owner@example.com",
            "allowed_scopes": scopes or ["s:read"],
            "allowed_resources": resources or [],
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _token(client, agent, secret=None, **extra):
    data = {
        "grant_type": "client_credentials",
        "client_id": agent["client_id"],
        "client_secret": secret or agent["client_secret"],
    }
    data.update(extra)
    return client.post("/oauth/token", data=data)


def _ensure_owner(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})


def test_lockout_after_repeated_failures(admin):
    _ensure_owner(admin)
    agent = _create(admin)

    # Threshold is 3 in tests.
    for _ in range(3):
        assert _token(admin, agent, secret="aibs_wrong").status_code == 401

    # Correct secret is now refused while locked.
    locked = _token(admin, agent)
    assert locked.status_code == 401
    assert "locked" in locked.json()["error_description"].lower()

    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert "token.locked" in events


def test_success_resets_failure_counter(admin):
    _ensure_owner(admin)
    agent = _create(admin, name="resetter")

    for _ in range(2):
        _token(admin, agent, secret="aibs_wrong")
    assert _token(admin, agent).status_code == 200  # success clears the count
    for _ in range(2):
        _token(admin, agent, secret="aibs_wrong")
    assert _token(admin, agent).status_code == 200  # still not locked


def test_rotate_clears_lockout(admin):
    _ensure_owner(admin)
    agent = _create(admin, name="locked-then-rotated")
    for _ in range(3):
        _token(admin, agent, secret="aibs_wrong")
    assert _token(admin, agent).status_code == 401  # locked

    rotated = admin.post(f"/v1/agents/{agent['id']}/rotate").json()
    assert _token(admin, agent, secret=rotated["client_secret"]).status_code == 200


def test_resource_binds_audience(admin):
    _ensure_owner(admin)
    agent = _create(admin, name="mcp-client")
    resp = _token(admin, agent, resource="https://mcp.example.com/server")
    assert resp.status_code == 200, resp.text

    jwks = admin.get("/.well-known/jwks.json").json()
    claims = jwt.decode(resp.json()["access_token"], KeySet.import_key_set(jwks)).claims
    assert claims["aud"] == "https://mcp.example.com/server"

    # Without resource, the default audience applies.
    resp = _token(admin, agent)
    claims = jwt.decode(resp.json()["access_token"], KeySet.import_key_set(jwks)).claims
    assert claims["aud"] == "agent-iam"


def test_resource_allowlist_enforced(admin):
    _ensure_owner(admin)
    agent = _create(
        admin, name="restricted", resources=["https://allowed.example.com"]
    )
    ok = _token(admin, agent, resource="https://allowed.example.com")
    assert ok.status_code == 200
    denied = _token(admin, agent, resource="https://other.example.com")
    assert denied.status_code == 400
    assert denied.json()["error"] == "invalid_target"


def test_malformed_resource_rejected(admin):
    _ensure_owner(admin)
    agent = _create(admin, name="malformed")
    resp = _token(admin, agent, resource="not-a-uri")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_target"


def test_agent_patch_updates_scopes_and_audits(admin):
    _ensure_owner(admin)
    agent = _create(admin, name="patchable", scopes=["a:read"])
    resp = admin.patch(
        f"/v1/agents/{agent['id']}",
        json={"allowed_scopes": ["a:read", "b:write"], "description": "updated"},
    )
    assert resp.status_code == 200
    assert resp.json()["allowed_scopes"] == ["a:read", "b:write"]

    events = admin.get("/v1/audit", params={"event": "agent.updated"}).json()
    assert any("allowed_scopes" in e["detail"].get("changes", {}) for e in events)
