"""Richer gateway policy: per-route/per-agent rate limits and daily quotas
(429, counted only when allowed), and the external OPA-style policy hook
(allow shapes, deny, fail-closed vs fail-open, input document contents)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient


class _Upstream(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        _Upstream.hits += 1
        payload = b'{"upstream":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture()
def upstream():
    _Upstream.hits = 0
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(autouse=True)
def _fresh_counters():
    from app import gateway_limits

    gateway_limits.reset()
    yield
    gateway_limits.reset()


def _bootstrap(admin, upstream_base, **route_extra):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post("/v1/agents", json={
        "name": "gw-agent", "owner_email": "owner@example.com", "allowed_scopes": ["svc:read"],
    }).json()
    admin.post("/v1/credentials", json={
        "name": "svc-cred", "secret": "SECRET-XYZ", "owner_email": "owner@example.com",
    })
    route = admin.post("/v1/routes", json={
        "slug": "svc", "upstream_base": upstream_base, "credential_name": "svc-cred",
        "owner_email": "owner@example.com", "allowed_methods": ["GET"],
        **route_extra,
    })
    assert route.status_code == 201, route.text
    route = route.json()
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    tok = admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    }).json()["access_token"]
    return agent, route, tok


def _call(client, token):
    return client.get("/gw/svc/data", headers={"Authorization": f"Bearer {token}"})


def test_route_rate_limit(admin, upstream):
    _, route, tok = _bootstrap(admin, upstream, rate_limit_per_minute=3)
    assert route["rate_limit_per_minute"] == 3
    for _ in range(3):
        assert _call(admin, tok).status_code == 200
    denied = _call(admin, tok)
    assert denied.status_code == 429
    assert "rate limit" in denied.json()["detail"]
    assert _Upstream.hits == 3  # the denied request never reached the upstream

    events = admin.get("/v1/audit", params={"event": "gateway.denied"}).json()
    assert any(e["detail"].get("reason") == "rate_limited" for e in events)


def test_route_daily_quota(admin, upstream):
    _, _, tok = _bootstrap(admin, upstream, daily_quota=2)
    assert _call(admin, tok).status_code == 200
    assert _call(admin, tok).status_code == 200
    denied = _call(admin, tok)
    assert denied.status_code == 429
    assert "quota" in denied.json()["detail"]

    events = admin.get("/v1/audit", params={"event": "gateway.denied"}).json()
    assert any(e["detail"].get("reason") == "quota_exceeded" for e in events)


def test_limits_are_per_agent(admin, upstream):
    _, route, tok = _bootstrap(admin, upstream, rate_limit_per_minute=1)
    agent2 = admin.post("/v1/agents", json={
        "name": "gw-agent-2", "owner_email": "owner@example.com", "allowed_scopes": [],
    }).json()
    admin.post(f"/v1/routes/{route['id']}/grants/{agent2['id']}")
    tok2 = admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent2["client_id"], "client_secret": agent2["client_secret"],
    }).json()["access_token"]

    assert _call(admin, tok).status_code == 200
    assert _call(admin, tok).status_code == 429  # agent 1 exhausted
    assert _call(admin, tok2).status_code == 200  # agent 2 has its own window


def test_limit_validation_and_update(admin, upstream):
    _, route, _ = _bootstrap(admin, upstream)
    resp = admin.patch(f"/v1/routes/{route['id']}", json={"rate_limit_per_minute": -1})
    assert resp.status_code == 422
    resp = admin.patch(f"/v1/routes/{route['id']}", json={"daily_quota": 500})
    assert resp.status_code == 200
    assert resp.json()["daily_quota"] == 500


def _policy_app(make_app, monkeypatch, decisions: list, fail_open=False, error=False):
    """App with the policy hook pointed at a fake evaluator."""
    import app.policy_hook as hook

    calls: list = []

    def fake_post(url, document, timeout):
        calls.append(document)
        if error:
            raise RuntimeError("policy endpoint down")
        return decisions.pop(0)

    monkeypatch.setattr(hook, "_post", fake_post)
    app = make_app(
        BROKER_GATEWAY_POLICY_URL="http://opa.test/v1/data/cipherlatch/gw",
        **({"BROKER_GATEWAY_POLICY_FAIL_OPEN": "true"} if fail_open else {}),
    )
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = "test-admin-key"
    return c, calls


def test_policy_hook_allow_and_deny_shapes(make_app, monkeypatch, upstream):
    decisions = [
        {"result": True},              # OPA boolean rule
        {"result": {"allow": True}},   # OPA object rule / cedar-agent
        {"result": {"allow": False}},
        {"result": False},
        {},                            # missing result -> deny
    ]
    admin, calls = _policy_app(make_app, monkeypatch, decisions)
    _, _, tok = _bootstrap(admin, upstream)

    assert _call(admin, tok).status_code == 200
    assert _call(admin, tok).status_code == 200
    assert _call(admin, tok).status_code == 403
    assert _call(admin, tok).status_code == 403
    assert _call(admin, tok).status_code == 403

    # The input document carries everything a policy needs.
    doc = calls[0]["input"]
    assert doc["route"]["slug"] == "svc"
    assert doc["request"] == {"method": "GET", "path": "/data"}
    assert doc["agent"]["owner"] == "owner@example.com"
    assert doc["scopes"] == ["svc:read"]
    assert doc["tenant"] == "default"

    events = admin.get("/v1/audit", params={"event": "gateway.denied"}).json()
    assert any(e["detail"].get("reason") == "policy_deny" for e in events)


def test_policy_hook_fails_closed(make_app, monkeypatch, upstream):
    admin, _ = _policy_app(make_app, monkeypatch, [], error=True)
    _, _, tok = _bootstrap(admin, upstream)
    denied = _call(admin, tok)
    assert denied.status_code == 403
    events = admin.get("/v1/audit", params={"event": "gateway.denied"}).json()
    assert any(e["detail"].get("reason") == "policy_unreachable" for e in events)


def test_policy_hook_fail_open_when_configured(make_app, monkeypatch, upstream):
    admin, _ = _policy_app(make_app, monkeypatch, [], fail_open=True, error=True)
    _, _, tok = _bootstrap(admin, upstream)
    assert _call(admin, tok).status_code == 200  # advisory mode


def test_policy_hook_off_by_default(admin, upstream):
    _, _, tok = _bootstrap(admin, upstream)
    assert _call(admin, tok).status_code == 200


def test_inject_credential_header_drops_client_copies():
    from app.gateway_policy import inject_credential_header

    # Client supplied its own copy under different casing; injection must win
    # and leave exactly one instance.
    fwd = {"x-api-key": "ATTACKER", "X-API-KEY": "also-attacker", "accept": "*/*"}
    out = inject_credential_header(fwd, "X-Api-Key", "REAL")
    keys_lower = [k.lower() for k in out]
    assert keys_lower.count("x-api-key") == 1
    assert out["X-Api-Key"] == "REAL"
    assert out["accept"] == "*/*"
