"""MCP authorization-server role: authorization_code + PKCE, CIMD client
registration, registered resources, consent, and RFC 9207 iss."""

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.testing import ADMIN_KEY

CLIENT_URL = "https://mcp-client.test/oauth-client.json"
CALLBACK = "http://127.0.0.1:33418/callback"
CLIENT_DOC = {
    "client_id": CLIENT_URL,
    "client_name": "Test MCP Client",
    "redirect_uris": [CALLBACK],
}
RESOURCE = "https://mcp.example.test/mcp"

VERIFIER = "test-verifier-string-that-is-long-enough-for-pkce"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .rstrip(b"=").decode()
)

FAKE_DISCOVERY = {
    "authorization_endpoint": "https://idp.test/authorize",
    "token_endpoint": "https://idp.test/token",
    "jwks_uri": "https://idp.test/jwks",
}


@pytest.fixture()
def mcp_app(make_app, monkeypatch):
    app = make_app(BROKER_MCP_AS_ENABLED="true")
    import app.cimd as cimd_module

    monkeypatch.setattr(cimd_module, "fetch_document", lambda url: dict(CLIENT_DOC))
    return app


@pytest.fixture()
def mcp_client(mcp_app):
    with TestClient(mcp_app) as c:
        yield c


@pytest.fixture()
def mcp_admin(mcp_client):
    mcp_client.headers["X-Admin-Key"] = ADMIN_KEY
    return mcp_client


def _register_resource(admin, uri=RESOURCE, scopes=None):
    resp = admin.post("/v1/mcp/resources", json={
        "resource_uri": uri, "name": "Test MCP server",
        "allowed_scopes": scopes if scopes is not None else ["files:read", "files:write"],
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def _login(app, monkeypatch, email="user@example.com"):
    """Session client via the stubbed OIDC seams (same shape as conftest's
    login fixture, but bound to the MCP-enabled app)."""
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)

    c = TestClient(app)
    resp = c.get("/auth/login", follow_redirects=False)
    assert resp.status_code == 302
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    resp = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    assert resp.status_code == 302, resp.text
    return c


def _authorize_params(**overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_URL,
        "redirect_uri": CALLBACK,
        "scope": "files:read",
        "state": "st-123",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    params.update(overrides)
    return params


def _approve(session_client, **overrides):
    """Run authorize → consent → approve; returns the parsed callback query."""
    resp = session_client.get("/oauth/authorize", params=_authorize_params(**overrides),
                              follow_redirects=False)
    assert resp.status_code == 200, resp.text  # consent page
    resp = session_client.post("/oauth/authorize/decision", data={"action": "approve"},
                               follow_redirects=False)
    assert resp.status_code == 302, resp.text
    target = urlparse(resp.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == CALLBACK
    return parse_qs(target.query)


def _redeem(client, code, verifier=VERIFIER, redirect_uri=CALLBACK, client_id=CLIENT_URL):
    return client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    })


# ---------- metadata / gating ----------

def test_metadata_absent_when_disabled(client):
    doc = client.get("/.well-known/oauth-authorization-server").json()
    assert "authorization_endpoint" not in doc
    assert "authorization_code" not in doc["grant_types_supported"]


def test_authorize_404_when_disabled(client):
    assert client.get("/oauth/authorize", params=_authorize_params()).status_code == 404


def test_metadata_advertises_mcp_as(mcp_client):
    doc = mcp_client.get("/.well-known/oauth-authorization-server").json()
    assert doc["authorization_endpoint"] == "http://testserver/oauth/authorize"
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert "authorization_code" in doc["grant_types_supported"]
    assert doc["authorization_response_iss_parameter_supported"] is True
    assert doc["client_id_metadata_document_supported"] is True


# ---------- the happy path ----------

def test_full_flow(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)

    query = _approve(user)
    assert query["state"] == ["st-123"]
    assert query["iss"] == ["http://testserver"]  # RFC 9207

    resp = _redeem(mcp_admin, query["code"][0])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "files:read"

    # The minted token introspects as an active user-delegated token.
    mcp_admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = mcp_admin.post("/v1/agents", json={
        "name": "introspector", "owner_email": "owner@example.com",
        "allowed_scopes": ["s:read"],
    }).json()
    intro = mcp_admin.post("/oauth/introspect", data={
        "token": body["access_token"],
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    }).json()
    assert intro["active"] is True
    assert intro["sub"].startswith("user:")
    assert intro["client_id"] == CLIENT_URL
    assert intro["aud"] == RESOURCE


def test_standing_consent_skips_screen(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    _approve(user)

    # Second authorize: no consent page, straight to the callback with a code.
    resp = user.get("/oauth/authorize", params=_authorize_params(state="st-2"),
                    follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert "code" in query and query["state"] == ["st-2"]


def test_login_roundtrip_returns_to_authorize(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    import app.oidc as oidc_module

    claims = {"sub": "sub-rt", "email": "rt@example.com", "email_verified": True}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)

    c = TestClient(mcp_app)
    # Anonymous authorize parks the request and bounces to SSO...
    resp = c.get("/oauth/authorize", params=_authorize_params(), follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"
    # ...and the SSO callback returns to the authorize URL, not the UI.
    resp = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    resp = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/oauth/authorize?")


# ---------- protocol hardening ----------

def test_pkce_wrong_verifier_rejected(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    query = _approve(user)
    resp = _redeem(mcp_admin, query["code"][0], verifier="wrong-verifier-value")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_code_single_use_and_replay_revokes_token(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    query = _approve(user)

    first = _redeem(mcp_admin, query["code"][0])
    assert first.status_code == 200
    token = first.json()["access_token"]

    replay = _redeem(mcp_admin, query["code"][0])
    assert replay.status_code == 400

    # The replay burned the originally issued token (OAuth 2.1 §4.1.2).
    mcp_admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = mcp_admin.post("/v1/agents", json={
        "name": "replay-check", "owner_email": "owner@example.com",
        "allowed_scopes": ["s:read"],
    }).json()
    intro = mcp_admin.post("/oauth/introspect", data={
        "token": token,
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    }).json()
    assert intro["active"] is False


def test_unregistered_redirect_uri_never_redirects(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize", params=_authorize_params(
        redirect_uri="https://evil.test/steal"), follow_redirects=False)
    assert resp.status_code == 400  # error page, not a redirect

def test_loopback_redirect_port_may_vary(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    moved = "http://127.0.0.1:54321/callback"  # same host+path, other port
    resp = user.get("/oauth/authorize",
                    params=_authorize_params(redirect_uri=moved),
                    follow_redirects=False)
    assert resp.status_code == 200  # accepted: consent page renders
    resp = user.post("/oauth/authorize/decision", data={"action": "approve"},
                     follow_redirects=False)
    assert resp.headers["location"].startswith(moved)


def test_pkce_required(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize",
                    params=_authorize_params(code_challenge=""),
                    follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["invalid_request"]
    assert query["iss"] == ["http://testserver"]


def test_unregistered_resource_rejected(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)  # registers RESOURCE, not the one below
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize",
                    params=_authorize_params(resource="https://other.test/mcp"),
                    follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["invalid_target"]


def test_scope_excess_rejected(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin, scopes=["files:read"])
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize",
                    params=_authorize_params(scope="files:read admin:everything"),
                    follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["invalid_scope"]


def test_deny_redirects_access_denied(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize", params=_authorize_params(), follow_redirects=False)
    assert resp.status_code == 200
    resp = user.post("/oauth/authorize/decision", data={"action": "deny"},
                     follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["iss"] == ["http://testserver"]


# ---------- CIMD validation ----------

def test_cimd_client_id_mismatch_rejected(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    import app.cimd as cimd_module

    bad = dict(CLIENT_DOC, client_id="https://elsewhere.test/other.json")
    monkeypatch.setattr(cimd_module, "fetch_document", lambda url: bad)
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize", params=_authorize_params(), follow_redirects=False)
    assert resp.status_code == 400  # error page: client can't be verified


def test_cimd_requires_https_client_id(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    resp = user.get("/oauth/authorize",
                    params=_authorize_params(client_id="http://mcp-client.test/id.json"),
                    follow_redirects=False)
    assert resp.status_code == 400


def test_cimd_private_address_blocked():
    from app.cimd import CIMDError, _addresses_public

    # Loopback resolves locally everywhere; must be flagged non-public.
    assert _addresses_public("localhost") is False
    with pytest.raises(CIMDError):
        _addresses_public("definitely-not-a-real-host.invalid")


# ---------- revocation levers ----------

def test_revoked_client_refused(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    _approve(user)

    clients = mcp_admin.get("/v1/mcp/clients").json()
    assert len(clients) == 1
    mcp_admin.post(f"/v1/mcp/clients/{clients[0]['id']}/revoke")

    resp = user.get("/oauth/authorize", params=_authorize_params(), follow_redirects=False)
    assert resp.status_code == 400  # error page: revoked client, no redirect


def test_consent_revocation_kills_outstanding_tokens(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    query = _approve(user)
    token = _redeem(mcp_admin, query["code"][0]).json()["access_token"]

    consents = mcp_admin.get("/v1/mcp/consents", params={"all": "true"}).json()
    assert len(consents) == 1
    mcp_admin.post(f"/v1/mcp/consents/{consents[0]['id']}/revoke")

    mcp_admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = mcp_admin.post("/v1/agents", json={
        "name": "revoke-check", "owner_email": "owner@example.com",
        "allowed_scopes": ["s:read"],
    }).json()
    intro = mcp_admin.post("/oauth/introspect", data={
        "token": token,
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    }).json()
    assert intro["active"] is False


def test_user_can_revoke_own_consent(mcp_app, mcp_admin, monkeypatch):
    _register_resource(mcp_admin)
    user = _login(mcp_app, monkeypatch)
    _approve(user)

    mine = user.get("/v1/mcp/consents").json()
    assert len(mine) == 1
    assert user.post(f"/v1/mcp/consents/{mine[0]['id']}/revoke").status_code == 200

    # Next authorize asks again (standing consent is gone).
    resp = user.get("/oauth/authorize", params=_authorize_params(), follow_redirects=False)
    assert resp.status_code == 200  # consent page again


# ---------- management API ----------

def test_resources_crud_and_permissions(mcp_app, mcp_admin, monkeypatch):
    row = _register_resource(mcp_admin)
    assert mcp_admin.get("/v1/mcp/resources").json()[0]["resource_uri"] == RESOURCE

    resp = mcp_admin.patch(f"/v1/mcp/resources/{row['id']}", json={"active": False})
    assert resp.json()["active"] is False

    # A plain user (agent-manager) has no mcp:* permission: surfaces hide as 404.
    user = _login(mcp_app, monkeypatch)
    assert user.get("/v1/mcp/resources").status_code == 404
    assert user.get("/v1/mcp/clients").status_code == 404

    assert mcp_admin.delete(f"/v1/mcp/resources/{row['id']}").json() == {"deleted": True}
    assert mcp_admin.get("/v1/mcp/resources").json() == []


def test_duplicate_resource_conflicts(mcp_admin):
    _register_resource(mcp_admin)
    resp = mcp_admin.post("/v1/mcp/resources", json={
        "resource_uri": RESOURCE, "name": "dupe",
    })
    assert resp.status_code == 409
