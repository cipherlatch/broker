from joserfc import jwt
from joserfc.jwk import KeySet


def _create_agent(admin, scopes):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post(
        "/v1/agents",
        json={"name": "worker", "owner_email": "owner@example.com", "allowed_scopes": scopes},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _token(client, agent, scope=None):
    data = {
        "grant_type": "client_credentials",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    }
    if scope is not None:
        data["scope"] = scope
    return client.post("/oauth/token", data=data)


def test_mint_and_verify_against_jwks(admin):
    agent = _create_agent(admin, ["ha:read", "gitlab:api"])
    resp = _token(admin, agent, scope="ha:read")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert 0 < body["expires_in"] <= 900

    # Verify offline the way a downstream service would: JWKS only.
    jwks = admin.get("/.well-known/jwks.json").json()
    key_set = KeySet.import_key_set(jwks)
    claims = jwt.decode(body["access_token"], key_set).claims
    jwt.JWTClaimsRegistry(exp={"essential": True}).validate(claims)
    assert claims["sub"] == f"agent:{agent['id']}"
    assert claims["owner"] == "owner@example.com"
    assert claims["scope"] == "ha:read"
    assert claims["iss"] == "http://testserver"


def test_default_scope_is_full_grant(admin):
    agent = _create_agent(admin, ["b:scope", "a:scope"])
    body = _token(admin, agent).json()
    assert body["scope"] == "a:scope b:scope"


def test_scope_escalation_rejected(admin):
    agent = _create_agent(admin, ["ha:read"])
    resp = _token(admin, agent, scope="ha:read admin:everything")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_bad_secret_rejected(admin):
    agent = _create_agent(admin, ["ha:read"])
    agent["client_secret"] = "aibs_wrong"
    assert _token(admin, agent).status_code == 401


def test_unknown_client_same_error_as_bad_secret(admin):
    agent = _create_agent(admin, ["ha:read"])
    bad_secret = _token(admin, {**agent, "client_secret": "aibs_wrong"})
    unknown = _token(admin, {"client_id": "aib_nonexistent", "client_secret": "aibs_wrong"})
    assert unknown.status_code == bad_secret.status_code == 401
    assert unknown.json() == bad_secret.json()


def test_revoked_agent_rejected(admin):
    agent = _create_agent(admin, ["ha:read"])
    admin.delete(f"/v1/agents/{agent['id']}")
    resp = _token(admin, agent)
    assert resp.status_code == 401
    denials = admin.get("/v1/audit", params={"event": "token.denied"}).json()
    assert any(d["detail"].get("reason") == "revoked" for d in denials)
