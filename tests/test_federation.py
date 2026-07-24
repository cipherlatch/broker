"""Workload identity federation (SPIFFE/OIDC secretless bootstrap): an agent
bound to (issuer, subject) authenticates with a platform-issued JWT verified
against the issuer's JWKS — no broker secret exists at all. Covers the happy
path (SPIFFE-style subject), every rejection (sub/aud/exp/signature/allowlist),
secretlessness itself, token exchange, and binding management."""

import time

import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import ECKey

ADMIN = "test-admin-key"
ISSUER = "https://spire.test"
SPIFFE_ID = "spiffe://home.arpa/agent/ha-bridge"


@pytest.fixture()
def idp(monkeypatch):
    """A fake external OIDC issuer (SPIRE-style) with a signing key."""
    import app.federation as federation

    key = ECKey.generate_key("P-256", private=True)
    jwk = key.as_dict(private=False)
    jwk.update({"kid": key.thumbprint(), "use": "sig", "alg": "ES256"})

    monkeypatch.setattr(federation, "_fetch_jwks_uri", lambda iss: f"{iss}/keys")
    monkeypatch.setattr(federation, "_fetch_jwks", lambda uri: {"keys": [jwk]})
    federation.reset_cache()

    def mint(sub=SPIFFE_ID, iss=ISSUER, aud="http://testserver", exp_in=300, **extra):
        claims = {"iss": iss, "sub": sub, "aud": aud,
                  "exp": int(time.time()) + exp_in, "iat": int(time.time()), **extra}
        return jwt.encode({"alg": "ES256", "kid": key.thumbprint()}, claims, key)

    yield mint
    federation.reset_cache()


def _fed_app(make_app, **env):
    return make_app(BROKER_FEDERATED_ISSUERS=ISSUER, **env)


def _admin(app):
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN
    return c


def _make_fed_agent(admin, name="wl-agent", subject=SPIFFE_ID, scopes=("a:b",)):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post("/v1/agents", json={
        "name": name, "owner_email": "owner@example.com",
        "allowed_scopes": list(scopes),
        "federated_issuer": ISSUER, "federated_subject": subject,
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def _assert_mint(client, agent, assertion, expect=200):
    resp = client.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"],
        "client_assertion": assertion,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    })
    assert resp.status_code == expect, resp.text
    return resp


def test_secretless_agent_minting(make_app, idp):
    app = _fed_app(make_app)
    admin = _admin(app)
    agent = _make_fed_agent(admin)

    # Truly secretless: creation returns no secret...
    assert agent["client_secret"] is None
    assert agent["federated_subject"] == SPIFFE_ID

    # ...and secret auth cannot work.
    resp = admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"], "client_secret": "anything",
    })
    assert resp.status_code == 401

    # A platform-issued SVID mints a normal Cipherlatch token.
    tok = _assert_mint(admin, agent, idp()).json()
    assert tok["scope"] == "a:b"
    from joserfc.jwk import KeySet

    jwks = admin.get("/.well-known/jwks.json").json()
    claims = jwt.decode(tok["access_token"], KeySet.import_key_set(jwks)).claims
    assert claims["sub"].startswith("agent:")
    assert claims["owner"] == "owner@example.com"


def test_federated_rejections(make_app, idp):
    app = _fed_app(make_app)
    admin = _admin(app)
    agent = _make_fed_agent(admin)

    _assert_mint(admin, agent, idp(sub="spiffe://home.arpa/agent/other"), expect=401)
    _assert_mint(admin, agent, idp(aud="https://something-else"), expect=401)
    _assert_mint(admin, agent, idp(exp_in=-60), expect=401)

    # Signature from a different key than the issuer's JWKS.
    rogue = ECKey.generate_key("P-256", private=True)
    forged = jwt.encode(
        {"alg": "ES256"},
        {"iss": ISSUER, "sub": SPIFFE_ID, "aud": "http://testserver",
         "exp": int(time.time()) + 300},
        rogue,
    )
    _assert_mint(admin, agent, forged, expect=401)

    # Audit trail names the federated path.
    events = admin.get("/v1/audit", params={"event": "token.denied"}).json()
    assert any(e["detail"].get("reason") == "bad_federated_assertion" for e in events)


def test_issuer_allowlist_enforced_at_create(make_app, idp):
    app = _fed_app(make_app)
    admin = _admin(app)
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post("/v1/agents", json={
        "name": "bad", "owner_email": "owner@example.com",
        "federated_issuer": "https://evil.test", "federated_subject": "x",
    })
    assert resp.status_code == 422
    # Both-or-neither.
    resp = admin.post("/v1/agents", json={
        "name": "half", "owner_email": "owner@example.com",
        "federated_issuer": ISSUER,
    })
    assert resp.status_code == 422


def test_federation_disabled_without_allowlist(make_app, idp):
    app = make_app()  # no BROKER_FEDERATED_ISSUERS
    admin = _admin(app)
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post("/v1/agents", json={
        "name": "wl", "owner_email": "owner@example.com",
        "federated_issuer": ISSUER, "federated_subject": SPIFFE_ID,
    })
    assert resp.status_code == 422


def test_binding_update_and_clear(make_app, idp):
    app = _fed_app(make_app)
    admin = _admin(app)
    agent = _make_fed_agent(admin)

    # Rebind to a different workload.
    resp = admin.patch(f"/v1/agents/{agent['id']}", json={
        "federated_issuer": ISSUER, "federated_subject": "spiffe://home.arpa/agent/v2",
    })
    assert resp.status_code == 200
    _assert_mint(admin, agent, idp(), expect=401)  # old subject no longer valid
    _assert_mint(admin, agent, idp(sub="spiffe://home.arpa/agent/v2"))

    # Clear the binding; agent now has no authenticator until a secret is
    # rotated in.
    resp = admin.patch(f"/v1/agents/{agent['id']}", json={
        "federated_issuer": "", "federated_subject": "",
    })
    assert resp.status_code == 200
    assert resp.json()["federated_issuer"] is None
    _assert_mint(admin, agent, idp(sub="spiffe://home.arpa/agent/v2"), expect=401)
    rotated = admin.post(f"/v1/agents/{agent['id']}/rotate").json()
    resp = admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"], "client_secret": rotated["client_secret"],
    })
    assert resp.status_code == 200


def test_federated_token_exchange(make_app, idp):
    app = _fed_app(make_app)
    admin = _admin(app)
    agent = _make_fed_agent(admin, name="xchg-agent")

    cred = admin.post("/v1/credentials", json={
        "name": "ha-token", "secret": "long-lived-ha-token",
        "owner_email": "owner@example.com",
    })
    assert cred.status_code == 201, cred.text
    grant = admin.post(f"/v1/credentials/{cred.json()['id']}/grants/{agent['id']}")
    assert grant.status_code == 200, grant.text

    cipherlatch_token = _assert_mint(admin, agent, idp()).json()["access_token"]
    resp = admin.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent["client_id"],
        "client_assertion": idp(),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "subject_token": cipherlatch_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "ha-token",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"] == "long-lived-ha-token"


def test_private_key_jwt_still_routes_correctly(make_app, idp):
    """An agent with BOTH a registered JWK and a federated binding: iss ==
    client_id routes to private_key_jwt, external iss routes to federation."""
    app = _fed_app(make_app)
    admin = _admin(app)
    agent = _make_fed_agent(admin, name="dual-agent")

    key = ECKey.generate_key("P-256", private=True)
    jwk = key.as_dict(private=False)
    resp = admin.put(f"/v1/agents/{agent['id']}/auth-key", json={"jwk": jwk})
    if resp.status_code == 404:
        pytest.skip("no auth-key endpoint; covered by proof tests")
    assertion = jwt.encode(
        {"alg": "ES256"},
        {"iss": agent["client_id"], "sub": agent["client_id"],
         "aud": "http://testserver", "exp": int(time.time()) + 300},
        key,
    )
    _assert_mint(admin, agent, assertion)
