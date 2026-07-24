"""Per-tenant keyrings: the same agent-facing ring name in two tenants is two
independent signing keys; rotating one never touches the other. The `default`
ring stays shared platform infrastructure, so only the platform admin (machine
key) may rotate it — a tenant broker-admin cannot rotate a key other tenants'
agents sign with."""

from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet

ADMIN = "test-admin-key"


def _boot(app):
    with TestClient(app):  # run lifespan -> create schema
        pass


def _tenant_admin(app, tenant_slug):
    c = TestClient(app)
    c.headers["X-Admin-Key"] = ADMIN
    c.headers["X-Tenant"] = tenant_slug
    return c


def _make_agent(client, name, keyring):
    client.post("/v1/users", json={"email": f"owner-{name}@example.com"})
    resp = client.post(
        "/v1/agents",
        json={
            "name": name,
            "owner_email": f"owner-{name}@example.com",
            "allowed_scopes": ["a:b"],
            "keyring": keyring,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _mint(client, agent):
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _kid(token):
    import base64
    import json

    header = token.split(".")[0]
    header += "=" * (-len(header) % 4)
    return json.loads(base64.urlsafe_b64decode(header))["kid"]


def test_same_ring_name_isolated_across_tenants(app):
    _boot(app)
    acme, beta = _tenant_admin(app, "acme"), _tenant_admin(app, "beta")
    kid_a = _kid(_mint(acme, _make_agent(acme, "a1", "payments")))
    kid_b = _kid(_mint(beta, _make_agent(beta, "b1", "payments")))
    assert kid_a != kid_b  # same name, distinct tenant-scoped keys

    # Platform view shows both storage rings; tokens from both verify via JWKS.
    platform = TestClient(app)
    platform.headers["X-Admin-Key"] = ADMIN
    rings = platform.get("/v1/keys").json()["keyrings"]
    assert {"default", "acme.payments", "beta.payments"} <= set(rings)


def test_rotation_is_confined_to_the_actors_tenant(app):
    _boot(app)
    acme, beta = _tenant_admin(app, "acme"), _tenant_admin(app, "beta")
    agent_a = _make_agent(acme, "a1", "payments")
    agent_b = _make_agent(beta, "b1", "payments")
    kid_b_before = _kid(_mint(beta, agent_b))

    rotated = acme.post("/v1/keys/rotate", params={"keyring": "payments"})
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["keyring"] == "payments"

    # acme's agents now sign with the new kid; beta's kid is untouched.
    assert _kid(_mint(acme, agent_a)) == rotated.json()["active_kid"]
    assert _kid(_mint(beta, agent_b)) == kid_b_before


def test_human_tenant_admin_rotation_scope(make_app, monkeypatch):
    """A human broker-admin (tenant-scoped `*`) sees its own rings by name
    (no cross-tenant leakage) and may rotate them — but never the shared
    default, which needs the platform admin."""
    from urllib.parse import parse_qs, urlparse

    import app.oidc as oidc_module
    from tests.conftest import FAKE_DISCOVERY

    app = make_app(
        BROKER_TENANT_DOMAIN_MAP="acme.com=acme",
        BROKER_GROUP_ROLE_MAP="admins=broker-admin",
    )
    _boot(app)

    claims = {"sub": "sub-alice", "email": "alice@acme.com", "email_verified": True,
              "name": "", "groups": ["admins"]}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)

    # Shared default ring: denied even for a tenant broker-admin.
    denied = c.post("/v1/keys/rotate")
    assert denied.status_code == 403
    assert "platform admin" in denied.json()["detail"].lower()

    # Alice's own agent on a named ring; another tenant has a ring too.
    resp = c.post("/v1/agents", json={"name": "a1", "allowed_scopes": ["a:b"],
                                      "keyring": "payments"})
    assert resp.status_code == 201, resp.text
    beta = _tenant_admin(app, "beta")
    _make_agent(beta, "b1", "billing")

    # Tenant view: own rings by agent-facing name, no beta leakage.
    assert set(c.get("/v1/keys").json()["keyrings"]) == {"default", "payments"}

    # Own tenant's named ring: rotation allowed, lands in the tenant's storage
    # ring, and the response stays in the tenant view.
    rotated = c.post("/v1/keys/rotate", params={"keyring": "payments"})
    assert rotated.status_code == 200, rotated.text
    assert set(rotated.json()["keyrings"]) == {"default", "payments"}

    platform = TestClient(app)
    platform.headers["X-Admin-Key"] = ADMIN
    assert "acme.payments" in platform.get("/v1/keys").json()["keyrings"]


def test_platform_admin_rotates_default_even_with_tenant_header(app):
    _boot(app)
    acme = _tenant_admin(app, "acme")  # machine key is platform admin regardless
    before = acme.get("/v1/keys").json()["keys"][0]["kid"]
    rotated = acme.post("/v1/keys/rotate")
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["active_kid"] != before


def test_jwks_serves_all_tenant_rings_and_tokens_verify(app):
    _boot(app)
    acme, beta = _tenant_admin(app, "acme"), _tenant_admin(app, "beta")
    tok_a = _mint(acme, _make_agent(acme, "a1", "payments"))
    tok_b = _mint(beta, _make_agent(beta, "b1", "payments"))
    tok_d = _mint(acme, _make_agent(acme, "a2", "default"))

    jwks = TestClient(app).get("/.well-known/jwks.json").json()
    key_set = KeySet.import_key_set(jwks)
    for tok in (tok_a, tok_b, tok_d):
        assert jwt.decode(tok, key_set).claims["iss"] == "http://testserver"
