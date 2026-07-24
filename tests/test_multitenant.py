"""Tenant isolation: two tenants cannot see, read, or mutate each other's
data — even a tenant broker-admin is confined to its own tenant. Only the
machine admin key (platform admin) manages the tenant plane."""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY

ADMIN = "test-admin-key"
DOMAINS = "acme.com=acme,beta.com=beta"


def _app(make_app, **extra):
    return make_app(BROKER_TENANT_DOMAIN_MAP=DOMAINS, **extra)


def _boot(app):
    with TestClient(app):  # run lifespan -> create schema
        pass


def _login(app, monkeypatch, email, groups=("cipherlatch-admins",)):
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True,
              "name": "", "groups": list(groups)}
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


def _admin(app, tenant_slug):
    _boot(app)
    c = TestClient(app)
    c.headers["X-Admin-Key"] = ADMIN
    if tenant_slug:
        c.headers["X-Tenant"] = tenant_slug
    return c


def test_domain_routes_users_to_tenants(make_app, monkeypatch):
    app = _app(make_app, BROKER_GROUP_ROLE_MAP="cipherlatch-admins=broker-admin")
    alice = _login(app, monkeypatch, "alice@acme.com")
    bob = _login(app, monkeypatch, "bob@beta.com")
    assert {u["email"] for u in alice.get("/v1/users").json()} == {"alice@acme.com"}
    assert {u["email"] for u in bob.get("/v1/users").json()} == {"bob@beta.com"}


def test_agents_isolated_across_tenants(make_app):
    app = _app(make_app)
    acme = _admin(app, "acme")
    beta = _admin(app, "beta")
    acme.post("/v1/users", json={"email": "u@acme.com"})
    beta.post("/v1/users", json={"email": "u@beta.com"})
    a = acme.post("/v1/agents", json={"name": "acme-agent", "owner_email": "u@acme.com"}).json()
    b = beta.post("/v1/agents", json={"name": "beta-agent", "owner_email": "u@beta.com"}).json()

    assert {x["name"] for x in acme.get("/v1/agents").json()} == {"acme-agent"}
    assert {x["name"] for x in beta.get("/v1/agents").json()} == {"beta-agent"}

    # Cross-tenant fetch/mutate is 404 (existence hidden), not 403.
    assert beta.get(f"/v1/agents/{a['id']}").status_code == 404
    assert beta.patch(f"/v1/agents/{a['id']}", json={"description": "x"}).status_code == 404
    assert beta.delete(f"/v1/agents/{a['id']}").status_code == 404
    assert acme.get(f"/v1/agents/{b['id']}").status_code == 404

    # Same agent name is fine in different tenants.
    assert acme.post(
        "/v1/agents", json={"name": "beta-agent", "owner_email": "u@acme.com"}
    ).status_code == 201


def test_tenant_admin_cannot_cross_even_with_read_all(make_app, monkeypatch):
    app = _app(make_app, BROKER_GROUP_ROLE_MAP="cipherlatch-admins=broker-admin")
    alice = _login(app, monkeypatch, "alice@acme.com")  # acme broker-admin
    beta = _admin(app, "beta")
    beta.post("/v1/users", json={"email": "u@beta.com"})
    b = beta.post("/v1/agents", json={"name": "beta-secret", "owner_email": "u@beta.com"}).json()

    assert all(x["name"] != "beta-secret" for x in alice.get("/v1/agents").json())
    assert alice.get(f"/v1/agents/{b['id']}").status_code == 404


def test_credentials_and_routes_isolated(make_app):
    app = _app(make_app)
    acme = _admin(app, "acme")
    beta = _admin(app, "beta")
    acme.post("/v1/users", json={"email": "u@acme.com"})
    cred = acme.post(
        "/v1/credentials", json={"name": "acme-cred", "secret": "s", "owner_email": "u@acme.com"}
    ).json()
    acme.post(
        "/v1/routes",
        json={"slug": "acme-route", "upstream_base": "http://up.test",
              "credential_name": "acme-cred", "owner_email": "u@acme.com"},
    )
    assert beta.get("/v1/credentials").json() == []
    assert beta.get("/v1/routes").json() == []
    assert beta.get(f"/v1/credentials/{cred['id']}").status_code == 404


def test_tokens_carry_tenant_and_agents_isolated(make_app):
    app = _app(make_app)
    acme = _admin(app, "acme")
    beta = _admin(app, "beta")
    acme.post("/v1/users", json={"email": "u@acme.com"})
    ag = acme.post(
        "/v1/agents", json={"name": "a", "owner_email": "u@acme.com", "allowed_scopes": ["x"]}
    ).json()
    tok = acme.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": ag["client_id"],
              "client_secret": ag["client_secret"]},
    ).json()

    from joserfc import jwt
    from joserfc.jwk import KeySet

    jwks = acme.get("/.well-known/jwks.json").json()
    claims = jwt.decode(tok["access_token"], KeySet.import_key_set(jwks)).claims
    assert claims["tenant"] == "acme"
    assert beta.get(f"/v1/agents/{ag['id']}").status_code == 404


def test_tenant_crud_is_platform_admin_only(make_app, monkeypatch):
    app = _app(make_app, BROKER_GROUP_ROLE_MAP="cipherlatch-admins=broker-admin")
    # Create tenants by domain-routed admin activity.
    _admin(app, "acme").post("/v1/users", json={"email": "u@acme.com"})
    _admin(app, "beta").post("/v1/users", json={"email": "u@beta.com"})

    platform = _admin(app, None)
    listed = {t["slug"] for t in platform.get("/v1/tenants").json()}
    assert {"acme", "beta"} <= listed
    assert platform.post("/v1/tenants", json={"slug": "gamma", "name": "Gamma"}).status_code == 201

    alice = _login(app, monkeypatch, "alice@acme.com")
    assert alice.get("/v1/tenants").status_code == 403
    assert alice.post("/v1/tenants", json={"slug": "evil", "name": "x"}).status_code == 403


def test_default_tenant_cannot_be_deleted(make_app):
    app = _app(make_app)
    assert _admin(app, None).delete("/v1/tenants/default").status_code == 409


def test_tenant_admins_see_only_their_audit(make_app, monkeypatch):
    app = _app(make_app, BROKER_GROUP_ROLE_MAP="cipherlatch-admins=broker-admin")
    alice = _login(app, monkeypatch, "alice@acme.com")
    bob = _login(app, monkeypatch, "bob@beta.com")
    _admin(app, "acme").post("/v1/users", json={"email": "carol@acme.com"})

    beta_actors = {(e["actor"] or "") for e in bob.get("/v1/audit").json()}
    assert not any("acme" in a for a in beta_actors)
    acme_actors = {(e["actor"] or "") for e in alice.get("/v1/audit").json()}
    assert any("acme" in a for a in acme_actors)
