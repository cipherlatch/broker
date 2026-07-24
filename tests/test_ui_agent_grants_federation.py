"""Agent-side management UI: manage an agent's credential (exchange) and route
grants from the agent's own page, and create/edit federated (secretless) agents
through the browser forms. These close the gaps that previously forced grants to
be set only from the credential/route pages and federated agents to be
provisioned via an admin-API curl."""

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY

ISSUER = "https://gitlab.example.com"
SUBJECT = "project_path:briancbunner/demo:ref_type:branch:ref:main"


def _login(app, monkeypatch, email="alice@example.com"):
    """Session-authed client against a *specific* app (the conftest `login`
    fixture is bound to the default app; here we need a federation-enabled one)."""
    import app.oidc as oidc_module

    with TestClient(app):  # run lifespan so the schema exists
        pass
    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    assert r.status_code in (302, 303), r.text
    return c


@pytest.fixture()
def fed_app(make_app):
    return make_app(BROKER_FEDERATED_ISSUERS=ISSUER)


def _create_agent(client, name):
    r = client.post("/ui/agents", data={"name": name}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r.headers["location"].rsplit("/", 1)[1]


# --- federated (secretless) create/edit from the UI ---------------------------


def test_ui_create_federated_agent_is_secretless(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    r = alice.post("/ui/agents", data={
        "name": "ci-deploy", "federated_issuer": ISSUER, "federated_subject": SUBJECT,
    }, follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith("/ui/agents/")

    detail = alice.get(loc).text
    assert "secretless" in detail  # edit-form label or read-only badge
    assert ISSUER in detail

    a = next(a for a in alice.get("/v1/agents").json() if a["name"] == "ci-deploy")
    assert a["federated_issuer"] == ISSUER
    assert a["federated_subject"] == SUBJECT


def test_ui_create_federated_bad_issuer_flashes_and_creates_nothing(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    r = alice.post("/ui/agents", data={
        "name": "bad", "federated_issuer": "https://evil.test", "federated_subject": "x",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/agents"
    assert all(a["name"] != "bad" for a in alice.get("/v1/agents").json())
    assert "Could not create agent" in alice.get("/ui/agents").text


def test_ui_edit_binds_and_clears_federation(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    aid = _create_agent(alice, "editme")

    alice.post(f"/ui/agents/{aid}/update", data={
        "description": "", "scopes": "", "resources": "",
        "federated_issuer": ISSUER, "federated_subject": SUBJECT,
    }, follow_redirects=False)
    a = next(a for a in alice.get("/v1/agents").json() if a["id"] == aid)
    assert a["federated_issuer"] == ISSUER
    assert a["federated_subject"] == SUBJECT

    # Clearing both fields unbinds it.
    alice.post(f"/ui/agents/{aid}/update", data={
        "description": "", "scopes": "", "resources": "",
        "federated_issuer": "", "federated_subject": "",
    }, follow_redirects=False)
    a = next(a for a in alice.get("/v1/agents").json() if a["id"] == aid)
    assert a["federated_issuer"] is None
    assert a["federated_subject"] is None


def test_ui_edit_lone_federated_field_flashes(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    aid = _create_agent(alice, "half")
    r = alice.post(f"/ui/agents/{aid}/update", data={
        "description": "", "scopes": "", "resources": "",
        "federated_issuer": ISSUER, "federated_subject": "",
    }, follow_redirects=False)
    assert r.status_code == 303
    assert "Could not update agent" in alice.get(f"/ui/agents/{aid}").text
    a = next(a for a in alice.get("/v1/agents").json() if a["id"] == aid)
    assert a["federated_issuer"] is None  # unchanged


# --- credential (exchange) grants from the agent page -------------------------


def test_ui_grant_and_revoke_credential_from_agent(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    aid = _create_agent(alice, "worker")
    cred = alice.post("/v1/credentials", json={"name": "svc-token", "secret": "s"}).json()

    r = alice.post(f"/ui/agents/{aid}/grant-credential",
                   data={"credential_id": cred["id"]}, follow_redirects=False)
    assert r.status_code == 303
    detail = alice.get(f"/ui/agents/{aid}").text
    assert "svc-token" in detail
    assert f"/ui/agents/{aid}/revoke-credential" in detail  # granted chip's revoke form

    alice.post(f"/ui/agents/{aid}/revoke-credential",
               data={"credential_id": cred["id"]}, follow_redirects=False)
    detail2 = alice.get(f"/ui/agents/{aid}").text
    # No granted credentials left -> no revoke form (cred reappears in grant dropdown).
    assert f"/ui/agents/{aid}/revoke-credential" not in detail2


# --- route grants from the agent page -----------------------------------------


def test_ui_grant_and_revoke_route_from_agent(fed_app, monkeypatch):
    alice = _login(fed_app, monkeypatch)
    aid = _create_agent(alice, "router-agent")
    alice.post("/v1/credentials", json={"name": "r-cred", "secret": "s"})
    route = alice.post("/v1/routes", json={
        "slug": "demo", "upstream_base": "http://127.0.0.1:1", "credential_name": "r-cred",
    }).json()

    r = alice.post(f"/ui/agents/{aid}/grant-route",
                   data={"route_id": route["id"]}, follow_redirects=False)
    assert r.status_code == 303
    detail = alice.get(f"/ui/agents/{aid}").text
    assert "/gw/demo" in detail
    assert f"/ui/agents/{aid}/revoke-route" in detail

    alice.post(f"/ui/agents/{aid}/revoke-route",
               data={"route_id": route["id"]}, follow_redirects=False)
    detail2 = alice.get(f"/ui/agents/{aid}").text
    assert f"/ui/agents/{aid}/revoke-route" not in detail2


def test_ui_agent_grant_scoped_to_other_users_credential(fed_app, monkeypatch):
    """An agent page never lets you grant a credential you can't see."""
    alice = _login(fed_app, monkeypatch, email="alice@example.com")
    bob = _login(fed_app, monkeypatch, email="bob@example.com")
    # bob owns a credential; alice owns an agent
    bob_cred = bob.post("/v1/credentials", json={"name": "bob-secret", "secret": "s"}).json()
    aid = _create_agent(alice, "alice-agent")
    detail = alice.get(f"/ui/agents/{aid}").text
    assert "bob-secret" not in detail  # not offered in alice's grant dropdown
