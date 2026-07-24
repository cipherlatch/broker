"""User A must never see or touch user B's agents."""


def _create_agent(c, name="my-agent", scopes=None):
    resp = c.post(
        "/v1/agents",
        json={"name": name, "allowed_scopes": scopes or ["s:read"]},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_users_only_see_own_agents(login):
    alice, _ = login("alice@example.com")
    bob, _ = login("bob@example.com")

    a1 = _create_agent(alice, "alice-agent")
    _create_agent(bob, "bob-agent")

    alice_names = {a["name"] for a in alice.get("/v1/agents").json()}
    bob_names = {a["name"] for a in bob.get("/v1/agents").json()}
    assert alice_names == {"alice-agent"}
    assert bob_names == {"bob-agent"}

    # Direct access to the other user's agent behaves like a missing resource.
    assert bob.get(f"/v1/agents/{a1['id']}").status_code == 404


def test_cross_user_mutations_are_404(login):
    alice, _ = login("alice@example.com")
    bob, _ = login("bob@example.com")
    agent = _create_agent(alice)

    assert bob.patch(f"/v1/agents/{agent['id']}", json={"description": "x"}).status_code == 404
    assert bob.post(f"/v1/agents/{agent['id']}/rotate").status_code == 404
    assert bob.delete(f"/v1/agents/{agent['id']}").status_code == 404

    # And the agent is untouched.
    mine = alice.get(f"/v1/agents/{agent['id']}").json()
    assert mine["active"] is True


def test_admin_role_via_admin_emails(make_app, monkeypatch):
    from fastapi.testclient import TestClient
    from urllib.parse import parse_qs, urlparse
    import app.oidc as oidc_module
    from tests.conftest import FAKE_DISCOVERY

    app = make_app(BROKER_ADMIN_EMAILS="root@example.com")

    def do_login(email):
        claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
        monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
        monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
        monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
        c = TestClient(app)
        with c:
            pass  # run lifespan (schema)
        r = c.get("/auth/login", follow_redirects=False)
        state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
        c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        return c

    user = do_login("plain@example.com")
    _create_agent(user, "plain-agent")

    root = do_login("root@example.com")
    names = {a["name"] for a in root.get("/v1/agents").json()}
    assert "plain-agent" in names  # admin sees other users' agents

    # Admin-only surface: users list
    assert root.get("/v1/users").status_code == 200
    assert user.get("/v1/users").status_code == 403


def test_audit_is_owner_scoped(login):
    alice, _ = login("alice@example.com")
    bob, _ = login("bob@example.com")
    agent = _create_agent(alice, "alice-agent")

    bob_events = bob.get("/v1/audit").json()
    assert not any(e["agent_id"] == agent["id"] for e in bob_events)
    alice_events = alice.get("/v1/audit").json()
    assert any(e["agent_id"] == agent["id"] for e in alice_events)
