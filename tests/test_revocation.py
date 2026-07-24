"""Token revocation (RFC 7009) + introspection (RFC 7662)."""


def _agent(admin, name="rev"):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    return admin.post(
        "/v1/agents",
        json={"name": name, "owner_email": "owner@example.com", "allowed_scopes": ["s:x"]},
    ).json()


def _mint(client, agent):
    return client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    ).json()["access_token"]


def _introspect(client, agent, token):
    return client.post(
        "/oauth/introspect",
        data={"token": token, "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    ).json()


def test_introspection_active_then_inactive_after_revoke(admin):
    agent = _agent(admin)
    token = _mint(admin, agent)

    intro = _introspect(admin, agent, token)
    assert intro["active"] is True
    assert intro["client_id"] == agent["client_id"]
    assert intro["owner"] == "owner@example.com"

    r = admin.post(
        "/oauth/revoke",
        data={"token": token, "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    )
    assert r.status_code == 200
    assert _introspect(admin, agent, token)["active"] is False

    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert "token.revoked" in events


def test_revoked_token_rejected_at_gateway(admin):
    # A revoked token must also fail at the enforcing gateway.
    agent = _agent(admin)
    token = _mint(admin, agent)
    admin.post(
        "/oauth/revoke",
        data={"token": token, "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    )
    resp = admin.get("/gw/anything/x", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (401, 403)


def test_introspection_requires_client_auth(admin):
    agent = _agent(admin)
    token = _mint(admin, agent)
    # No/bad client credentials -> 401, not a token oracle.
    resp = admin.post("/oauth/introspect", data={"token": token})
    assert resp.status_code == 401


def test_mass_revoke_invalidates_all_existing_tokens(admin):
    agent = _agent(admin)
    t1 = _mint(admin, agent)
    t2 = _mint(admin, agent)
    assert _introspect(admin, agent, t1)["active"] is True

    resp = admin.post(f"/v1/agents/{agent['id']}/revoke-tokens")
    assert resp.status_code == 200

    # Every token issued before the mass-revoke is now inactive...
    assert _introspect(admin, agent, t1)["active"] is False
    assert _introspect(admin, agent, t2)["active"] is False
    # ...but the agent can still mint fresh ones.
    t3 = _mint(admin, agent)
    assert _introspect(admin, agent, t3)["active"] is True

    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert "agent.tokens_revoked" in events


def test_revoke_foreign_token_is_noop_but_200(admin):
    a = _agent(admin, "a")
    b = _agent(admin, "b")
    token_a = _mint(admin, a)
    # b tries to revoke a's token: RFC 7009 says still 200, but nothing happens.
    r = admin.post(
        "/oauth/revoke",
        data={"token": token_a, "client_id": b["client_id"],
              "client_secret": b["client_secret"]},
    )
    assert r.status_code == 200
    assert _introspect(admin, a, token_a)["active"] is True  # untouched


def test_metadata_advertises_endpoints(admin):
    meta = admin.get("/.well-known/oauth-authorization-server").json()
    assert meta["introspection_endpoint"].endswith("/oauth/introspect")
    assert meta["revocation_endpoint"].endswith("/oauth/revoke")
    assert "private_key_jwt" in meta["token_endpoint_auth_methods_supported"]
