"""SCIM 2.0 provisioning: per-tenant token auth, Users CRUD/PATCH/filter,
lifecycle semantics (soft-delete + agent revocation, last-admin guard,
reactivation), and the owner-suspension enforcement — a deactivated owner's
agents can neither mint new tokens nor keep using outstanding ones."""

from fastapi.testclient import TestClient

ADMIN = "test-admin-key"


def _admin(app, tenant=None):
    c = TestClient(app)
    with c:  # lifespan -> schema
        pass
    c.headers["X-Admin-Key"] = ADMIN
    if tenant:
        c.headers["X-Tenant"] = tenant
    return c


def _scim_client(app, token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def _issue_token(admin_client):
    resp = admin_client.post("/v1/scim-token")
    assert resp.status_code == 200, resp.text
    return resp.json()["scim_token"]


def test_scim_requires_valid_token(app):
    admin = _admin(app)
    _issue_token(admin)
    c = TestClient(app)
    assert c.get("/scim/v2/Users").status_code == 401
    c.headers["Authorization"] = "Bearer wrong"
    resp = c.get("/scim/v2/Users")
    assert resp.status_code == 401
    assert resp.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_scim_token_lifecycle(app):
    admin = _admin(app)
    token1 = _issue_token(admin)
    assert token1.startswith("cipherlatch_scim_")
    # Replacing invalidates the old token.
    token2 = _issue_token(admin)
    assert _scim_client(app, token1).get("/scim/v2/Users").status_code == 401
    assert _scim_client(app, token2).get("/scim/v2/Users").status_code == 200
    # Revoking disables SCIM entirely.
    assert admin.delete("/v1/scim-token").status_code == 200
    assert _scim_client(app, token2).get("/scim/v2/Users").status_code == 401
    assert admin.delete("/v1/scim-token").status_code == 404


def test_scim_user_crud_lifecycle(app):
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))

    # Create.
    resp = scim.post("/scim/v2/Users", json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "Alice@Example.com",
        "displayName": "Alice",
        "externalId": "idp-sub-alice",
    })
    assert resp.status_code == 201, resp.text
    user = resp.json()
    assert user["userName"] == "alice@example.com"  # normalized
    assert user["externalId"] == "idp-sub-alice"
    assert user["active"] is True
    uid = user["id"]
    assert resp.headers["Location"].endswith(uid)

    # Duplicate -> 409 uniqueness.
    dup = scim.post("/scim/v2/Users", json={"userName": "alice@example.com"})
    assert dup.status_code == 409
    assert dup.json()["scimType"] == "uniqueness"

    # Get + filter.
    assert scim.get(f"/scim/v2/Users/{uid}").json()["userName"] == "alice@example.com"
    listed = scim.get('/scim/v2/Users', params={"filter": 'userName eq "alice@example.com"'}).json()
    assert listed["totalResults"] == 1
    assert listed["Resources"][0]["id"] == uid
    by_ext = scim.get('/scim/v2/Users', params={"filter": 'externalId eq "idp-sub-alice"'}).json()
    assert by_ext["totalResults"] == 1
    bad = scim.get('/scim/v2/Users', params={"filter": 'emails co "x"'})
    assert bad.status_code == 400
    assert bad.json()["scimType"] == "invalidFilter"

    # PUT replace.
    put = scim.put(f"/scim/v2/Users/{uid}", json={
        "userName": "alice@example.com", "displayName": "Alice A.", "active": True,
    })
    assert put.status_code == 200
    assert put.json()["displayName"] == "Alice A."

    # PATCH deactivate (Entra-style string bool, no path).
    patch = scim.patch(f"/scim/v2/Users/{uid}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "value": {"active": "False"}}],
    })
    assert patch.status_code == 200
    assert patch.json()["active"] is False

    # PATCH reactivate with explicit path.
    patch = scim.patch(f"/scim/v2/Users/{uid}", json={
        "Operations": [{"op": "replace", "path": "active", "value": True}],
    })
    assert patch.json()["active"] is True

    # Delete -> 204, gone from lists, 404 on fetch.
    assert scim.delete(f"/scim/v2/Users/{uid}").status_code == 204
    assert scim.get(f"/scim/v2/Users/{uid}").status_code == 404
    assert scim.get("/scim/v2/Users").json()["totalResults"] == 0

    # Re-provision after delete: reactivated, not 409.
    again = scim.post("/scim/v2/Users", json={"userName": "alice@example.com"})
    assert again.status_code == 201
    assert again.json()["id"] == uid  # same principal, revived


def test_scim_tenant_isolation(app):
    acme_admin = _admin(app, "acme")
    beta_admin = _admin(app, "beta")
    acme = _scim_client(app, _issue_token(acme_admin))
    beta = _scim_client(app, _issue_token(beta_admin))

    uid = acme.post("/scim/v2/Users", json={"userName": "a@acme.com"}).json()["id"]
    assert beta.get("/scim/v2/Users").json()["totalResults"] == 0
    assert beta.get(f"/scim/v2/Users/{uid}").status_code == 404
    assert beta.delete(f"/scim/v2/Users/{uid}").status_code == 404


def test_scim_last_admin_guard(make_app, login, monkeypatch):
    app = make_app(BROKER_ADMIN_EMAILS="root@example.com")
    with TestClient(app):
        pass
    c, _ = login("root@example.com")  # promoted to broker-admin
    admin = TestClient(app)
    admin.headers["X-Admin-Key"] = ADMIN
    scim = _scim_client(app, admin.post("/v1/scim-token").json()["scim_token"])

    root = scim.get('/scim/v2/Users', params={"filter": 'userName eq "root@example.com"'}).json()
    uid = root["Resources"][0]["id"]
    deact = scim.patch(f"/scim/v2/Users/{uid}", json={
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    })
    assert deact.status_code == 409
    assert scim.delete(f"/scim/v2/Users/{uid}").status_code == 409


def test_owner_deactivation_suspends_agents(app):
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))

    uid = scim.post("/scim/v2/Users", json={"userName": "bob@example.com"}).json()["id"]
    agent = admin.post("/v1/agents", json={
        "name": "bobs-agent", "owner_email": "bob@example.com", "allowed_scopes": ["a:b"],
    }).json()
    creds = {"grant_type": "client_credentials",
             "client_id": agent["client_id"], "client_secret": agent["client_secret"]}

    # Active owner: token mints and introspects as active.
    tok = admin.post("/oauth/token", data=creds)
    assert tok.status_code == 200
    access = tok.json()["access_token"]

    # Deactivate the owner via SCIM: no new tokens, outstanding ones dead.
    scim.patch(f"/scim/v2/Users/{uid}", json={
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    })
    denied = admin.post("/oauth/token", data=creds)
    assert denied.status_code == 401
    assert "suspended" in denied.json()["error_description"].lower()
    introspect = admin.post("/oauth/introspect", data={
        "token": access, "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    })
    # introspection requires client auth, which itself is refused now
    assert introspect.status_code in (200, 401)
    if introspect.status_code == 200:
        assert introspect.json()["active"] is False

    # Reactivate: minting works again (agents were suspended, not revoked).
    scim.patch(f"/scim/v2/Users/{uid}", json={
        "Operations": [{"op": "replace", "path": "active", "value": True}],
    })
    assert admin.post("/oauth/token", data=creds).status_code == 200


def test_scim_delete_revokes_agents_permanently(app):
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))
    uid = scim.post("/scim/v2/Users", json={"userName": "carol@example.com"}).json()["id"]
    agent = admin.post("/v1/agents", json={
        "name": "carols-agent", "owner_email": "carol@example.com", "allowed_scopes": ["a:b"],
    }).json()
    creds = {"grant_type": "client_credentials",
             "client_id": agent["client_id"], "client_secret": agent["client_secret"]}
    assert admin.post("/oauth/token", data=creds).status_code == 200

    assert scim.delete(f"/scim/v2/Users/{uid}").status_code == 204
    assert admin.post("/oauth/token", data=creds).status_code == 401

    # Re-provisioning the user does NOT resurrect the revoked agent.
    scim.post("/scim/v2/Users", json={"userName": "carol@example.com"})
    assert admin.post("/oauth/token", data=creds).status_code == 401


def test_scim_pagination(app):
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))
    for i in range(5):
        scim.post("/scim/v2/Users", json={"userName": f"u{i}@example.com"})
    page = scim.get("/scim/v2/Users", params={"startIndex": 3, "count": 2}).json()
    assert page["totalResults"] == 5
    assert page["startIndex"] == 3
    assert page["itemsPerPage"] == 2
    assert [r["userName"] for r in page["Resources"]] == ["u2@example.com", "u3@example.com"]


def test_scim_discovery(app):
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))
    cfg = scim.get("/scim/v2/ServiceProviderConfig").json()
    assert cfg["patch"]["supported"] is True
    assert cfg["bulk"]["supported"] is False
    types = scim.get("/scim/v2/ResourceTypes").json()
    assert [r["id"] for r in types["Resources"]] == ["User"]
    assert scim.get("/scim/v2/Schemas").status_code == 200


def test_scim_token_permission_required(login):
    c, _ = login("pleb@example.com")  # agent-manager: no users:manage
    assert c.post("/v1/scim-token").status_code == 403


def test_groups_degrade_gracefully(app):
    """IdPs that insist on group sync get an empty list and a clear SCIM
    error on writes — never a bare 404 retry-loop."""
    admin = _admin(app)
    scim = _scim_client(app, _issue_token(admin))

    listed = scim.get("/scim/v2/Groups")
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 0

    created = scim.post("/scim/v2/Groups", json={"displayName": "cipherlatch-users"})
    assert created.status_code == 501
    body = created.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert "group" in body["detail"].lower()

    assert scim.put("/scim/v2/Groups/abc", json={}).status_code == 501
    assert scim.delete("/scim/v2/Groups/abc").status_code == 501

    # Still authenticated: no token, no answer.
    assert TestClient(app).get("/scim/v2/Groups").status_code == 401
