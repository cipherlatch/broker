"""UI sessions under concurrency: one user with several browser sessions,
sessions hopping between nodes of a cluster, and two admins stepping on each
other.

"Two nodes" here = two `create_app()` instances built from the same
environment, sharing one database and one BROKER_SESSION_SECRET — exactly the
HA topology of docker-compose.ha.yml. The session cookie is a signed stateless
cookie holding only the principal id; authorization state (active / deleted /
role) is re-read from the shared DB on every request, which is what makes the
cross-node assertions below hold.
"""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.testing import ADMIN_KEY
from tests.conftest import FAKE_DISCOVERY

SESSION_COOKIE = "cipherlatch_session"


def _login(app, monkeypatch, email):
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    with c:
        pass  # run lifespan once (schema)
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    assert r.status_code == 302, r.text
    return c


def _machine(app):
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return c


def _as_session(app, cookie_value):
    """A client for `app` presenting a session cookie minted elsewhere."""
    c = TestClient(app)
    with c:
        pass
    c.cookies.set(SESSION_COOKIE, cookie_value)
    return c


def _uid(machine, email):
    return next(u for u in machine.get("/v1/users").json() if u["email"] == email)["id"]


# --- one user, several sessions ---------------------------------------------


def test_same_user_two_sessions_are_independent(login, admin):
    s1, _ = login("dual@example.com")
    s2, _ = login("dual@example.com")  # same sub -> same principal
    assert s1.get("/v1/agents").status_code == 200
    assert s2.get("/v1/agents").status_code == 200

    # Logout is per-browser (the cookie is stateless): it ends that session
    # only, never the user's other sessions.
    assert s1.post("/auth/logout", follow_redirects=False).status_code == 302
    assert s1.get("/v1/agents").status_code == 401
    assert s2.get("/v1/agents").status_code == 200


def test_disable_kills_every_session_of_the_user(login, admin):
    s1, _ = login("multi@example.com")
    s2, _ = login("multi@example.com")
    uid = _uid(admin, "multi@example.com")

    assert admin.patch(f"/v1/users/{uid}", json={"active": False}).status_code == 200
    assert s1.get("/v1/agents").status_code == 401
    assert s2.get("/v1/agents").status_code == 401


def test_role_change_applies_to_live_sessions_immediately(login, admin):
    s, _ = login("climber@example.com")
    login("other-admin@example.com")
    admin.patch(f"/v1/users/{_uid(admin, 'other-admin@example.com')}", json={"role": "broker-admin"})
    uid = _uid(admin, "climber@example.com")
    assert s.get("/ui/users").status_code == 404  # non-admin: page hidden

    admin.patch(f"/v1/users/{uid}", json={"role": "broker-admin"})
    assert s.get("/ui/users").status_code == 200  # no re-login needed

    admin.patch(f"/v1/users/{uid}", json={"role": "agent-manager"})
    assert s.get("/ui/users").status_code == 404  # demotion equally immediate


# --- sessions across cluster nodes -------------------------------------------


def test_session_minted_on_one_node_works_on_another(make_app, monkeypatch):
    node1 = make_app()
    node2 = make_app()  # same env: same DB file, same session secret
    s1 = _login(node1, monkeypatch, "roamer@example.com")

    cookie = s1.cookies.get(SESSION_COOKIE)
    assert cookie
    s2 = _as_session(node2, cookie)
    assert s2.get("/v1/agents").status_code == 200
    page = s2.get("/ui/agents")
    assert page.status_code == 200


def test_node_with_different_session_secret_rejects_the_cookie(make_app, monkeypatch):
    node1 = make_app()
    s1 = _login(node1, monkeypatch, "split@example.com")
    cookie = s1.cookies.get(SESSION_COOKIE)

    # A replica that failed to share BROKER_SESSION_SECRET: the cookie's
    # signature no longer verifies, so the request is simply anonymous.
    node2 = make_app(BROKER_SESSION_SECRET="a-different-secret-on-node-2")
    s2 = _as_session(node2, cookie)
    assert s2.get("/v1/agents").status_code == 401
    assert s2.get("/ui/agents", follow_redirects=False).status_code == 303  # -> /login


def test_disable_on_one_node_kills_sessions_on_all_nodes(make_app, monkeypatch):
    node1 = make_app()
    node2 = make_app()
    s1 = _login(node1, monkeypatch, "everywhere@example.com")
    s2 = _as_session(node2, s1.cookies.get(SESSION_COOKIE))
    assert s2.get("/v1/agents").status_code == 200

    machine = _machine(node1)  # admin acts on node 1
    uid = _uid(machine, "everywhere@example.com")
    assert machine.patch(f"/v1/users/{uid}", json={"active": False}).status_code == 200

    # The shared DB is the source of truth: both nodes deny on the next request.
    assert s1.get("/v1/agents").status_code == 401
    assert s2.get("/v1/agents").status_code == 401


# --- admins stepping on each other -------------------------------------------


def _two_admin_sessions(login, admin):
    a, _ = login("admin-a@example.com")
    b, _ = login("admin-b@example.com")
    for email in ("admin-a@example.com", "admin-b@example.com"):
        admin.patch(f"/v1/users/{_uid(admin, email)}", json={"role": "broker-admin"})
    return a, b


def test_stale_admin_edit_after_delete_is_a_clean_404(login, admin):
    a, b = _two_admin_sessions(login, admin)
    login("target@example.com")
    uid = _uid(admin, "target@example.com")

    # Admin A deletes the user while admin B still has them on screen.
    assert a.delete(f"/v1/users/{uid}").status_code == 200
    assert b.patch(f"/v1/users/{uid}", json={"role": "broker-admin"}).status_code == 404
    assert b.delete(f"/v1/users/{uid}").status_code == 404  # double-delete too


def test_conflicting_admin_edits_last_write_wins_and_both_audit(login, admin):
    a, b = _two_admin_sessions(login, admin)
    login("edited@example.com")
    uid = _uid(admin, "edited@example.com")

    assert a.patch(f"/v1/users/{uid}", json={"display_name": "From A"}).status_code == 200
    assert b.patch(f"/v1/users/{uid}", json={"display_name": "From B"}).status_code == 200

    users = admin.get("/v1/users").json()
    assert next(u for u in users if u["id"] == uid)["display_name"] == "From B"
    # Both writes are in the audit trail with their real actors — nothing is
    # silently swallowed even though B overwrote A.
    events = admin.get("/v1/audit", params={"event": "user.updated"}).json()
    actors = {e["actor"] for e in events if e["detail"].get("email") == "edited@example.com"}
    assert {"admin-a@example.com", "admin-b@example.com"} <= actors


def test_admins_cannot_race_each_other_down_to_zero_admins(login, admin):
    a, b = _two_admin_sessions(login, admin)
    uid_a = _uid(admin, "admin-a@example.com")
    uid_b = _uid(admin, "admin-b@example.com")

    # A deactivates B first; the guard re-reads current state, so every
    # later attempt to remove A — by A, or by the machine key — is refused.
    assert a.patch(f"/v1/users/{uid_b}", json={"active": False}).status_code == 200
    assert b.get("/v1/users").status_code == 401  # B's session is already dead
    assert a.patch(f"/v1/users/{uid_a}", json={"active": False}).status_code == 409
    assert admin.patch(f"/v1/users/{uid_a}", json={"active": False}).status_code == 409
    assert admin.delete(f"/v1/users/{uid_a}").status_code == 409


def test_demoted_admin_session_loses_admin_powers_before_next_click(login, admin):
    a, b = _two_admin_sessions(login, admin)
    uid_b = _uid(admin, "admin-b@example.com")

    assert a.patch(f"/v1/users/{uid_b}", json={"role": "agent-manager"}).status_code == 200
    # B's open session can no longer manage users — permissions come from the
    # DB row, not from anything cached in the cookie.
    login("bystander@example.com")
    uid = _uid(admin, "bystander@example.com")
    assert b.patch(f"/v1/users/{uid}", json={"display_name": "x"}).status_code == 403
    assert b.get("/ui/users").status_code == 404
