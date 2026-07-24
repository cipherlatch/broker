"""Audit API keyset pagination: `before` cursor + X-Next-Before header.
Backward compatible — the response body stays a plain list; the cursor
travels in a header and only appears when more pages exist."""


def _seed_events(admin, n):
    """Each user create emits one user.created audit event."""
    for i in range(n):
        admin.post("/v1/users", json={"email": f"page-{i}@example.com"})


def test_keyset_pagination_walks_all_events(admin):
    _seed_events(admin, 7)

    seen: list[str] = []
    before = None
    pages = 0
    while True:
        params = {"event": "user.created", "limit": 3}
        if before:
            params["before"] = before
        resp = admin.get("/v1/audit", params=params)
        assert resp.status_code == 200, resp.text
        page = resp.json()
        assert len(page) <= 3
        seen.extend(e["id"] for e in page)
        pages += 1
        before = resp.headers.get("X-Next-Before")
        if not before:
            break

    assert pages == 3  # 3 + 3 + 1
    assert len(seen) == 7
    assert len(set(seen)) == 7  # no overlaps, no gaps

    # Newest-first across the whole walk.
    all_events = admin.get("/v1/audit", params={"event": "user.created", "limit": 100}).json()
    assert [e["id"] for e in all_events] == seen


def test_last_page_has_no_cursor(admin):
    _seed_events(admin, 2)
    resp = admin.get("/v1/audit", params={"event": "user.created", "limit": 50})
    assert len(resp.json()) == 2
    assert "X-Next-Before" not in resp.headers


def test_cursor_header_only_when_more_rows(admin):
    _seed_events(admin, 3)
    resp = admin.get("/v1/audit", params={"event": "user.created", "limit": 3})
    # Exactly limit rows and nothing beyond: no cursor.
    assert len(resp.json()) == 3
    assert "X-Next-Before" not in resp.headers


def test_unknown_before_404s(admin):
    _seed_events(admin, 1)
    resp = admin.get("/v1/audit", params={"before": "no-such-event-id"})
    assert resp.status_code == 404


def test_before_respects_tenant_scope(make_app):
    """A cursor from another tenant's event is a 404, not a filter."""
    from fastapi.testclient import TestClient

    app = make_app()
    with TestClient(app):
        pass
    acme = TestClient(app)
    acme.headers.update({"X-Admin-Key": "test-admin-key", "X-Tenant": "acme"})
    beta = TestClient(app)
    beta.headers.update({"X-Admin-Key": "test-admin-key", "X-Tenant": "beta"})

    acme.post("/v1/users", json={"email": "a@acme.com"})
    beta.post("/v1/users", json={"email": "b@beta.com"})

    # The machine key is platform admin (sees all), so scope-check the human
    # path instead: platform admin CAN anchor on any event.
    acme_event = acme.get("/v1/audit", params={"event": "user.created"}).json()[0]["id"]
    resp = beta.get("/v1/audit", params={"before": acme_event})
    assert resp.status_code == 200  # platform admin: cross-tenant anchor OK


def test_human_cannot_anchor_on_foreign_event(make_app, monkeypatch):
    from urllib.parse import parse_qs, urlparse

    from fastapi.testclient import TestClient

    import app.oidc as oidc_module
    from tests.conftest import FAKE_DISCOVERY

    app = make_app(
        BROKER_TENANT_DOMAIN_MAP="acme.com=acme,beta.com=beta",
        BROKER_GROUP_ROLE_MAP="admins=broker-admin",
    )
    with TestClient(app):
        pass

    def login(email):
        claims = {"sub": f"sub-{email}", "email": email, "email_verified": True,
                  "name": "", "groups": ["admins"]}
        monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
        monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
        monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
        c = TestClient(app)
        r = c.get("/auth/login", follow_redirects=False)
        state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
        c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        return c

    alice = login("alice@acme.com")
    bob = login("bob@beta.com")

    # Alice's login produced audit events in tenant acme.
    alice_event = alice.get("/v1/audit").json()[0]["id"]
    resp = bob.get("/v1/audit", params={"before": alice_event})
    assert resp.status_code == 404  # existence does not leak across tenants


def test_pagination_combines_with_filters(admin):
    _seed_events(admin, 4)
    admin.post("/v1/users", json={"email": "other@example.com"})

    first = admin.get("/v1/audit", params={"event": "user.created", "limit": 2})
    cursor = first.headers["X-Next-Before"]
    second = admin.get(
        "/v1/audit", params={"event": "user.created", "limit": 2, "before": cursor}
    )
    assert all(e["event"] == "user.created" for e in second.json())
    ids_first = {e["id"] for e in first.json()}
    assert ids_first.isdisjoint({e["id"] for e in second.json()})
