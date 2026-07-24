"""Enforcing gateway: auth, grant-gating, method/path policy, credential
injection, and the agent never seeing the secret."""

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# 1x1 transparent PNG, for the upstream's /favicon.ico
_FAVICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY


# --- a tiny real upstream that echoes what it received -----------------------

class _Upstream(BaseHTTPRequestHandler):
    received: list = []

    def _read_body(self):
        # Handle both fixed-length and chunked (git-mode streams -> chunked).
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()  # trailing CRLF
                    break
                data += self.rfile.read(size)
                self.rfile.readline()  # CRLF after each chunk
            return data
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _handle(self):
        if self.command == "GET" and self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(_FAVICON_PNG)))
            self.end_headers()
            self.wfile.write(_FAVICON_PNG)
            return
        body = self._read_body()
        _Upstream.received.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "x_api_key": self.headers.get("X-Api-Key"),
                "x_api_key_all": self.headers.get_all("X-Api-Key") or [],
                "cookie": self.headers.get("Cookie"),
                "body": body.decode() or None,
            }
        )
        payload = b'{"upstream":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_DELETE = _handle

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def upstream():
    _Upstream.received = []
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", _Upstream.received
    server.shutdown()


# --- helpers -----------------------------------------------------------------

def _bootstrap(admin, upstream_base, *, methods=None, prefixes=None, inject=("bearer", "Authorization")):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post(
        "/v1/agents",
        json={"name": "gw-agent", "owner_email": "owner@example.com", "allowed_scopes": []},
    ).json()
    admin.post(
        "/v1/credentials",
        json={"name": "svc-cred", "secret": "SECRET-TOKEN-XYZ", "owner_email": "owner@example.com"},
    )
    route = admin.post(
        "/v1/routes",
        json={
            "slug": "svc", "upstream_base": upstream_base, "credential_name": "svc-cred",
            "owner_email": "owner@example.com",
            "inject_mode": inject[0], "inject_header": inject[1],
            "allowed_methods": methods or ["GET", "POST"],
            "allowed_path_prefixes": prefixes or [],
        },
    )
    assert route.status_code == 201, route.text
    return agent, route.json()


def _mint(client, agent):
    return client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    ).json()["access_token"]


def _call(client, token, path="/data", method="GET", extra_headers=None, **kw):
    headers = {"Authorization": f"Bearer {token}"}
    if extra_headers:
        headers.update(extra_headers)
    return client.request(method, f"/gw/svc{path}", headers=headers, **kw)


# --- tests -------------------------------------------------------------------

def test_proxy_injects_credential_agent_never_sees_it(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)

    resp = _call(admin, token, "/data")
    assert resp.status_code == 200
    assert resp.json() == {"upstream": "ok"}

    # Upstream saw the injected credential; the agent supplied only its Cipherlatch JWT.
    assert received[-1]["authorization"] == "Bearer SECRET-TOKEN-XYZ"
    assert "SECRET-TOKEN-XYZ" not in resp.text  # never echoed back to the agent


def test_ungranted_agent_denied(admin, upstream):
    base, _ = upstream
    agent, route = _bootstrap(admin, base)  # no grant
    token = _mint(admin, agent)
    resp = _call(admin, token, "/data")
    assert resp.status_code == 403
    assert resp.json()["error"] == "gateway_denied"


def test_unknown_route_same_as_ungranted(admin, upstream):
    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    granted_miss = _call(admin, token, "/data", method="GET")  # allowed
    # A route that doesn't exist returns the same 403 shape as not-granted.
    resp = admin.get("/gw/nonexistent/x", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_method_policy_enforced(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base, methods=["GET"])
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    assert _call(admin, token, "/x", method="GET").status_code == 200
    denied = _call(admin, token, "/x", method="POST", content=b"{}")
    assert denied.status_code == 403
    # The blocked request never reached the upstream.
    assert all(r["method"] != "POST" for r in received)


def test_path_prefix_policy_enforced(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base, prefixes=["/api/allowed"])
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    assert _call(admin, token, "/api/allowed/thing").status_code == 200
    assert _call(admin, token, "/api/secret").status_code == 403
    assert all("/api/secret" not in r["path"] for r in received)


def test_path_traversal_cannot_escape_base(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base, prefixes=["/api"])
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    # Attempt to climb out of /api via traversal; policy + URL join must refuse.
    resp = _call(admin, token, "/api/../secret")
    assert resp.status_code in (400, 403)


def test_header_injection_mode(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base, inject=("header", "X-Api-Key"))
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    _call(admin, token, "/data")
    assert received[-1]["x_api_key"] == "SECRET-TOKEN-XYZ"
    assert received[-1]["authorization"] is None  # not a bearer route


def test_client_bearer_and_cookies_not_forwarded(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    _call(admin, token, "/data", extra_headers={"Cookie": "x=y"})
    # The agent's Cipherlatch token is replaced, not forwarded; cookies stripped.
    assert received[-1]["authorization"] == "Bearer SECRET-TOKEN-XYZ"
    assert received[-1]["cookie"] is None


def test_expired_token_denied(admin, upstream):
    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    resp = _call(admin, "not-a-real-jwt", "/data")
    assert resp.status_code == 401


def test_body_and_query_forwarded(admin, upstream):
    base, received = upstream
    agent, route = _bootstrap(admin, base, methods=["POST"])
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    _call(admin, token, "/submit?flag=1", method="POST", content=b'{"k":"v"}')
    assert received[-1]["body"] == '{"k":"v"}'
    assert "flag=1" in received[-1]["path"]


def test_proxied_transaction_is_audited(admin, upstream):
    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)
    _call(admin, token, "/data")
    events = admin.get("/v1/audit", params={"event": "gateway.proxied"}).json()
    assert any(
        e["detail"]["slug"] == "svc" and e["detail"]["status"] == 200 for e in events
    )


def test_routes_are_owner_scoped(login, upstream):
    base, _ = upstream
    alice, _ = login("alice@example.com")
    bob, _ = login("bob@example.com")
    alice.post("/v1/credentials", json={"name": "a-cred", "secret": "s"})
    r = alice.post(
        "/v1/routes",
        json={"slug": "aroute", "upstream_base": base, "credential_name": "a-cred"},
    ).json()
    assert bob.get("/v1/routes").json() == []
    assert bob.get(f"/v1/routes/{r['id']}").status_code == 404
    assert bob.delete(f"/v1/routes/{r['id']}").status_code == 404


# --- M1: client cannot smuggle a duplicate of the injected credential header --

def test_client_cannot_override_injected_custom_header(admin, upstream):
    """inject_mode=header with a custom header name: a client that sends its
    own copy (any casing) must not reach the upstream alongside the injected
    credential."""
    base, received = upstream
    agent, route = _bootstrap(admin, base, inject=("header", "X-Api-Key"))
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)

    resp = _call(admin, token, "/data", extra_headers={"x-api-key": "ATTACKER"})
    assert resp.status_code == 200
    # Only the injected value reaches upstream — no duplicate, no attacker value.
    assert received[-1]["x_api_key_all"] == ["SECRET-TOKEN-XYZ"]
    assert "ATTACKER" not in (received[-1]["x_api_key_all"] or [])


# --- M3: request / response body caps ----------------------------------------

def _small_cap_app(make_app, monkeypatch):
    from app.testing import ADMIN_KEY
    app = make_app(BROKER_GATEWAY_MAX_BODY_BYTES="8")
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return c


def test_oversized_request_body_rejected_before_upstream(make_app, monkeypatch, upstream):
    base, received = upstream
    admin = _small_cap_app(make_app, monkeypatch)
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)

    resp = _call(admin, token, "/data", method="POST", content=b"x" * 4096)
    assert resp.status_code == 413
    # Upstream was never contacted with the oversized body.
    assert received == []
    events = admin.get("/v1/audit", params={"event": "gateway.denied"}).json()
    assert any(e["detail"].get("reason") == "request_too_large" for e in events)


def test_oversized_upstream_response_capped(make_app, monkeypatch, upstream):
    # Cap (8 bytes) is smaller than the upstream's ~17-byte JSON, so the
    # response is aborted mid-stream rather than buffered whole.
    base, received = upstream
    admin = _small_cap_app(make_app, monkeypatch)
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    token = _mint(admin, agent)

    resp = _call(admin, token, "/data")
    assert resp.status_code == 502
    assert resp.json()["detail"] == "upstream response too large"
    events = admin.get("/v1/audit", params={"event": "gateway.error"}).json()
    assert any(e["detail"].get("reason") == "response_too_large" for e in events)


def test_route_verify_tls_flag(admin, upstream, monkeypatch):
    """verify_tls defaults on, is togglable, and is passed to the upstream client."""
    import app.routers.gateway as gw

    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    assert route["verify_tls"] is True  # default: verification on
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")

    captured: dict = {}
    real_client = gw.httpx.AsyncClient

    def spy(*a, **kw):
        captured["verify"] = kw.get("verify")
        return real_client(*a, **kw)

    monkeypatch.setattr(gw.httpx, "AsyncClient", spy)

    token = _mint(admin, agent)
    assert _call(admin, token, "/data").status_code == 200
    assert captured["verify"] is True

    # Flip to the risky, testing-only path and confirm it propagates.
    upd = admin.patch(f"/v1/routes/{route['id']}", json={"verify_tls": False})
    assert upd.status_code == 200 and upd.json()["verify_tls"] is False
    captured.clear()
    assert _call(admin, token, "/data").status_code == 200
    assert captured["verify"] is False


def test_route_icon_autodetect_favicon_on_ui_create(login, upstream):
    """Creating a route through the UI (no icon) auto-detects the upstream's
    favicon. (The JSON API stays side-effect-free — icon must be set explicitly
    or via /detect-icon there.)"""
    base, _ = upstream
    alice, _ = login("alice@example.com")
    alice.post("/v1/credentials", json={"name": "c1", "secret": "s"})
    alice.post("/ui/routes", data={"slug": "iconic", "upstream_base": base, "credential_name": "c1"})
    r = next(x for x in alice.get("/v1/routes").json() if x["slug"] == "iconic")
    assert r["icon"].startswith("data:image/png;base64,")
    # the routes page renders the detected favicon as an <img>
    assert '<img src="data:image/png;base64,' in alice.get("/ui/routes").text


def test_route_icon_explicit_emoji_wins_and_data_uri_rejected(admin, upstream):
    """A user-set emoji is kept (no favicon fetch); a data: URI from a caller is rejected."""
    base, _ = upstream
    admin.post("/v1/users", json={"email": "o@example.com"})
    admin.post("/v1/credentials", json={"name": "c2", "secret": "s", "owner_email": "o@example.com"})
    r = admin.post(
        "/v1/routes",
        json={"slug": "emoji", "upstream_base": base, "credential_name": "c2",
              "owner_email": "o@example.com", "icon": "🔧"},
    ).json()
    assert r["icon"] == "🔧"
    bad = admin.patch(f"/v1/routes/{r['id']}", json={"icon": "data:image/png;base64,AAAA"})
    assert bad.status_code == 422
    # re-detect endpoint replaces it with the favicon
    got = admin.post(f"/v1/routes/{r['id']}/detect-icon").json()
    assert got["icon"].startswith("data:image/png;base64,")


def test_route_catalog_api(admin):
    r = admin.get("/v1/routes/catalog")
    assert r.status_code == 200
    entries = r.json()
    ids = {e["id"] for e in entries}
    assert {"anthropic", "proxmox", "github", "gitlab-git", "vmware-vcenter", "podman"} <= ids
    anth = next(e for e in entries if e["id"] == "anthropic")
    assert anth["inject_header"] == "x-api-key" and anth["needs_host"] is False
    prox = next(e for e in entries if e["id"] == "proxmox")
    assert prox["needs_host"] is True and prox["verify_tls"] is False and "{host}" in prox["upstream"]
    # catalog isn't shadowed by GET /{route_id}
    assert admin.get("/v1/routes/catalog").json()[0]["id"] == entries[0]["id"]


def test_static_assets_cache_busted(login):
    """Static refs carry a ?v=<hash> so a deploy isn't masked by a stale app.js."""
    import re
    alice, _ = login("alice@example.com")
    html = alice.get("/ui/routes").text
    assert re.search(r"/static/app\.js\?v=[0-9a-f]{8}", html)
    assert re.search(r"/static/app\.css\?v=[0-9a-f]{8}", html)


def test_routes_ui_has_template_picker(login):
    alice, _ = login("alice@example.com")
    html = alice.get("/ui/routes").text
    assert 'id="route-template"' in html and 'route-catalog-data' in html
    assert "Proxmox VE" in html


# Icon-from-URL fetches arbitrary caller-supplied URLs, so the SSRF guard is on
# by default and blocks the localhost fixture upstream. These tests opt into the
# same cimd escape hatch a deployment would use to fetch internal icons; the
# guard's default-on behavior is covered by test_fetch_icon_url_* below and the
# cimd suite.
def _allow_private_admin(make_app):
    from app.testing import ADMIN_KEY
    app = make_app(BROKER_CIMD_ALLOW_PRIVATE_IPS="true")
    c = TestClient(app)
    with c:
        pass
    c.headers["X-Admin-Key"] = ADMIN_KEY
    return app, c


def _login_on(app, monkeypatch, email):
    import app.oidc as oidc_module
    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(app)
    resp = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    return c


def test_ui_single_icon_field_url_or_emoji(make_app, monkeypatch, upstream):
    """The route UI's one Icon field takes an emoji OR an image URL (fetched)."""
    base, _ = upstream
    app, _ = _allow_private_admin(make_app)
    alice = _login_on(app, monkeypatch, "alice@example.com")
    alice.post("/v1/credentials", json={"name": "c1", "secret": "s"})
    r = alice.post("/v1/routes", json={"slug": "iconic", "upstream_base": base, "credential_name": "c1"}).json()
    alice.post(f"/ui/routes/{r['id']}/update",
               data={"icon": base + "/favicon.ico", "upstream_base": base, "methods": "GET"})
    assert alice.get(f"/v1/routes/{r['id']}").json()["icon"].startswith("data:image/png")
    alice.post(f"/ui/routes/{r['id']}/update",
               data={"icon": "🔧", "upstream_base": base, "methods": "GET"})
    assert alice.get(f"/v1/routes/{r['id']}").json()["icon"] == "🔧"


def test_route_icon_from_url(make_app, upstream):
    """A pasted image URL is fetched server-side and stored as the route icon."""
    base, _ = upstream
    _, admin = _allow_private_admin(make_app)
    agent, route = _bootstrap(admin, base)
    ok = admin.post(f"/v1/routes/{route['id']}/icon-from-url", json={"url": base + "/favicon.ico"})
    assert ok.status_code == 200 and ok.json()["icon"].startswith("data:image/png;base64,")
    # a URL that isn't a usable image -> 422
    bad = admin.post(f"/v1/routes/{route['id']}/icon-from-url", json={"url": base + "/data"})
    assert bad.status_code == 422


def test_agent_icon(make_app, upstream):
    """Agents take an emoji or a fetched image URL; a data: URI is rejected."""
    base, _ = upstream
    _, admin = _allow_private_admin(make_app)
    admin.post("/v1/users", json={"email": "o@example.com"})
    a = admin.post(
        "/v1/agents",
        json={"name": "iconbot", "owner_email": "o@example.com", "allowed_scopes": [], "icon": "🤖"},
    ).json()
    assert a["icon"] == "🤖"
    bad = admin.post(
        "/v1/agents",
        json={"name": "baddie", "owner_email": "o@example.com", "icon": "data:image/png;base64,AAAA"},
    )
    assert bad.status_code == 422
    got = admin.post(f"/v1/agents/{a['id']}/icon-from-url", json={"url": base + "/favicon.ico"})
    assert got.status_code == 200 and got.json()["icon"].startswith("data:image/png;base64,")


def test_icon_from_url_blocks_private_target_by_default(admin, upstream):
    """With the SSRF guard on (default), icon-from-URL refuses a localhost/LAN
    target: the guarded fetch returns nothing, so the endpoint 422s."""
    base, _ = upstream  # http://127.0.0.1:<port>
    agent, route = _bootstrap(admin, base)
    resp = admin.post(f"/v1/routes/{route['id']}/icon-from-url",
                      json={"url": base + "/favicon.ico"})
    assert resp.status_code == 422


def test_fetch_icon_url_rejects_bad_scheme():
    from app import favicon
    assert favicon.fetch_icon_url("ftp://host/x.png") is None
    assert favicon.fetch_icon_url("not-a-url") is None


def test_routes_ui_edit_form_full_crud(login, upstream):
    """The routes UI renders the per-route Test form and an edit form at parity
    with create (credential + inject fields, previously create-only)."""
    base, _ = upstream
    alice, _ = login("alice@example.com")
    alice.post("/v1/credentials", json={"name": "a-cred", "secret": "s"})
    alice.post("/v1/routes", json={"slug": "aroute", "upstream_base": base, "credential_name": "a-cred"})
    html = alice.get("/ui/routes").text
    assert 'name="test_path"' in html and "Test / Discover" in html  # Test + favicon discovery
    assert html.count('name="inject_mode"') >= 2                      # create + edit forms
    assert html.count('name="credential_name"') >= 2                  # update parity with create


def test_route_test_probe(admin, upstream):
    """The owner-side test endpoint fires a real request through the route
    (credential injected, no agent grant needed) and reports the outcome."""
    base, received = upstream
    agent, route = _bootstrap(admin, base)  # no grant issued
    resp = admin.post(f"/v1/routes/{route['id']}/test", json={"path": "/health"})
    assert resp.status_code == 200, resp.text
    r = resp.json()
    assert r["ok"] is True and r["reached"] is True and r["status"] == 200
    # the probe injected the credential and hit the requested path
    assert received[-1]["path"] == "/health"
    assert received[-1]["authorization"] == "Bearer SECRET-TOKEN-XYZ"


def test_route_test_reports_unreachable(admin, upstream):
    """A route pointing at a dead upstream reports reached=False, not a 500."""
    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    # repoint at a closed port
    admin.patch(f"/v1/routes/{route['id']}", json={"upstream_base": "http://127.0.0.1:1"})
    r = admin.post(f"/v1/routes/{route['id']}/test", json={"path": "/"}).json()
    assert r["ok"] is False and r["reached"] is False


def test_gateway_401_offers_basic_challenge(admin, upstream):
    """A missing token yields 401 with a WWW-Authenticate: Basic challenge, so
    git (which auths only after a challenge) knows to retry with credentials."""
    base, _ = upstream
    agent, route = _bootstrap(admin, base)
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    resp = admin.get("/gw/svc/data")  # no Authorization header
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate", "").lower().startswith("basic")


def _git_route(admin, base):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post(
        "/v1/agents",
        json={"name": "git-agent", "owner_email": "owner@example.com", "allowed_scopes": []},
    ).json()
    admin.post(
        "/v1/credentials",
        json={"name": "git-cred", "secret": "glpat-XYZ", "owner_email": "owner@example.com"},
    )
    route = admin.post(
        "/v1/routes",
        json={"slug": "git", "upstream_base": base, "credential_name": "git-cred",
              "owner_email": "owner@example.com", "allowed_methods": ["GET", "POST"],
              "git_http": True},
    )
    assert route.status_code == 201, route.text
    assert route.json()["git_http"] is True
    admin.post(f"/v1/routes/{route.json()['id']}/grants/{agent['id']}")
    return agent, route.json()


def test_git_http_basic_auth_and_injection(admin, upstream):
    """git-mode: the agent presents its token via Basic (as git does), and the
    upstream receives the stored credential as Basic oauth2:<pat> — never the token."""
    import base64
    base, received = upstream
    agent, _ = _git_route(admin, base)
    token = _mint(admin, agent)

    basic = base64.b64encode(f"x:{token}".encode()).decode()
    resp = admin.post(
        "/gw/git/repo.git/git-receive-pack",
        headers={"Authorization": f"Basic {basic}"}, content=b"PACKDATA",
    )
    assert resp.status_code == 200, resp.text
    assert received[-1]["path"] == "/repo.git/git-receive-pack"
    assert received[-1]["body"] == "PACKDATA"
    assert received[-1]["authorization"] == "Basic " + base64.b64encode(b"oauth2:glpat-XYZ").decode()
    assert token not in (received[-1]["authorization"] or "")


def test_git_http_streams_past_body_cap(make_app, monkeypatch, upstream):
    """A body far larger than the gateway body cap rides through in git-mode,
    where a normal route would 413."""
    base, received = upstream
    admin = _small_cap_app(make_app, monkeypatch)  # 8-byte cap
    agent, _ = _git_route(admin, base)
    token = _mint(admin, agent)

    import base64
    basic = base64.b64encode(f"x:{token}".encode()).decode()
    big = b"X" * 5000  # >> the 8-byte cap
    resp = admin.post(
        "/gw/git/repo.git/git-receive-pack",
        headers={"Authorization": f"Basic {basic}"}, content=big,
    )
    assert resp.status_code == 200, resp.text
    assert received[-1]["body"] == big.decode()
