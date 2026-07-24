"""UI refinements: the Access Map page (permission-scoped graph), the System
page (admin-only, non-sensitive), the shared icon dialog endpoints on all
three object types, Test / Discover, and the create/edit parity fields
(route rate limits, credential provider config)."""

import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FAKE_DISCOVERY

# 1x1 transparent PNG (same as the avatar tests)
PNG = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAA"
       "C0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
_FAVICON = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d4944415478da63fcffff3f030005fe02fea72d200000000049454e44ae426082"
)


class _Upstream(BaseHTTPRequestHandler):
    def _handle(self):
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(_FAVICON)))
            self.end_headers()
            self.wfile.write(_FAVICON)
            return
        payload = b'{"upstream":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle

    def log_message(self, *a):
        pass


@pytest.fixture()
def upstream():
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _setup(client, slug="mapped", upstream_base="http://127.0.0.1:1"):
    """Session-authed bootstrap: credential + route + agent, both granted."""
    client.post("/v1/credentials", json={"name": f"{slug}-cred", "secret": "s"})
    route = client.post("/v1/routes", json={
        "slug": slug, "upstream_base": upstream_base, "credential_name": f"{slug}-cred",
    }).json()
    agent = client.post("/v1/agents", json={"name": f"{slug}-agent"}).json()
    client.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    return route, agent


# --- access map ---------------------------------------------------------------


def test_access_map_renders_own_objects(login):
    alice, _ = login("alice@example.com")
    route, agent = _setup(alice)
    html = alice.get("/ui/access-map").text
    assert 'id="access-map-data"' in html
    assert "/gw/mapped" in html and "mapped-agent" in html and "mapped-cred" in html
    assert "your objects" in html  # not an admin: scoped view


def test_access_map_direct_grant_edge(login):
    alice, _ = login("alice@example.com")
    cred = alice.post("/v1/credentials", json={"name": "d-cred", "secret": "s"}).json()
    agent = alice.post("/v1/agents", json={"name": "d-agent"}).json()
    alice.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    html = alice.get("/ui/access-map").text
    assert '"direct": [{' in html or '"direct":[{' in html  # the direct edge made it into the graph


def test_access_map_is_scoped_per_user(login):
    alice, _ = login("alice@example.com")
    _setup(alice)
    bob, _ = login("bob@example.com")
    html = bob.get("/ui/access-map").text
    assert "mapped-agent" not in html and "/gw/mapped" not in html
    assert "Nothing to map yet" in html


# --- system page ----------------------------------------------------------------


def _login_to(broker_app, monkeypatch, email):
    """Session login against a specific (env-customized) app instance —
    the same seam test_default_admin uses."""
    import app.oidc as oidc_module

    claims = {"sub": f"sub-{email}", "email": email, "email_verified": True, "name": ""}
    monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
    monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
    monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)
    c = TestClient(broker_app)
    with c:
        pass  # run lifespan once (schema)
    r = c.get("/auth/login", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
    return c


def test_system_page_admin_only(make_app, monkeypatch):
    broker_app = make_app(BROKER_ADMIN_EMAILS="boss@example.com")
    boss = _login_to(broker_app, monkeypatch, "boss@example.com")
    html = boss.get("/ui/system").text
    assert "Signing keystore" in html and "file" in html
    assert "Credential encryption" in html and "Enterprise plugin" in html
    # never leak material: the page shows kids and booleans only
    assert "BEGIN" not in html
    alice = _login_to(broker_app, monkeypatch, "alice@example.com")
    assert alice.get("/ui/system").status_code == 404


# --- shared icon dialog endpoints ------------------------------------------------


def test_credential_icon_emoji_upload_remove(login):
    alice, _ = login("alice@example.com")
    cred = alice.post("/v1/credentials", json={"name": "ic-cred", "secret": "s"}).json()
    url = f"/ui/credentials/{cred['id']}/icon"

    r = alice.post(url, data={"mode": "emoji", "value": "🔑"}, follow_redirects=False)
    assert r.status_code == 303
    assert "🔑" in alice.get("/ui/credentials").text

    r = alice.post(url, data={"mode": "upload", "data": PNG}, follow_redirects=False)
    assert r.status_code == 303
    assert PNG in alice.get("/ui/credentials").text

    # SVG stays excluded, same as avatars and fetched favicons
    svg = "data:image/svg+xml;base64,PHN2Zy8+"
    assert alice.post(url, data={"mode": "upload", "data": svg},
                      follow_redirects=False).status_code == 422

    r = alice.post(url, data={"mode": "remove"}, follow_redirects=False)
    assert r.status_code == 303
    assert PNG not in alice.get("/ui/credentials").text


def test_agent_icon_endpoint(login):
    alice, _ = login("alice@example.com")
    agent = alice.post("/v1/agents", json={"name": "icon-agent"}).json()
    r = alice.post(f"/ui/agents/{agent['id']}/icon",
                   data={"mode": "upload", "data": PNG}, follow_redirects=False)
    assert r.status_code == 303
    assert PNG in alice.get(f"/ui/agents/{agent['id']}").text


def test_route_icon_endpoint_detect(login, upstream):
    alice, _ = login("alice@example.com")
    route, _ = _setup(alice, slug="det", upstream_base=upstream)
    r = alice.post(f"/ui/routes/{route['id']}/icon",
                   data={"mode": "detect"}, follow_redirects=False)
    assert r.status_code == 303
    assert "data:image/png" in alice.get("/ui/routes").text


# --- Test / Discover --------------------------------------------------------------


def test_route_test_discover_combined_flash(login, upstream):
    alice, _ = login("alice@example.com")
    route, _ = _setup(alice, slug="td", upstream_base=upstream)
    r = alice.post(f"/ui/routes/{route['id']}/test", data={"test_path": "/"},
                   follow_redirects=False)
    assert r.status_code == 303
    html = alice.get("/ui/routes").text  # flash renders on the next page
    assert "HTTP 200" in html and "favicon discovered" in html


def test_route_test_discover_reports_no_favicon(login):
    alice, _ = login("alice@example.com")
    route, _ = _setup(alice, slug="dead")  # upstream is a closed port
    alice.post(f"/ui/routes/{route['id']}/test", data={"test_path": "/"},
               follow_redirects=False)
    html = alice.get("/ui/routes").text
    assert "✗" in html and "no favicon found" in html


# --- create/edit parity fields -----------------------------------------------------


def test_route_rate_limit_and_quota_via_ui(login):
    alice, _ = login("alice@example.com")
    alice.post("/v1/credentials", json={"name": "rl-cred", "secret": "s"})
    r = alice.post("/ui/routes", data={
        "slug": "rl", "upstream_base": "http://127.0.0.1:1", "credential_name": "rl-cred",
        "rate_limit_per_minute": "30", "daily_quota": "100",
    }, follow_redirects=False)
    assert r.status_code == 303
    html = alice.get("/ui/routes").text
    assert "30/min" in html and "100/day" in html
    # a non-number is refused, not silently zeroed
    assert alice.post("/ui/routes", data={
        "slug": "rl2", "upstream_base": "http://127.0.0.1:1", "credential_name": "rl-cred",
        "rate_limit_per_minute": "lots",
    }, follow_redirects=False).status_code == 422


def test_static_credential_config_field_is_inert(login):
    """Posting provider config on a static credential must not error or stick —
    config only applies to provider-backed credentials."""
    alice, _ = login("alice@example.com")
    cred = alice.post("/v1/credentials", json={"name": "st-cred", "secret": "s"}).json()
    r = alice.post(f"/ui/credentials/{cred['id']}/update",
                   data={"description": "d", "provider_config": '{"ttl": 60}'},
                   follow_redirects=False)
    assert r.status_code == 303
    got = alice.get(f"/v1/credentials/{cred['id']}").json()
    assert got.get("provider_config") in (None, {})


# --- CSP / upload regression guard -----------------------------------------------


def test_uploads_use_filereader_not_blob_urls():
    """Client-side image uploads (icon + avatar) must read files via FileReader
    (a data: URL) — NOT URL.createObjectURL, whose blob: URL is refused by the
    page CSP (img-src 'self' data:), silently breaking every upload. This bug is
    invisible to the request-level tests, so guard the source pattern directly."""
    import pathlib

    js = pathlib.Path(__file__).resolve().parent.parent / "app" / "static" / "app.js"
    src = js.read_text()
    assert ".createObjectURL(" not in src, (
        "blob: URLs are blocked by the CSP; use FileReader.readAsDataURL instead"
    )
    assert src.count("readAsDataURL") >= 2, "both icon and avatar uploads must use FileReader"


def test_csp_allows_data_images_for_uploads():
    """The upload preview + canvas path relies on data: images; assert the CSP
    still permits them (and documents that it need not allow blob:)."""
    from app.testing import build_app

    import pytest as _pytest

    # A tiny app instance just to read the middleware-set CSP header.
    # (make_app fixture isn't used here to keep this a pure header check.)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        mp = _pytest.MonkeyPatch()
        try:
            app = build_app(mp, pathlib.Path(d), {})
            from fastapi.testclient import TestClient

            with TestClient(app) as c:
                csp = c.get("/login").headers.get("content-security-policy", "")
        finally:
            mp.undo()
    assert "img-src" in csp and "data:" in csp
