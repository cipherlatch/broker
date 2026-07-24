from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.testing import ADMIN_KEY, build_app, reset_app_state

FAKE_DISCOVERY = {
    "authorization_endpoint": "https://idp.test/authorize",
    "token_endpoint": "https://idp.test/token",
    "jwks_uri": "https://idp.test/jwks",
}


@pytest.fixture()
def make_app(tmp_path, monkeypatch):
    """App factory; call with env overrides, e.g. make_app(BROKER_JIT_PROVISIONING='false').
    The machinery lives in app/testing.py, shared with plugin-package suites."""

    def _make(**env):
        return build_app(monkeypatch, tmp_path, env)

    yield _make
    reset_app_state()


@pytest.fixture()
def app(make_app):
    return make_app()


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin(client):
    """Client authenticated with the machine admin key."""
    client.headers["X-Admin-Key"] = ADMIN_KEY
    return client


@pytest.fixture()
def login(app, client, monkeypatch):
    """Returns login(email, ...) -> (fresh TestClient with a session, callback response).

    Stubs the OIDC network seams; the real /auth/login and /auth/callback
    routes (state checking, JIT, linking, role sync) still execute. Depends on
    `client` so the app lifespan (schema creation) has run.
    """

    def _login(email: str, sub: str | None = None, name: str = "", claims_extra: dict | None = None):
        import app.oidc as oidc_module

        sub = sub or f"sub-{email}"
        claims = {"sub": sub, "email": email, "email_verified": True, "name": name}
        claims.update(claims_extra or {})

        monkeypatch.setattr(oidc_module, "get_discovery", lambda: FAKE_DISCOVERY)
        monkeypatch.setattr(oidc_module, "exchange_code", lambda *a, **k: {"id_token": "stub"})
        monkeypatch.setattr(oidc_module, "verify_id_token", lambda token, nonce: claims)

        c = TestClient(app)
        resp = c.get("/auth/login", follow_redirects=False)
        assert resp.status_code == 302, resp.text
        state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
        resp = c.get(f"/auth/callback?code=fake&state={state}", follow_redirects=False)
        return c, resp

    return _login
