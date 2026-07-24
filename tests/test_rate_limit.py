"""Per-IP rate limiting on the token/gateway endpoints."""

from fastapi.testclient import TestClient


def test_token_endpoint_rate_limited(make_app):
    app = make_app(BROKER_RATE_LIMIT_PER_MINUTE="5")
    from app.ratelimit import reset_windows

    reset_windows()
    with TestClient(app) as c:
        # 5 allowed in the window; the 6th is 429. (Bad creds still count as
        # requests — the limiter runs before auth.)
        codes = []
        for _ in range(7):
            r = c.post(
                "/oauth/token",
                data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"},
            )
            codes.append(r.status_code)
        assert codes.count(429) >= 1
        assert 429 in codes[5:]  # only after the limit is hit


def test_management_endpoints_not_rate_limited(make_app):
    app = make_app(BROKER_RATE_LIMIT_PER_MINUTE="2")
    from app.ratelimit import reset_windows

    reset_windows()
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        # /v1/* is not in the limited prefixes; many calls all succeed.
        for _ in range(6):
            assert c.get("/v1/agents").status_code == 200


def test_rate_limit_disabled_by_default(client):
    # conftest sets BROKER_RATE_LIMIT_PER_MINUTE=0; no throttling.
    codes = [
        client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"},
        ).status_code
        for _ in range(20)
    ]
    assert 429 not in codes


def test_spoofed_xforwarded_for_cannot_evade_limit(make_app):
    """With trust_proxy_hops=1, the real client is the rightmost XFF entry (set
    by the trusted proxy). A rotating spoofed left entry must not mint fresh
    buckets and slip the limit."""
    app = make_app(BROKER_RATE_LIMIT_PER_MINUTE="5", BROKER_TRUST_PROXY_IP="true")
    from app.ratelimit import reset_windows

    reset_windows()
    with TestClient(app) as c:
        codes = []
        for i in range(7):
            r = c.post(
                "/oauth/token",
                data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"},
                # attacker rotates the left (client-controlled) hop; proxy hop is fixed.
                headers={"X-Forwarded-For": f"198.51.100.{i}, 203.0.113.9"},
            )
            codes.append(r.status_code)
        assert 429 in codes  # rightmost 203.0.113.9 is one bucket -> limited


def test_client_ip_reads_nth_from_right():
    from types import SimpleNamespace

    from app.authz import client_ip
    from app.config import get_settings

    get_settings.cache_clear()

    def req(xff):
        return SimpleNamespace(
            headers={"X-Forwarded-For": xff},
            client=SimpleNamespace(host="127.0.0.1"),
        )

    import os
    os.environ["BROKER_TRUST_PROXY_IP"] = "true"
    os.environ["BROKER_TRUST_PROXY_HOPS"] = "1"
    get_settings.cache_clear()
    # rightmost is the trusted-proxy-observed client
    assert client_ip(req("1.1.1.1, 2.2.2.2, 3.3.3.3")) == "3.3.3.3"

    os.environ["BROKER_TRUST_PROXY_HOPS"] = "2"
    get_settings.cache_clear()
    assert client_ip(req("1.1.1.1, 2.2.2.2, 3.3.3.3")) == "2.2.2.2"
    del os.environ["BROKER_TRUST_PROXY_IP"]
    del os.environ["BROKER_TRUST_PROXY_HOPS"]
    get_settings.cache_clear()


def test_expired_windows_are_evicted():
    """A flood of distinct source IPs must not grow the window map without
    bound: entries past their window are swept."""
    import app.ratelimit as rl

    rl.reset_windows()
    # Seed many stale windows well in the past.
    with rl._lock:
        for i in range(200):
            rl._windows[(f"198.51.100.{i}", "/oauth/")] = [0.0, 1]
    assert len(rl._windows) == 200
    # A fresh request triggers the periodic sweep (last_sweep is 0.0).
    assert rl._allow("203.0.113.1", "/oauth/", limit=10, window=60) is True
    # All the epoch-0 windows are gone; only the new one remains.
    assert len(rl._windows) == 1
    rl.reset_windows()
