"""BROKER_FIPS_MODE self-check: claiming FIPS on a non-FIPS OpenSSL refuses
to boot; on a FIPS provider it boots and /readyz reports (and gates on) the
provider state. Off by default with no surface change."""

import pytest
from fastapi.testclient import TestClient


def test_fips_mode_refuses_non_fips_openssl(make_app, monkeypatch):
    import app.fips as fips

    monkeypatch.setattr(fips, "_openssl_fips_enabled", lambda: False)
    app = make_app(BROKER_FIPS_MODE="true")
    with pytest.raises(RuntimeError, match="not operating in FIPS mode"):
        with TestClient(app):
            pass


def test_fips_mode_boots_on_fips_provider_and_reports(make_app, monkeypatch):
    import app.fips as fips

    monkeypatch.setattr(fips, "_openssl_fips_enabled", lambda: True)
    app = make_app(BROKER_FIPS_MODE="true")
    with TestClient(app) as c:
        body = c.get("/readyz").json()
        assert body["fips"] == "ok"
        assert body["database"] == "ok"

        # A provider regression after boot flips readiness to 503.
        monkeypatch.setattr(fips, "_openssl_fips_enabled", lambda: False)
        resp = c.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["fips"] == "unavailable"


def test_fips_off_by_default(client):
    body = client.get("/readyz").json()
    assert "fips" not in body


def test_status_shape():
    from app.fips import status

    s = status(True)
    assert set(s) == {"fips_mode", "openssl_fips", "openssl"}
    assert s["fips_mode"] is True
