"""Downstream-credential encryption backends: local Fernet and vault-transit."""

import base64

from fastapi.testclient import TestClient


def _fake_transit(monkeypatch):
    """Simulate Vault transit: a `vault:v1:<b64>` envelope the broker treats
    as opaque. The point under test is routing + at-rest shape, not Vault's
    crypto."""
    import app.secretbox as sb

    def enc(plaintext: str) -> str:
        return "vault:v1:" + base64.b64encode(plaintext.encode()).decode()

    def dec(ciphertext: str) -> str:
        return base64.b64decode(ciphertext[len("vault:v1:"):]).decode()

    monkeypatch.setattr(sb, "_transit_encrypt", enc)
    monkeypatch.setattr(sb, "_transit_decrypt", dec)


def _seed_and_exchange(c, secret="hass_secret"):
    c.headers["X-Admin-Key"] = "test-admin-key"
    c.post("/v1/users", json={"email": "owner@example.com"})
    agent = c.post(
        "/v1/agents",
        json={"name": "w", "owner_email": "owner@example.com", "allowed_scopes": ["s:x"]},
    ).json()
    cred = c.post(
        "/v1/credentials",
        json={"name": "ha-token", "secret": secret, "owner_email": "owner@example.com"},
    ).json()
    c.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    tok = c.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
    ).json()["access_token"]
    exch = c.post(
        "/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agent["client_id"], "client_secret": agent["client_secret"],
            "subject_token": tok,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "ha-token",
        },
    )
    return cred, exch


def _stored_ciphertext(app, name="ha-token") -> str:
    from sqlalchemy import text

    from app.db import get_engine

    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT secret_encrypted FROM credentials WHERE name=:n"), {"n": name}
        ).scalar()


def test_vault_transit_backend(make_app, monkeypatch):
    _fake_transit(monkeypatch)
    app = make_app(
        BROKER_CREDENTIAL_BACKEND="vault-transit",
        BROKER_CREDENTIAL_KEY="",  # not used by this backend
        BROKER_VAULT_ADDR="http://vault.test:8200",
        BROKER_VAULT_TOKEN="t",
    )
    with TestClient(app) as c:
        cred, exch = _seed_and_exchange(c, secret="hass_secret")
        assert exch.status_code == 200, exch.text
        assert exch.json()["access_token"] == "hass_secret"

    # Stored blob is the Vault envelope, not local Fernet, and not plaintext.
    stored = _stored_ciphertext(app)
    assert stored.startswith("vault:v1:")
    assert "hass_secret" not in stored


def test_vault_transit_requires_vault_config(make_app):
    app = make_app(
        BROKER_CREDENTIAL_BACKEND="vault-transit",
        BROKER_CREDENTIAL_KEY="",
        BROKER_VAULT_ADDR="",
        BROKER_VAULT_TOKEN="",
    )
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        c.post("/v1/users", json={"email": "owner@example.com"})
        resp = c.post(
            "/v1/credentials",
            json={"name": "x", "secret": "y", "owner_email": "owner@example.com"},
        )
        assert resp.status_code == 503


def test_ciphertext_shape_routes_decrypt(make_app, monkeypatch):
    """A vault: envelope decrypts via transit even when the configured backend
    is local — so a backend switch never strands previously stored secrets."""
    _fake_transit(monkeypatch)
    app = make_app(BROKER_CREDENTIAL_KEY="local-fernet-key")  # local backend
    import app.secretbox as sb

    # A blob that was written by the transit backend earlier.
    legacy = "vault:v1:" + base64.b64encode(b"old-secret").decode()
    assert sb.decrypt(legacy) == "old-secret"
    # New writes still use local Fernet (no vault: prefix).
    fresh = sb.encrypt("new-secret")
    assert not fresh.startswith("vault:")
    assert sb.decrypt(fresh) == "new-secret"
