"""Keystore backends and readiness probe. Enterprise backends (jks, pkcs11,
cloud KMS) are tested in the cipherlatch-enterprise repo alongside their code."""

import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet


def _mint_and_verify(client):
    client.headers["X-Admin-Key"] = "test-admin-key"
    client.post("/v1/users", json={"email": "owner@example.com"})
    agent = client.post(
        "/v1/agents",
        json={"name": "ks-agent", "owner_email": "owner@example.com", "allowed_scopes": ["a:b"]},
    ).json()
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        },
    )
    assert resp.status_code == 200, resp.text
    jwks = client.get("/.well-known/jwks.json").json()
    claims = jwt.decode(resp.json()["access_token"], KeySet.import_key_set(jwks)).claims
    assert claims["client_id"] == agent["client_id"]
    return jwks


def test_readyz(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"database": "ok", "keystore": "ok"}


def test_vault_keystore_roundtrip(make_app, monkeypatch):
    store: dict[str, str] = {}

    import app.keystore.vault as vault_module

    monkeypatch.setattr(vault_module, "_get", lambda keyring="default": store.get("doc"))
    monkeypatch.setattr(
        vault_module, "_put", lambda doc, keyring="default": store.__setitem__("doc", doc)
    )

    app = make_app(
        BROKER_KEYSTORE="vault",
        BROKER_VAULT_ADDR="http://vault.test:8200",
        BROKER_VAULT_TOKEN="test-token",
    )
    with TestClient(app) as c:
        jwks1 = _mint_and_verify(c)
    assert "doc" in store  # key was generated into Vault

    # A second replica against the same Vault sees the same key.
    from app.keys import reset_key_cache

    reset_key_cache()
    app2 = make_app(
        BROKER_KEYSTORE="vault",
        BROKER_VAULT_ADDR="http://vault.test:8200",
        BROKER_VAULT_TOKEN="test-token",
    )
    with TestClient(app2) as c2:
        jwks2 = c2.get("/.well-known/jwks.json").json()
    assert jwks1["keys"][0]["kid"] == jwks2["keys"][0]["kid"]


def test_unknown_keystore_names_plugin_packages(make_app):
    """A backend name that is neither built in nor plugin-provided fails with
    a message that points at the plugin mechanism."""
    make_app(BROKER_KEYSTORE="no-such-backend")
    from app.keystore import get_provider

    with pytest.raises(ValueError, match="cipherlatch-enterprise"):
        get_provider()
