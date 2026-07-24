"""Signing-key rotation: JWKS continuity, permissions, retention pruning."""

from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet


def _mint(client):
    client.post("/v1/users", json={"email": "owner@example.com"})
    agent = client.post(
        "/v1/agents",
        json={"name": "rot-agent", "owner_email": "owner@example.com", "allowed_scopes": ["a:b"]},
    ).json()
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def test_rotation_keeps_old_tokens_valid(admin):
    token_before = _mint(admin)
    kid_before = admin.get("/v1/keys").json()["keys"][0]["kid"]

    rotated = admin.post("/v1/keys/rotate")
    assert rotated.status_code == 200, rotated.text
    body = rotated.json()
    assert body["active_kid"] != kid_before
    assert len(body["keyrings"]["default"]) == 2  # new active + retained old key

    # JWKS serves both keys: old tokens verify, new tokens use the new kid.
    jwks = admin.get("/.well-known/jwks.json").json()
    assert {k["kid"] for k in jwks["keys"]} == {body["active_kid"], kid_before}
    key_set = KeySet.import_key_set(jwks)
    jwt.decode(token_before, key_set)  # would raise if the old key vanished

    token_after = _mint_second(admin)
    claims_header_kid = jwt.decode(token_after, key_set)  # verifies against set
    assert claims_header_kid

    # Rotation is audited.
    events = admin.get("/v1/audit", params={"event": "key.rotated"}).json()
    assert any(e["detail"]["new_kid"] == body["active_kid"] for e in events)


def _mint_second(client):
    agent = client.post(
        "/v1/agents",
        json={"name": "rot-agent-2", "owner_email": "owner@example.com", "allowed_scopes": ["a:b"]},
    ).json()
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        },
    ).json()["access_token"]


def test_retention_prunes_retired_keys(make_app):
    app = make_app(BROKER_KEY_RETENTION_SECONDS="0")  # prune everything not active
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        first_kid = c.get("/v1/keys").json()["keys"][0]["kid"]
        c.post("/v1/keys/rotate")
        kids = [k["kid"] for k in c.get("/v1/keys").json()["keys"]]
        assert first_kid not in kids  # zero retention: old key dropped
        assert len(kids) == 1


def test_rotation_requires_permission(login):
    c, _ = login("pleb@example.com")  # agent-manager
    assert c.post("/v1/keys/rotate").status_code == 403
    assert c.get("/v1/keys").status_code == 403


def test_file_keystore_rotation_survives_restart(make_app, tmp_path):
    app = make_app()
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        c.post("/v1/keys/rotate")
        kids_before = {k["kid"] for k in c.get("/v1/keys").json()["keys"]}
        assert len(kids_before) == 2

    # "Restart": rebuild the provider from disk.
    from app.keys import reset_key_cache
    from app.keystore import get_provider

    reset_key_cache()
    kids_after = {k["kid"] for k in get_provider().keys_info()}
    assert kids_after == kids_before


def test_vault_keystore_rotation(make_app, monkeypatch):
    store: dict = {}
    import app.keystore.vault as vault_module

    monkeypatch.setattr(vault_module, "_get", lambda keyring="default": store.get(f"doc-{keyring}"))
    monkeypatch.setattr(
        vault_module, "_put", lambda doc, keyring="default": store.__setitem__(f"doc-{keyring}", doc)
    )

    app = make_app(
        BROKER_KEYSTORE="vault",
        BROKER_VAULT_ADDR="http://vault.test:8200",
        BROKER_VAULT_TOKEN="t",
    )
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        c.post("/v1/keys/rotate")
        assert len(store["doc-default"]["keys"]) == 2  # both keys persisted to Vault
        assert len(c.get("/.well-known/jwks.json").json()["keys"]) == 2


def test_metrics_exposes_audit_counters(admin):
    _mint(admin)
    metrics = admin.get("/metrics").text
    assert 'cipherlatch_audit_events_total{event="token.issued"}' in metrics
    assert "cipherlatch_http_request_duration_seconds" in metrics
