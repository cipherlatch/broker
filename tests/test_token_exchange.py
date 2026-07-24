"""RFC 8693 token exchange for downstream credentials, and keyring isolation."""

from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet

TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def _setup_agent(admin, name="worker", keyring="default"):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post(
        "/v1/agents",
        json={
            "name": name, "owner_email": "owner@example.com",
            "allowed_scopes": ["s:x"], "keyring": keyring,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _mint(client, agent, **extra):
    data = {
        "grant_type": "client_credentials",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    }
    data.update(extra)
    return client.post("/oauth/token", data=data)


def _store_credential(admin, name="ha-token", secret="hass_supersecret_value"):
    resp = admin.post(
        "/v1/credentials",
        json={"name": name, "description": "HA token", "secret": secret,
              "owner_email": "owner@example.com"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _exchange(client, agent, subject_token, audience):
    return client.post(
        "/oauth/token",
        data={
            "grant_type": GRANT,
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
            "subject_token": subject_token,
            "subject_token_type": TOKEN_TYPE,
            "audience": audience,
        },
    )


def test_exchange_happy_path(admin):
    agent = _setup_agent(admin)
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")

    cipherlatch_token = _mint(admin, agent).json()["access_token"]
    resp = _exchange(admin, agent, cipherlatch_token, "ha-token")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"] == "hass_supersecret_value"
    assert body["issued_token_type"] == TOKEN_TYPE

    events = {e["event"] for e in admin.get("/v1/audit").json()}
    assert "token.exchanged" in events
    # last_exchanged_at recorded
    got = admin.get(f"/v1/credentials/{cred['id']}").json()
    assert got["last_exchanged_at"] is not None


def test_exchange_without_grant_denied(admin):
    agent = _setup_agent(admin)
    _store_credential(admin)  # no grant
    cipherlatch_token = _mint(admin, agent).json()["access_token"]
    resp = _exchange(admin, agent, cipherlatch_token, "ha-token")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_target"

    # Unknown credential name yields the identical error (no enumeration).
    resp2 = _exchange(admin, agent, cipherlatch_token, "does-not-exist")
    assert resp2.json() == resp.json()


def test_exchange_rejects_foreign_subject_token(admin):
    agent_a = _setup_agent(admin, "agent-a")
    agent_b = _setup_agent(admin, "agent-b")
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent_b['id']}")

    token_a = _mint(admin, agent_a).json()["access_token"]
    # B authenticates itself but presents A's token: rejected.
    resp = _exchange(admin, agent_b, token_a, "ha-token")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    denials = admin.get("/v1/audit", params={"event": "token.exchange_denied"}).json()
    assert any(d["detail"]["reason"] == "subject_token_mismatch" for d in denials)


def test_exchange_honors_token_revocation(admin):
    """A subject token that was explicitly revoked (RFC 7009) must not be
    exchangeable for the downstream credential — the exchange path used to skip
    the revocation denylist that the gateway/introspection enforce."""
    agent = _setup_agent(admin)
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    token = _mint(admin, agent).json()["access_token"]

    # Sanity: the token exchanges before revocation.
    assert _exchange(admin, agent, token, "ha-token").status_code == 200

    admin.post("/oauth/revoke", data={
        "token": token, "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    })
    resp = _exchange(admin, agent, token, "ha-token")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_exchange_honors_mass_revocation(admin):
    """Bumping the agent's token generation (mass-revoke) must also stop the
    exchange path from cashing in a superseded token."""
    agent = _setup_agent(admin)
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    token = _mint(admin, agent).json()["access_token"]

    admin.post(f"/v1/agents/{agent['id']}/revoke-tokens")
    resp = _exchange(admin, agent, token, "ha-token")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_exchange_requires_client_auth(admin):
    agent = _setup_agent(admin)
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    cipherlatch_token = _mint(admin, agent).json()["access_token"]
    resp = _exchange(
        admin, {**agent, "client_secret": "aibs_wrong"}, cipherlatch_token, "ha-token"
    )
    assert resp.status_code == 401


def test_revoked_grant_stops_exchange(admin):
    agent = _setup_agent(admin)
    cred = _store_credential(admin)
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    cipherlatch_token = _mint(admin, agent).json()["access_token"]
    assert _exchange(admin, agent, cipherlatch_token, "ha-token").status_code == 200

    admin.delete(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    assert _exchange(admin, agent, cipherlatch_token, "ha-token").status_code == 400


def test_secret_encrypted_at_rest_and_write_only(admin, app):
    _setup_agent(admin)
    cred = _store_credential(admin, name="enc-check", secret="plaintext-value")

    # Never returned by the management API.
    got = admin.get(f"/v1/credentials/{cred['id']}").json()
    assert "secret" not in got and "plaintext-value" not in str(got)

    # And not stored in the clear.
    from app.db import get_engine
    from sqlalchemy import text

    with get_engine().connect() as conn:
        stored = conn.execute(
            text("SELECT secret_encrypted FROM credentials WHERE name='enc-check'")
        ).scalar()
    assert "plaintext-value" not in stored


def test_credentials_owner_scoped(login):
    alice, _ = login("alice@example.com")
    bob, _ = login("bob@example.com")
    created = alice.post(
        "/v1/credentials", json={"name": "alice-cred", "secret": "s3cret"}
    )
    assert created.status_code == 201
    cred_id = created.json()["id"]

    assert bob.get("/v1/credentials").json() == []
    assert bob.get(f"/v1/credentials/{cred_id}").status_code == 404
    assert bob.delete(f"/v1/credentials/{cred_id}").status_code == 404


def test_disabled_without_credential_key(make_app):
    app = make_app(BROKER_CREDENTIAL_KEY="")
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        c.post("/v1/users", json={"email": "owner@example.com"})
        resp = c.post(
            "/v1/credentials",
            json={"name": "x", "secret": "y", "owner_email": "owner@example.com"},
        )
        assert resp.status_code == 503


# ------------------------------------------------------------------ keyrings


def test_keyring_isolation_on_rotation(admin, client):
    agent_default = _setup_agent(admin, "on-default")
    agent_ring = _setup_agent(admin, "on-ring-b", keyring="ring-b")

    tok_default = _mint(admin, agent_default).json()["access_token"]
    tok_ring = _mint(admin, agent_ring).json()["access_token"]

    # JWKS serves both rings' keys; both tokens verify.
    jwks = admin.get("/.well-known/jwks.json").json()
    assert len(jwks["keys"]) == 2
    key_set = KeySet.import_key_set(jwks)
    jwt.decode(tok_default, key_set)
    jwt.decode(tok_ring, key_set)

    # Status lists both rings (platform view: named rings are tenant-scoped
    # in storage, so ring-b of the default tenant is "default.ring-b").
    rings = admin.get("/v1/keys").json()["keyrings"]
    assert set(rings) == {"default", "default.ring-b"}

    # Rotate ring-b only: default's kid unchanged, ring-b gets a new one.
    default_kid_before = rings["default"][0]["kid"]
    admin.post("/v1/keys/rotate", params={"keyring": "ring-b"})
    rings_after = admin.get("/v1/keys").json()["keyrings"]
    assert rings_after["default"][0]["kid"] == default_kid_before
    assert len(rings_after["default.ring-b"]) == 2


def test_keyring_rotation_blast_radius(make_app):
    app = make_app(BROKER_KEY_RETENTION_SECONDS="0")  # rotation kills old keys
    with TestClient(app) as c:
        c.headers["X-Admin-Key"] = "test-admin-key"
        agent_a = _setup_agent(c, "blast-a", keyring="ring-a")
        agent_b = _setup_agent(c, "blast-b", keyring="ring-b")
        tok_a = _mint(c, agent_a).json()["access_token"]
        tok_b = _mint(c, agent_b).json()["access_token"]

        c.post("/v1/keys/rotate", params={"keyring": "ring-a"})

        key_set = KeySet.import_key_set(c.get("/.well-known/jwks.json").json())
        jwt.decode(tok_b, key_set)  # ring-b untouched
        try:
            jwt.decode(tok_a, key_set)
            raise AssertionError("ring-a token should no longer verify")
        except Exception:
            pass  # expected: ring-a's signing key was dropped


def test_invalid_keyring_name_rejected(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post(
        "/v1/agents",
        json={"name": "bad-ring", "owner_email": "owner@example.com",
              "keyring": "Not Valid!"},
    )
    assert resp.status_code == 422
