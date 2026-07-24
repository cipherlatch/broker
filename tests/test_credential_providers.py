"""Dynamic credential providers: the ssh-ca provider mints real OpenSSH
certificates at RFC 8693 exchange, scoped to the agent, signed by the stored
CA seed — and the guards (validation at create, injectability, param
required, static creds unaffected)."""

import time

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)
from cryptography.hazmat.primitives.serialization.ssh import load_ssh_public_identity
from fastapi.testclient import TestClient

TOKEN_TYPE_SSH = "urn:cipherlatch:params:oauth:token-type:ssh-certificate"


def _ca_seed() -> str:
    ca = ed25519.Ed25519PrivateKey.generate()
    return ca.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode()


def _agent_keypair():
    key = ed25519.Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    return key, pub


def _setup(admin, provider_config=None, seed=None):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post("/v1/agents", json={
        "name": "ssh-agent", "owner_email": "owner@example.com", "allowed_scopes": ["a:b"],
    }).json()
    body = {"name": "prod-ssh", "secret": seed or _ca_seed(),
            "owner_email": "owner@example.com", "provider": "ssh-ca"}
    if provider_config is not None:
        body["provider_config"] = provider_config
    cred = admin.post("/v1/credentials", json=body)
    assert cred.status_code == 201, cred.text
    admin.post(f"/v1/credentials/{cred.json()['id']}/grants/{agent['id']}")
    return agent


def _cipherlatch_token(admin, agent):
    return admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
    }).json()["access_token"]


def _exchange(admin, agent, cipherlatch_token, public_key):
    return admin.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
        "subject_token": cipherlatch_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "prod-ssh", "public_key": public_key,
    })


def test_ssh_ca_issues_scoped_certificate(admin):
    seed = _ca_seed()
    agent = _setup(admin, provider_config={"principals": ["agent-{name}", "deploy"],
                                           "ttl": 120}, seed=seed)
    _, agent_pub = _agent_keypair()
    tok = _cipherlatch_token(admin, agent)
    resp = _exchange(admin, agent, tok, agent_pub)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issued_token_type"] == TOKEN_TYPE_SSH
    assert body["expires_in"] == 120
    assert body["token_type"] == "N_A"

    cert = load_ssh_public_identity(body["access_token"].encode())
    assert [p.decode() for p in cert.valid_principals] == ["agent-ssh-agent", "deploy"]
    assert cert.key_id.decode() == f"cipherlatch:agent:{agent['id']}:owner:owner@example.com:jti:" + \
        _jti(tok)
    assert cert.valid_before - cert.valid_after == 120 + 30  # ttl + skew backdate

    # Signed by the configured CA (not some other key).
    from cryptography.hazmat.primitives.serialization import ssh
    ca_pub = ssh.load_ssh_private_key(seed.encode(), None).public_key().public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH)
    sig_pub = cert.signature_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    assert sig_pub == ca_pub


def _jti(cipherlatch_token: str) -> str:
    import base64
    import json
    payload = cipherlatch_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["jti"]


def test_default_config_and_ecdsa_ca(admin):
    ca = ec.generate_private_key(ec.SECP256R1())
    seed = ca.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode()
    agent = _setup(admin, seed=seed)  # no provider_config -> defaults
    _, agent_pub = _agent_keypair()
    resp = _exchange(admin, agent, _cipherlatch_token(admin, agent), agent_pub)
    assert resp.status_code == 200, resp.text
    cert = load_ssh_public_identity(resp.json()["access_token"].encode())
    assert [p.decode() for p in cert.valid_principals] == ["agent-ssh-agent"]  # default
    assert resp.json()["expires_in"] == 300  # default ttl


def test_public_key_required(admin):
    agent = _setup(admin)
    resp = _exchange(admin, agent, _cipherlatch_token(admin, agent), "")
    assert resp.status_code == 400
    assert "public_key" in resp.json()["error_description"]


def test_bad_public_key_rejected(admin):
    agent = _setup(admin)
    resp = _exchange(admin, agent, _cipherlatch_token(admin, agent), "not-a-key")
    assert resp.status_code == 400
    assert "public key" in resp.json()["error_description"].lower()


def test_invalid_seed_rejected_at_create(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post("/v1/credentials", json={
        "name": "bad-ca", "secret": "not-a-ca-key",
        "owner_email": "owner@example.com", "provider": "ssh-ca",
    })
    assert resp.status_code == 422
    assert "seed" in resp.json()["detail"].lower()


def test_bad_config_rejected_at_create(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    for cfg, needle in [
        ({"ttl": 99999}, "ttl"),
        ({"extensions": ["permit-pty", "hack-the-planet"]}, "extensions"),
        ({"principals": []}, "principals"),
    ]:
        resp = admin.post("/v1/credentials", json={
            "name": f"bad-{needle}", "secret": _ca_seed(),
            "owner_email": "owner@example.com", "provider": "ssh-ca",
            "provider_config": cfg,
        })
        assert resp.status_code == 422, (cfg, resp.text)
        assert needle in resp.json()["detail"].lower()


def test_unknown_provider_rejected(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    resp = admin.post("/v1/credentials", json={
        "name": "nope", "secret": "x", "owner_email": "owner@example.com",
        "provider": "quantum-teleporter",
    })
    assert resp.status_code == 422


def test_provider_credential_cannot_bind_gateway_route(admin):
    _setup(admin)  # creates prod-ssh (ssh-ca)
    resp = admin.post("/v1/routes", json={
        "slug": "ssh-route", "upstream_base": "http://x.test",
        "credential_name": "prod-ssh", "owner_email": "owner@example.com",
        "allowed_methods": ["GET"],
    })
    assert resp.status_code == 422
    assert "gateway" in resp.json()["detail"].lower()


def test_static_credentials_unaffected(admin):
    """A plain (provider=None) credential exchanges exactly as before."""
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post("/v1/agents", json={
        "name": "static-agent", "owner_email": "owner@example.com", "allowed_scopes": ["a:b"],
    }).json()
    cred = admin.post("/v1/credentials", json={
        "name": "ha-token", "secret": "long-lived-secret", "owner_email": "owner@example.com",
    }).json()
    assert admin.get("/v1/credentials").json()  # provider field present, None
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")
    resp = _exchange_named(admin, agent, _cipherlatch_token(admin, agent), "ha-token")
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "long-lived-secret"
    assert resp.json()["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"


def _exchange_named(admin, agent, cipherlatch_token, audience):
    return admin.post("/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent["client_id"], "client_secret": agent["client_secret"],
        "subject_token": cipherlatch_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": audience,
    })
