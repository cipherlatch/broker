"""private_key_jwt (RFC 7523) client auth and DPoP (RFC 9449) binding."""

import time

from joserfc import jwt
from joserfc.jwk import ECKey


def _agent(admin, name="pk"):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    return admin.post(
        "/v1/agents",
        json={"name": name, "owner_email": "owner@example.com", "allowed_scopes": ["s:x"]},
    ).json()


# --- private_key_jwt ---------------------------------------------------------

def test_private_key_jwt_auth(admin):
    agent = _agent(admin)
    key = ECKey.generate_key("P-256", private=True)
    pub = key.as_dict(private=False)

    # Register the public key.
    resp = admin.put(f"/v1/agents/{agent['id']}/auth-key", json={"jwk": pub})
    assert resp.status_code == 200

    # Authenticate with a signed assertion instead of the client secret.
    now = int(time.time())
    assertion = jwt.encode(
        {"alg": "ES256"},
        {"iss": agent["client_id"], "sub": agent["client_id"],
         "aud": "http://testserver/oauth/token", "iat": now, "exp": now + 60},
        key,
    )
    tok = admin.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        },
    )
    assert tok.status_code == 200, tok.text
    assert tok.json()["access_token"]


def test_private_key_jwt_wrong_key_rejected(admin):
    agent = _agent(admin)
    good = ECKey.generate_key("P-256", private=True)
    admin.put(f"/v1/agents/{agent['id']}/auth-key", json={"jwk": good.as_dict(private=False)})

    attacker = ECKey.generate_key("P-256", private=True)
    now = int(time.time())
    assertion = jwt.encode(
        {"alg": "ES256"},
        {"iss": agent["client_id"], "sub": agent["client_id"],
         "aud": "http://testserver/oauth/token", "iat": now, "exp": now + 60},
        attacker,  # signed by the wrong key
    )
    tok = admin.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_assertion": assertion},
    )
    assert tok.status_code == 401


def test_private_key_only_accepts_public_jwk(admin):
    agent = _agent(admin)
    priv = ECKey.generate_key("P-256", private=True).as_dict(private=True)  # has 'd'
    resp = admin.put(f"/v1/agents/{agent['id']}/auth-key", json={"jwk": priv})
    assert resp.status_code == 422


# --- DPoP --------------------------------------------------------------------

def _dpop_proof(key, method, url, iat=None, jti=None):
    import secrets as _secrets

    pub = key.as_dict(private=False)
    return jwt.encode(
        {"alg": "ES256", "typ": "dpop+jwt", "jwk": pub},
        {"htm": method, "htu": url, "iat": iat or int(time.time()),
         "jti": _secrets.token_urlsafe(8) if jti is None else jti},
        key,
    )


def _mint_dpop(client, agent, key):
    proof = _dpop_proof(key, "POST", "http://testserver/oauth/token")
    return client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
        headers={"DPoP": proof},
    )


def _bootstrap_route(admin, agent):
    admin.post("/v1/credentials",
               json={"name": "c", "secret": "UPSTREAM", "owner_email": "owner@example.com"})
    r = admin.post("/v1/routes", json={
        "slug": "svc", "upstream_base": "http://127.0.0.1:59999", "credential_name": "c",
        "owner_email": "owner@example.com", "allowed_methods": ["GET"]}).json()
    admin.post(f"/v1/routes/{r['id']}/grants/{agent['id']}")
    return r


def test_dpop_binds_token_and_gateway_requires_matching_proof(admin):
    agent = _agent(admin)
    _bootstrap_route(admin, agent)
    key = ECKey.generate_key("P-256", private=True)

    resp = _mint_dpop(admin, agent, key)
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "DPoP"
    token = resp.json()["access_token"]

    # A plain Bearer presentation of a DPoP-bound token is refused...
    r1 = admin.get("/gw/svc/x", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code in (401, 403)

    # ...and a DPoP proof from a *different* key is refused...
    other = ECKey.generate_key("P-256", private=True)
    r2 = admin.get("/gw/svc/x", headers={
        "Authorization": f"DPoP {token}",
        "DPoP": _dpop_proof(other, "GET", "http://testserver/gw/svc/x")})
    assert r2.status_code in (401, 403)

    # ...but a fresh proof from the bound key is accepted (upstream unreachable
    # -> 502, which still proves auth + DPoP binding passed).
    r3 = admin.get("/gw/svc/x", headers={
        "Authorization": f"DPoP {token}",
        "DPoP": _dpop_proof(key, "GET", "http://testserver/gw/svc/x")})
    assert r3.status_code == 502


def test_dpop_stale_proof_rejected(admin):
    agent = _agent(admin)
    key = ECKey.generate_key("P-256", private=True)
    old = _dpop_proof(key, "POST", "http://testserver/oauth/token", iat=int(time.time()) - 9999)
    resp = admin.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
        headers={"DPoP": old},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_dpop_proof"


def test_dpop_proof_replay_rejected(admin):
    """A DPoP proof is single-use: replaying the same jti within its freshness
    window is refused (RFC 9449 §11.1)."""
    from app.proof import reset_seen_jti

    reset_seen_jti()
    agent = _agent(admin)
    key = ECKey.generate_key("P-256", private=True)
    proof = _dpop_proof(key, "POST", "http://testserver/oauth/token", jti="fixed-jti")
    data = {"grant_type": "client_credentials", "client_id": agent["client_id"],
            "client_secret": agent["client_secret"]}

    first = admin.post("/oauth/token", data=data, headers={"DPoP": proof})
    assert first.status_code == 200, first.text
    # Same proof again -> replay rejected.
    second = admin.post("/oauth/token", data=data, headers={"DPoP": proof})
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_dpop_proof"


def test_dpop_proof_missing_jti_rejected(admin):
    from app.proof import reset_seen_jti

    reset_seen_jti()
    agent = _agent(admin)
    key = ECKey.generate_key("P-256", private=True)
    # Proof with an explicit empty jti is not RFC-compliant -> rejected.
    proof = _dpop_proof(key, "POST", "http://testserver/oauth/token", jti="")
    resp = admin.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": agent["client_id"],
              "client_secret": agent["client_secret"]},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_dpop_proof"


def test_exchange_of_dpop_bound_subject_token_requires_proof(admin):
    """A DPoP-bound subject token can't be exchanged for a downstream
    credential without proving possession of the binding key."""
    from app.proof import reset_seen_jti

    reset_seen_jti()
    agent = _agent(admin)
    admin.post("/v1/credentials",
               json={"name": "svc-cred", "secret": "UPSTREAM", "owner_email": "owner@example.com"})
    # (grant the agent access to the credential)
    creds = admin.get("/v1/credentials").json()
    cid = next(c["id"] for c in creds if c["name"] == "svc-cred")
    admin.post(f"/v1/credentials/{cid}/grants/{agent['id']}")

    key = ECKey.generate_key("P-256", private=True)
    token = _mint_dpop(admin, agent, key).json()["access_token"]

    exch = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agent["client_id"], "client_secret": agent["client_secret"],
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "svc-cred"}

    # No DPoP proof on the exchange -> refused.
    r1 = admin.post("/oauth/token", data=exch)
    assert r1.status_code == 400

    # Fresh proof from the bound key -> credential released.
    proof = _dpop_proof(key, "POST", "http://testserver/oauth/token")
    r2 = admin.post("/oauth/token", data=exch, headers={"DPoP": proof})
    assert r2.status_code == 200, r2.text
    assert r2.json()["access_token"] == "UPSTREAM"
