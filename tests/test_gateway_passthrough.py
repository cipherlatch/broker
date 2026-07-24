"""Ephemeral-credential passthrough (credential lineage): the gateway witnesses
short-lived credentials minted inside brokered responses and relays follow-up
requests bearing them on the route's passthrough prefixes — attributed to the
minting agent, never an open relay. The pattern that unblocks Cloudflare Pages
direct upload, registry token auth, and similar two-auth-domain flows without
giving the client a network path around the gateway."""

import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# Long enough to clear lineage.MIN_TOKEN_LENGTH.
EPHEMERAL = "ephemeral-upload-jwt-token-1234567890"


class _Upstream(BaseHTTPRequestHandler):
    received: list = []

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        _Upstream.received.append({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": body.decode() or None,
        })
        if self.path.startswith("/accounts/") and self.path.endswith("/upload-token"):
            # Mint an ephemeral credential, wrapped the way real APIs wrap them.
            payload = json.dumps({"success": True, "result": {"jwt": EPHEMERAL}}).encode()
        else:
            payload = b'{"upstream":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


@pytest.fixture()
def upstream():
    _Upstream.received = []
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", _Upstream.received
    server.shutdown()


PASSTHROUGH = {
    "prefixes": ["/pages/assets/"],
    "capture": {"prefixes": ["/accounts/"], "fields": ["jwt"]},
    "ttl_seconds": 300,
}


def _bootstrap(admin, upstream_base, passthrough=PASSTHROUGH):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post("/v1/agents", json={
        "name": "pt-agent", "owner_email": "owner@example.com",
    }).json()
    admin.post("/v1/credentials", json={
        "name": "pt-cred", "secret": "ACCOUNT-TOKEN", "owner_email": "owner@example.com",
    })
    route = admin.post("/v1/routes", json={
        "slug": "cf", "upstream_base": upstream_base, "credential_name": "pt-cred",
        "owner_email": "owner@example.com",
        "allowed_methods": ["GET", "POST"],
        "passthrough": passthrough,
    })
    assert route.status_code == 201, route.text
    admin.post(f"/v1/routes/{route.json()['id']}/grants/{agent['id']}")
    return agent, route.json()


def _mint(client, agent):
    return client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    }).json()["access_token"]


def test_witness_then_passthrough(admin, upstream):
    base, received = upstream
    agent, _ = _bootstrap(admin, base)
    token = _mint(admin, agent)

    # 1. Brokered call mints the ephemeral credential — witnessed by the gateway.
    resp = admin.get("/gw/cf/accounts/a1/upload-token",
                     headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["result"]["jwt"] == EPHEMERAL
    assert received[-1]["authorization"] == "Bearer ACCOUNT-TOKEN"  # injected

    # 2. Follow-up authenticates with the ephemeral credential — relayed, not injected.
    resp = admin.post("/gw/cf/pages/assets/check-missing",
                      headers={"Authorization": f"Bearer {EPHEMERAL}"},
                      json={"hashes": ["h1"]})
    assert resp.status_code == 200
    assert received[-1]["authorization"] == f"Bearer {EPHEMERAL}"
    assert received[-1]["path"] == "/pages/assets/check-missing"


def test_unwitnessed_credential_denied(admin, upstream):
    base, _ = upstream
    _bootstrap(admin, base)
    resp = admin.post("/gw/cf/pages/assets/check-missing",
                      headers={"Authorization": "Bearer never-witnessed-token-abcdefgh"})
    assert resp.status_code == 401


def test_witnessed_credential_confined_to_passthrough_prefixes(admin, upstream):
    base, received = upstream
    agent, _ = _bootstrap(admin, base)
    token = _mint(admin, agent)
    admin.get("/gw/cf/accounts/a1/upload-token", headers={"Authorization": f"Bearer {token}"})

    # The witnessed credential is NOT an agent token: outside the passthrough
    # prefixes it authenticates nothing.
    resp = admin.get("/gw/cf/accounts/a1/secrets",
                     headers={"Authorization": f"Bearer {EPHEMERAL}"})
    assert resp.status_code == 401


def test_expired_witness_denied(admin, upstream):
    base, _ = upstream
    agent, _ = _bootstrap(admin, base)
    token = _mint(admin, agent)
    admin.get("/gw/cf/accounts/a1/upload-token", headers={"Authorization": f"Bearer {token}"})

    # Force-expire the witness row.
    from sqlalchemy.orm import Session

    from app.db import get_engine
    from app.models import WitnessedCredential, _now

    with Session(get_engine()) as db:
        for w in db.query(WitnessedCredential).all():
            w.expires_at = _now() - timedelta(seconds=1)
        db.commit()

    resp = admin.post("/gw/cf/pages/assets/upload",
                      headers={"Authorization": f"Bearer {EPHEMERAL}"})
    assert resp.status_code == 401


def test_passthrough_still_bound_by_route_policy(admin, upstream):
    """Method/path policy applies to relayed requests too."""
    base, _ = upstream
    agent, _ = _bootstrap(admin, base)
    token = _mint(admin, agent)
    admin.get("/gw/cf/accounts/a1/upload-token", headers={"Authorization": f"Bearer {token}"})

    resp = admin.request("DELETE", "/gw/cf/pages/assets/x",
                         headers={"Authorization": f"Bearer {EPHEMERAL}"})
    assert resp.status_code == 403  # DELETE not in allowed_methods


def test_passthrough_audited_with_agent_attribution(admin, upstream):
    base, _ = upstream
    agent, _ = _bootstrap(admin, base)
    token = _mint(admin, agent)
    admin.get("/gw/cf/accounts/a1/upload-token", headers={"Authorization": f"Bearer {token}"})
    admin.post("/gw/cf/pages/assets/upload", headers={"Authorization": f"Bearer {EPHEMERAL}"})

    from sqlalchemy.orm import Session

    from app.db import get_engine
    from app.models import AuditEvent

    with Session(get_engine()) as db:
        witnessed = [e for e in db.query(AuditEvent).all()
                     if e.event == "gateway.credential_witnessed"]
        relayed = [e for e in db.query(AuditEvent).all()
                   if e.event == "gateway.proxied" and e.detail.get("passthrough")]
    assert witnessed and witnessed[-1].agent_id == agent["id"]
    assert witnessed[-1].detail["count"] == 1
    assert relayed and relayed[-1].agent_id == agent["id"]  # attributed to the minter
    # The credential value itself is never in the audit log.
    assert EPHEMERAL not in json.dumps(witnessed[-1].detail)


def test_no_capture_outside_capture_prefixes(admin, upstream):
    base, _ = upstream
    agent, _ = _bootstrap(admin, base, passthrough={
        "prefixes": ["/pages/assets/"],
        "capture": {"prefixes": ["/never-matches/"], "fields": ["jwt"]},
        "ttl_seconds": 300,
    })
    token = _mint(admin, agent)
    admin.get("/gw/cf/accounts/a1/upload-token", headers={"Authorization": f"Bearer {token}"})
    # Minted outside the capture prefix -> never witnessed -> relay refused.
    resp = admin.post("/gw/cf/pages/assets/upload",
                      headers={"Authorization": f"Bearer {EPHEMERAL}"})
    assert resp.status_code == 401


def test_passthrough_config_validation(admin, upstream):
    base, _ = upstream
    admin.post("/v1/users", json={"email": "owner@example.com"})
    admin.post("/v1/credentials", json={
        "name": "v-cred", "secret": "s", "owner_email": "owner@example.com",
    })

    def create(pt):
        return admin.post("/v1/routes", json={
            "slug": "vroute", "upstream_base": base, "credential_name": "v-cred",
            "owner_email": "owner@example.com", "passthrough": pt,
        })

    assert create({"prefixes": []}).status_code == 422           # empty prefixes
    assert create({"prefixes": ["/a/"]}).status_code == 422      # capture required
    assert create({"prefixes": ["/a/"], "capture": {"prefixes": ["/b/"]},
                   "ttl_seconds": 5}).status_code == 422          # ttl too low
    assert create({"prefixes": ["/a/"], "capture": {"prefixes": ["/b/"]},
                   "bogus": 1}).status_code == 422                # unknown key
    ok = create({"prefixes": ["/a/"], "capture": {"prefixes": ["/b/"]}})
    assert ok.status_code == 201, ok.text
    assert ok.json()["passthrough"]["ttl_seconds"] == 1800        # default applied
    assert ok.json()["passthrough"]["capture"]["fields"] == ["jwt"]

    # Update clears with {}.
    rid = ok.json()["id"]
    cleared = admin.patch(f"/v1/routes/{rid}", json={"passthrough": {}})
    assert cleared.status_code == 200
    assert cleared.json()["passthrough"] is None
