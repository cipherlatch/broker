"""Native contextual policies (DECISIONS.md 2026-07-16): curated parameterized
controls (change_freeze, business_hours, cidr_fence), first-class CRUD with
their own permissions, attachment to routes/agents, additive-veto evaluation in
the gateway (fail-closed), and separation of duties — the controlled party
cannot weaken the control."""

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.policy_native import _evaluate_one


class _Upstream(BaseHTTPRequestHandler):
    def _handle(self):
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
    server = HTTPServer(("127.0.0.1", 0), _Upstream)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _bootstrap(admin, upstream_base):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    agent = admin.post("/v1/agents", json={
        "name": "pol-agent", "owner_email": "owner@example.com",
    }).json()
    admin.post("/v1/credentials", json={
        "name": "pol-cred", "secret": "S", "owner_email": "owner@example.com",
    })
    route = admin.post("/v1/routes", json={
        "slug": "pol", "upstream_base": upstream_base, "credential_name": "pol-cred",
        "owner_email": "owner@example.com", "allowed_methods": ["GET", "POST"],
    }).json()
    admin.post(f"/v1/routes/{route['id']}/grants/{agent['id']}")
    return agent, route


def _mint(client, agent):
    return client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    }).json()["access_token"]


def _freeze_params(active=True):
    now = datetime.now(timezone.utc)
    delta = timedelta(hours=1)
    if active:
        return {"start": (now - delta).isoformat(), "end": (now + delta).isoformat(),
                "message": "release freeze"}
    return {"start": (now + delta).isoformat(), "end": (now + 2 * delta).isoformat()}


# --- unit: evaluation semantics ----------------------------------------------


def test_business_hours_evaluation():
    params = {"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00",
              "timezone": "UTC"}
    monday_noon = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    saturday_noon = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
    monday_night = datetime(2026, 7, 20, 22, 0, tzinfo=timezone.utc)
    assert _evaluate_one("business_hours", params, ip="1.2.3.4", now=monday_noon)[0]
    assert not _evaluate_one("business_hours", params, ip="1.2.3.4", now=saturday_noon)[0]
    assert not _evaluate_one("business_hours", params, ip="1.2.3.4", now=monday_night)[0]


def test_cidr_fence_evaluation():
    params = {"allow": ["192.0.2.0/24", "100.64.0.0/10"]}
    now = datetime.now(timezone.utc)
    assert _evaluate_one("cidr_fence", params, ip="192.0.2.79", now=now)[0]
    assert _evaluate_one("cidr_fence", params, ip="100.99.1.1", now=now)[0]
    assert not _evaluate_one("cidr_fence", params, ip="8.8.8.8", now=now)[0]
    # Unparseable IP fails closed.
    assert not _evaluate_one("cidr_fence", params, ip="not-an-ip", now=now)[0]


def test_unknown_type_fails_closed():
    allowed, reason = _evaluate_one("no_such_type", {}, ip="1.2.3.4",
                                    now=datetime.now(timezone.utc))
    assert not allowed and "misconfigured" in reason


# --- API: CRUD + validation ---------------------------------------------------


def test_policy_crud_and_validation(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})

    def create(ptype, params, name="p1"):
        return admin.post("/v1/policies", json={
            "name": name, "type": ptype, "params": params,
            "owner_email": "owner@example.com",
        })

    assert create("bogus_type", {}).status_code == 422
    assert create("change_freeze", {"start": "nope", "end": "2026-01-01"}).status_code == 422
    assert create("change_freeze", {"start": "2026-01-02T00:00:00",
                                    "end": "2026-01-01T00:00:00"}).status_code == 422
    assert create("business_hours", {"days": [9], "start": "08:00", "end": "18:00"}).status_code == 422
    assert create("business_hours", {"days": [0], "start": "08:00", "end": "18:00",
                                     "timezone": "Mars/Olympus"}).status_code == 422
    assert create("cidr_fence", {"allow": ["not-a-cidr"]}).status_code == 422

    ok = create("change_freeze", _freeze_params(), name="freeze")
    assert ok.status_code == 201, ok.text
    pid = ok.json()["id"]
    assert create("change_freeze", _freeze_params(), name="freeze").status_code == 409

    upd = admin.patch(f"/v1/policies/{pid}", json={"active": False})
    assert upd.status_code == 200 and upd.json()["active"] is False

    assert admin.delete(f"/v1/policies/{pid}").status_code == 200
    assert admin.get(f"/v1/policies/{pid}").status_code == 404


# --- gateway enforcement ------------------------------------------------------


def _make_policy(admin, ptype, params, name="gw-policy"):
    resp = admin.post("/v1/policies", json={
        "name": name, "type": ptype, "params": params,
        "owner_email": "owner@example.com",
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_freeze_attached_to_route_denies(admin, upstream):
    agent, route = _bootstrap(admin, upstream)
    token = _mint(admin, agent)
    policy = _make_policy(admin, "change_freeze", _freeze_params())
    admin.post(f"/v1/policies/{policy['id']}/attachments/route/{route['id']}")

    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert "release freeze" in resp.json()["detail"]

    # Detach -> traffic flows again.
    admin.delete(f"/v1/policies/{policy['id']}/attachments/route/{route['id']}")
    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_freeze_attached_to_agent_denies(admin, upstream):
    agent, _ = _bootstrap(admin, upstream)
    token = _mint(admin, agent)
    policy = _make_policy(admin, "change_freeze", _freeze_params(), name="agent-freeze")
    admin.post(f"/v1/policies/{policy['id']}/attachments/agent/{agent['id']}")
    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_inactive_or_future_freeze_allows(admin, upstream):
    agent, route = _bootstrap(admin, upstream)
    token = _mint(admin, agent)
    policy = _make_policy(admin, "change_freeze", _freeze_params(active=False),
                          name="future-freeze")
    admin.post(f"/v1/policies/{policy['id']}/attachments/route/{route['id']}")
    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200  # window not yet open

    live = _make_policy(admin, "change_freeze", _freeze_params(), name="live-freeze")
    admin.post(f"/v1/policies/{live['id']}/attachments/route/{route['id']}")
    admin.patch(f"/v1/policies/{live['id']}", json={"active": False})
    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200  # disabled policy is inert


def test_policy_attached_to_both_targets_evaluates_once(admin, upstream):
    """Attached to the route AND the agent: still one policy, one veto (the
    dedupe that SQL DISTINCT can't do over a JSON column on Postgres)."""
    agent, route = _bootstrap(admin, upstream)
    token = _mint(admin, agent)
    policy = _make_policy(admin, "change_freeze", _freeze_params(active=False),
                          name="both-freeze")
    admin.post(f"/v1/policies/{policy['id']}/attachments/route/{route['id']}")
    admin.post(f"/v1/policies/{policy['id']}/attachments/agent/{agent['id']}")
    resp = admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200  # future window: allowed, evaluated cleanly


def test_policy_denied_audit_event(admin, upstream):
    agent, route = _bootstrap(admin, upstream)
    token = _mint(admin, agent)
    policy = _make_policy(admin, "change_freeze", _freeze_params(), name="audit-freeze")
    admin.post(f"/v1/policies/{policy['id']}/attachments/route/{route['id']}")
    admin.get("/gw/pol/data", headers={"Authorization": f"Bearer {token}"})

    from sqlalchemy.orm import Session

    from app.db import get_engine
    from app.models import AuditEvent

    with Session(get_engine()) as db:
        denied = [e for e in db.query(AuditEvent).all() if e.event == "policy.denied"]
    assert denied
    assert denied[-1].detail["policy"] == "audit-freeze"
    assert denied[-1].detail["type"] == "change_freeze"
    assert denied[-1].agent_id == agent["id"]


# --- separation of duties -----------------------------------------------------


def test_policy_admin_role_seeded(admin):
    # Role seeding runs when the tenant gets its first principal.
    admin.post("/v1/users", json={"email": "seed@example.com"})
    roles = admin.get("/v1/roles").json()
    pa = next(r for r in roles if r["name"] == "policy-admin")
    assert "policies:apply:all" in pa["permissions"]
    assert "agents:read:all" in pa["permissions"]
    assert not any(p.startswith("agents:update") or p.startswith("agents:create")
                   for p in pa["permissions"])


def test_controlled_party_cannot_weaken_the_control(login, admin, upstream):
    """An agent-manager (no policies:*) can run agents but cannot create, edit,
    or detach a policy attached to their resources."""
    alice, _ = login("alice@example.com")

    # Governance (admin key) freezes alice's world with an agent-scoped policy.
    agent = alice.post("/v1/agents", json={"name": "alice-agent"}).json()
    admin.post("/v1/users", json={"email": "owner@example.com"})
    policy = admin.post("/v1/policies", json={
        "name": "alice-freeze", "type": "change_freeze", "params": _freeze_params(),
        "owner_email": "owner@example.com",
    }).json()
    admin.post(f"/v1/policies/{policy['id']}/attachments/agent/{agent['id']}")

    # Alice can't author policies...
    resp = alice.post("/v1/policies", json={
        "name": "mine", "type": "change_freeze", "params": _freeze_params(),
    })
    assert resp.status_code == 403
    # ...can't even see the control placed on her agent...
    assert alice.get(f"/v1/policies/{policy['id']}").status_code == 404
    # ...and can't detach it.
    resp = alice.delete(f"/v1/policies/{policy['id']}/attachments/agent/{agent['id']}")
    assert resp.status_code == 404


def test_policies_ui_page(login, admin, upstream):
    """The Policies surface renders for a holder of policies:* (admin here via
    session is out of scope — exercise via broker-admin login)."""
    admin.post("/v1/users", json={"email": "gov@example.com", "role": "broker-admin"})
    gov, _ = login("gov@example.com")
    html = gov.get("/ui/policies")
    assert html.status_code == 200
    assert "Contextual policies" in html.text
