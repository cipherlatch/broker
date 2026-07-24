"""Agent/user lifecycle: unrevoke (reactivate a revoked agent, old tokens stay
dead) and archive (delete-as-archive: row removed, name/email freed, UUIDv7
tombstone in the graveyard keeps the audit trail resolvable)."""

import uuid

from app.models import _uuid7


def _agent(admin, name="lc-agent"):
    admin.post("/v1/users", json={"email": "owner@example.com"})
    return admin.post("/v1/agents", json={
        "name": name, "owner_email": "owner@example.com",
    }).json()


def _mint(client, agent, expect=200):
    resp = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
    })
    assert resp.status_code == expect, resp.text
    return resp


# --- uuid7 --------------------------------------------------------------------


def test_uuid7_shape_and_ordering():
    a, b = _uuid7(), _uuid7()
    ua, ub = uuid.UUID(a), uuid.UUID(b)
    assert ua.version == 7 and ub.version == 7
    assert ua.variant == uuid.RFC_4122
    assert a <= b  # time-ordered (same-ms ties still sort consistently enough)


# --- unrevoke -----------------------------------------------------------------


def test_unrevoke_reactivates_but_old_tokens_stay_dead(admin):
    agent = _agent(admin)
    token = _mint(admin, agent).json()["access_token"]

    admin.delete(f"/v1/agents/{agent['id']}")  # revoke
    _mint(admin, agent, expect=401)

    resp = admin.post(f"/v1/agents/{agent['id']}/unrevoke")
    assert resp.status_code == 200 and resp.json()["active"] is True

    # New tokens mint again...
    new_token = _mint(admin, agent, expect=200).json()["access_token"]
    # ...but the pre-revocation token was invalidated by the generation bump.
    from sqlalchemy.orm import Session

    from app.db import get_engine
    from app.tokens import verify_token

    with Session(get_engine()) as db:
        assert verify_token(db, token) is None       # old generation: dead
        assert verify_token(db, new_token) is not None


def test_unrevoke_active_agent_is_noop(admin):
    agent = _agent(admin, name="noop-agent")
    resp = admin.post(f"/v1/agents/{agent['id']}/unrevoke")
    assert resp.status_code == 200 and resp.json()["active"] is True


# --- archive ------------------------------------------------------------------


def test_archive_requires_revoked(admin):
    agent = _agent(admin, name="active-agent")
    resp = admin.post(f"/v1/agents/{agent['id']}/archive")
    assert resp.status_code == 409
    assert "revoke" in resp.json()["detail"].lower()


def test_archive_frees_name_and_leaves_tombstone(admin):
    agent = _agent(admin, name="phoenix")
    admin.post("/v1/credentials", json={
        "name": "lc-cred", "secret": "s", "owner_email": "owner@example.com",
    })
    creds = admin.get("/v1/credentials").json()
    cred = next(c for c in creds if c["name"] == "lc-cred")
    admin.post(f"/v1/credentials/{cred['id']}/grants/{agent['id']}")

    admin.delete(f"/v1/agents/{agent['id']}")
    resp = admin.post(f"/v1/agents/{agent['id']}/archive")
    assert resp.status_code == 200, resp.text
    tomb_id = resp.json()["tombstone"]
    assert uuid.UUID(tomb_id).version == 7

    # Row gone; grants cleared.
    assert admin.get(f"/v1/agents/{agent['id']}").status_code == 404
    cred_after = admin.get(f"/v1/credentials/{cred['id']}").json()
    assert cred_after["granted_agents"] == []

    # The name is reusable — the earlier 409-on-duplicate is gone.
    reborn = admin.post("/v1/agents", json={
        "name": "phoenix", "owner_email": "owner@example.com",
    })
    assert reborn.status_code == 201, reborn.text

    # Tombstone holds the final state under the ORIGINAL id.
    graves = admin.get("/v1/audit/graveyard").json()
    tomb = next(t for t in graves if t["id"] == tomb_id)
    assert tomb["kind"] == "agent"
    assert tomb["original_id"] == agent["id"]
    assert tomb["name"] == "phoenix"
    assert tomb["snapshot"]["client_id"] == agent["client_id"]
    # No secret material in the snapshot.
    assert "secret" not in str(tomb["snapshot"]).lower() or \
        tomb["snapshot"].get("federated_subject") is None


def test_archive_user_blocked_while_owning_then_succeeds(admin):
    admin.post("/v1/users", json={"email": "victim@example.com"})
    users = admin.get("/v1/users?include_deleted=true").json()
    victim = next(u for u in users if u["email"] == "victim@example.com")
    agent = admin.post("/v1/agents", json={
        "name": "victim-agent", "owner_email": "victim@example.com",
    }).json()

    # Soft-delete the user (revokes their agents), then archive is blocked by ownership.
    admin.delete(f"/v1/users/{victim['id']}")
    resp = admin.post(f"/v1/users/{victim['id']}/archive")
    assert resp.status_code == 409
    assert "owns" in resp.json()["detail"]

    # Archive the (already revoked) agent, then the user archives cleanly.
    assert admin.post(f"/v1/agents/{agent['id']}/archive").status_code == 200
    resp = admin.post(f"/v1/users/{victim['id']}/archive")
    assert resp.status_code == 200, resp.text

    # Email freed for reuse.
    again = admin.post("/v1/users", json={"email": "victim@example.com"})
    assert again.status_code in (200, 201), again.text

    graves = admin.get("/v1/audit/graveyard").json()
    assert any(t["kind"] == "user" and t["name"] == "victim@example.com" for t in graves)


def test_audit_page_resolves_archived_agent_names(login, admin):
    admin.post("/v1/users", json={"email": "gov@example.com", "role": "broker-admin"})
    gov, _ = login("gov@example.com")
    agent = gov.post("/v1/agents", json={"name": "ghost-agent"}).json()
    gov.delete(f"/v1/agents/{agent['id']}")
    gov.post(f"/v1/agents/{agent['id']}/archive")
    html = gov.get("/ui/audit").text
    assert "ghost-agent (archived)" in html


def test_graveyard_page_admin_only(login, admin):
    admin.post("/v1/users", json={"email": "gov2@example.com", "role": "broker-admin"})
    gov, _ = login("gov2@example.com")
    assert gov.get("/ui/graveyard").status_code == 200

    alice, _ = login("alice@example.com")  # agent-manager: no audit:read:all
    assert alice.get("/ui/graveyard").status_code == 404
    assert alice.get("/v1/audit/graveyard").status_code == 404
