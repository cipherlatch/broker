"""Automation surface: natural-key upserts (changed/unchanged semantics,
secrets only on create) and the declarative /v1/apply (dependency order,
dry-run check mode, fail-fast with partial report)."""

from fastapi.testclient import TestClient


def _seed_owner(admin):
    admin.post("/v1/users", json={"email": "owner@example.com"})


# ------------------------------------------------------------------ upserts


def test_agent_upsert_lifecycle(admin):
    _seed_owner(admin)
    spec = {"owner_email": "owner@example.com", "allowed_scopes": ["ha:read"]}

    first = admin.put("/v1/agents/by-name/ha-agent", json=spec)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["changed"] is True and body["action"] == "created"
    secret = body["client_secret"]
    assert secret and body["client_id"].startswith("aib_")

    # Re-run: no changes, and the secret is NOT regenerated or re-shown.
    second = admin.put("/v1/agents/by-name/ha-agent", json=spec)
    assert second.json()["changed"] is False
    assert "client_secret" not in second.json()

    # Converge a field.
    third = admin.put("/v1/agents/by-name/ha-agent",
                      json={**spec, "allowed_scopes": ["ha:read", "ha:write"]})
    assert third.json()["changed"] is True
    assert third.json()["changes"]["allowed_scopes"][1] == ["ha:read", "ha:write"]

    # Old secret still authenticates (update never rotated it).
    resp = admin.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": first.json()["client_id"], "client_secret": secret,
    })
    assert resp.status_code == 200


def test_user_and_role_upserts(admin):
    role = admin.put("/v1/roles/by-name/deployer",
                     json={"permissions": ["agents:create", "agents:read"]})
    assert role.json()["action"] == "created"
    assert admin.put("/v1/roles/by-name/deployer",
                     json={"permissions": ["agents:create", "agents:read"]}).json()["changed"] is False

    user = admin.put("/v1/users/by-email/ops@example.com", json={"role": "deployer"})
    assert user.json()["action"] == "created"
    again = admin.put("/v1/users/by-email/ops@example.com", json={"role": "deployer"})
    assert again.json()["changed"] is False
    demote = admin.put("/v1/users/by-email/ops@example.com", json={"role": "auditor"})
    assert demote.json()["changes"]["role"] == ["deployer", "auditor"]

    # Built-in roles refuse convergence attempts.
    builtin = admin.put("/v1/roles/by-name/broker-admin", json={"permissions": ["*"]})
    assert builtin.json()["changed"] is False  # identical = unchanged, fine
    tampered = admin.put("/v1/roles/by-name/broker-admin", json={"permissions": ["agents:read"]})
    assert tampered.status_code == 409


def test_credential_upsert_secret_modes(admin):
    _seed_owner(admin)
    created = admin.put("/v1/credentials/by-name/ha-token",
                        json={"secret": "s3cret", "owner_email": "owner@example.com"})
    assert created.json()["action"] == "created"

    # Default on_create: providing the secret again does not flip changed.
    rerun = admin.put("/v1/credentials/by-name/ha-token",
                      json={"secret": "s3cret", "owner_email": "owner@example.com"})
    assert rerun.json()["changed"] is False

    # always: replaces and reports.
    rotated = admin.put("/v1/credentials/by-name/ha-token",
                        json={"secret": "new-secret", "update_secret": "always"})
    assert rotated.json()["changes"]["secret"] == "replaced"

    missing = admin.put("/v1/credentials/by-name/brand-new", json={})
    assert missing.status_code == 422  # create needs a secret


def test_route_upsert_with_grant_convergence(admin):
    _seed_owner(admin)
    admin.put("/v1/credentials/by-name/svc-cred",
              json={"secret": "x", "owner_email": "owner@example.com"})
    for n in ("a1", "a2"):
        admin.put(f"/v1/agents/by-name/{n}", json={"owner_email": "owner@example.com"})

    created = admin.put("/v1/routes/by-slug/svc", json={
        "upstream_base": "http://upstream.test", "credential_name": "svc-cred",
        "owner_email": "owner@example.com", "allowed_methods": ["GET"],
        "granted_agents": ["a1"],
    })
    assert created.json()["action"] == "created"

    # Converge grants to exactly {a2}: adds a2, revokes a1.
    converged = admin.put("/v1/routes/by-slug/svc", json={"granted_agents": ["a2"]})
    assert converged.json()["changes"]["granted_agents"] == [["a1"], ["a2"]]
    route = next(r for r in admin.get("/v1/routes").json() if r["slug"] == "svc")
    assert [g["name"] for g in route["granted_agents"]] == ["a2"]

    # Same grants again: unchanged.
    assert admin.put("/v1/routes/by-slug/svc",
                     json={"granted_agents": ["a2"]}).json()["changed"] is False

    unknown = admin.put("/v1/routes/by-slug/svc", json={"granted_agents": ["ghost"]})
    assert unknown.status_code == 422


# -------------------------------------------------------------------- apply


DOC = {
    "roles": [{"name": "deployer", "permissions": ["agents:create", "agents:read"]}],
    "users": [{"email": "owner@example.com", "role": "broker-admin"},
              {"email": "ops@example.com", "role": "deployer"}],
    "credentials": [{"name": "ha-token", "secret": "s3cret",
                     "owner_email": "owner@example.com"}],
    "agents": [{"name": "ha-agent", "owner_email": "owner@example.com",
                "allowed_scopes": ["ha:read"]}],
    "routes": [{"slug": "ha", "upstream_base": "http://ha.test",
                "credential_name": "ha-token", "owner_email": "owner@example.com",
                "allowed_methods": ["GET", "POST"], "granted_agents": ["ha-agent"]}],
}


def test_apply_converges_and_is_idempotent(admin):
    first = admin.post("/v1/apply", json=DOC)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["changed"] is True
    assert {r["action"] for r in body["report"]} == {"created"}
    assert "ha-agent" in body["agent_secrets"]  # shown exactly once

    second = admin.post("/v1/apply", json=DOC)
    assert second.json()["changed"] is False
    assert {r["action"] for r in second.json()["report"]} == {"unchanged"}
    assert "agent_secrets" not in second.json()


def test_apply_dry_run_reports_without_writing(admin):
    dry = admin.post("/v1/apply", params={"dry_run": "true"}, json=DOC)
    assert dry.status_code == 200, dry.text
    body = dry.json()
    assert body["dry_run"] is True and body["changed"] is True
    # Cross-references to items created earlier in the same doc resolve.
    assert any(r["kind"] == "route" and r["action"] == "created" for r in body["report"])

    # Nothing was written.
    assert admin.get("/v1/agents").json() == []
    assert all(u["email"] != "ops@example.com" for u in admin.get("/v1/users").json())

    # A real apply after the dry run produces the same shape of report.
    real = admin.post("/v1/apply", json=DOC)
    assert [r["action"] for r in real.json()["report"]] == \
           [r["action"] for r in body["report"]]


def test_apply_fail_fast_with_partial_report(admin):
    doc = {
        "users": [{"email": "owner@example.com"}],
        "routes": [{"slug": "broken", "upstream_base": "http://x.test",
                    "credential_name": "does-not-exist",
                    "owner_email": "owner@example.com"}],
    }
    resp = admin.post("/v1/apply", json=doc)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["at"] == {"kind": "route", "key": "broken"}
    # The user upserted before the failure is in the partial report.
    assert any(r["kind"] == "user" for r in detail["report"])


def test_apply_permission_gates(login):
    c, _ = login("pleb@example.com")  # agent-manager
    resp = c.post("/v1/apply", json={"users": [{"email": "x@example.com"}]})
    assert resp.status_code == 403
    resp = c.post("/v1/apply", json={"roles": [{"name": "r", "permissions": []}]})
    assert resp.status_code == 403
