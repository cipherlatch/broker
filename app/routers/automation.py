"""Automation surface: idempotent upserts + declarative apply.

Built for config-management tools (Ansible, Puppet, Chef, GitOps
pipelines): every endpoint is safe to re-run, reports changed/unchanged in
Ansible's vocabulary, addresses resources by natural key instead of UUID,
and never regenerates a secret on update. POST /v1/apply converges a whole
desired-state document in dependency order; ?dry_run=true computes the full
change report without touching anything (check mode).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import upsert
from ..authz import Actor, require_actor, require_permission
from ..db import get_db

router = APIRouter(tags=["automation"])


def _result_body(res: upsert.Result, extra: dict | None = None) -> dict:
    body = {"changed": res.changed, "action": res.action, "changes": res.changes,
            "key": res.key}
    if res.secret is not None:
        body["client_secret"] = res.secret
    if extra:
        body.update(extra)
    return body


# ------------------------------------------------------- upserts (option A)


class UserSpec(BaseModel):
    display_name: str | None = None
    role: str | None = None
    active: bool | None = None


@router.put("/v1/users/by-email/{email}")
def upsert_user(
    email: EmailStr,
    body: UserSpec,
    request: Request,
    actor: Actor = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    res = upsert.upsert_user(db, request, actor, {"email": str(email), **body.model_dump()})
    return _result_body(res)


class RoleSpec(BaseModel):
    description: str | None = None
    permissions: list[str] | None = None


@router.put("/v1/roles/by-name/{name}")
def upsert_role(
    name: str,
    body: RoleSpec,
    request: Request,
    actor: Actor = Depends(require_permission("roles:manage")),
    db: Session = Depends(get_db),
):
    res = upsert.upsert_role(db, request, actor, {"name": name, **body.model_dump()})
    return _result_body(res)


class CredentialSpec(BaseModel):
    description: str | None = None
    secret: str | None = None
    owner_email: EmailStr | None = None
    update_secret: str = "on_create"  # on_create | always
    granted_agents: list[str] | None = None  # exact desired set of agent names


@router.put("/v1/credentials/by-name/{name}")
def upsert_credential(
    name: str,
    body: CredentialSpec,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    res = upsert.upsert_credential(db, request, actor, {"name": name, **body.model_dump()})
    return _result_body(res)


class AgentSpec(BaseModel):
    description: str | None = None
    owner_email: EmailStr | None = None
    allowed_scopes: list[str] | None = None
    allowed_resources: list[str] | None = None
    keyring: str | None = None
    federated_issuer: str | None = None
    federated_subject: str | None = None


@router.put("/v1/agents/by-name/{name}")
def upsert_agent(
    name: str,
    body: AgentSpec,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    res = upsert.upsert_agent(db, request, actor, {"name": name, **body.model_dump()})
    extra = {}
    if res.obj is not None:
        extra["client_id"] = res.obj.client_id
    return _result_body(res, extra)


class RouteSpec(BaseModel):
    description: str | None = None
    upstream_base: str | None = None
    credential_name: str | None = None
    inject_mode: str | None = None
    inject_header: str | None = None
    allowed_methods: list[str] | None = None
    allowed_path_prefixes: list[str] | None = None
    owner_email: EmailStr | None = None
    rate_limit_per_minute: int | None = None
    daily_quota: int | None = None
    active: bool | None = None
    granted_agents: list[str] | None = None


@router.put("/v1/routes/by-slug/{slug}")
def upsert_route(
    slug: str,
    body: RouteSpec,
    request: Request,
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    res = upsert.upsert_route(db, request, actor, {"slug": slug, **body.model_dump()})
    return _result_body(res)


# ------------------------------------------------- declarative apply (B)


class UserItem(UserSpec):
    email: EmailStr


class RoleItem(RoleSpec):
    name: str = Field(min_length=1)


class CredentialItem(CredentialSpec):
    name: str = Field(min_length=1)


class AgentItem(AgentSpec):
    name: str = Field(min_length=1)


class RouteItem(RouteSpec):
    slug: str = Field(min_length=1)


class ApplyDoc(BaseModel):
    roles: list[RoleItem] = []
    users: list[UserItem] = []
    credentials: list[CredentialItem] = []
    agents: list[AgentItem] = []
    routes: list[RouteItem] = []


@router.post("/v1/apply")
def apply(
    doc: ApplyDoc,
    request: Request,
    dry_run: bool = Query(False),
    actor: Actor = Depends(require_actor),
    db: Session = Depends(get_db),
):
    """Converge a desired-state document (dependency order: roles → users →
    credentials → agents → routes). Absent fields are left untouched; absent
    resources are NOT deleted — this converges what you declare. With
    dry_run=true nothing is written and the report shows what would change."""
    if doc.users and not actor.has("users:manage"):
        raise HTTPException(403, "Missing permission: users:manage")
    if doc.roles and not actor.has("roles:manage"):
        raise HTTPException(403, "Missing permission: roles:manage")

    # Names that earlier items in this document create, so later dry-run
    # items can reference them.
    planned = {
        "users": {str(u.email).lower() for u in doc.users},
        "roles": {r.name for r in doc.roles},
        "credentials": {c.name for c in doc.credentials},
        "agents": {a.name for a in doc.agents},
    }

    report: list[dict] = []
    secrets: dict[str, str] = {}

    def run(fn, items, key_field):
        for item in items:
            spec = item.model_dump()
            if "email" in spec and spec["email"] is not None:
                spec["email"] = str(spec["email"])
            try:
                res = fn(db, request, actor, spec, dry=dry_run, planned=planned)
            except HTTPException as exc:
                raise HTTPException(
                    exc.status_code,
                    {"error": str(exc.detail), "at": {"kind": fn.__name__.removeprefix("upsert_"),
                                                      "key": spec.get(key_field)},
                     "report": report},
                )
            report.append(res.report())
            if res.secret is not None:
                secrets[res.key] = res.secret

    run(upsert.upsert_role, doc.roles, "name")
    run(upsert.upsert_user, doc.users, "email")
    run(upsert.upsert_credential, doc.credentials, "name")
    run(upsert.upsert_agent, doc.agents, "name")
    run(upsert.upsert_route, doc.routes, "slug")

    body = {
        "changed": any(r["action"] != "unchanged" for r in report),
        "dry_run": dry_run,
        "report": report,
    }
    if secrets:
        body["agent_secrets"] = secrets  # shown once; store them now
    return body
