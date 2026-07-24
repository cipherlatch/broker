"""Server-rendered management UI. Session (OIDC) auth only — the admin API
key is a machine credential and deliberately cannot drive the browser UI.

Surfaces the actor lacks permission for are hidden as 404s, matching the
API's existence-hiding behavior.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import crud
from ..authz import Actor, get_actor
from ..config import get_settings
from ..db import get_db
from ..models import Agent, AuditEvent
from ..permissions import PERMISSIONS
from .audit_api import scoped_audit_query

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _asset_version() -> str:
    """Content hash of the static bundle, used as a ?v= cache-buster so a deploy
    is picked up immediately instead of serving a stale app.js/app.css."""
    import hashlib

    base = Path(__file__).resolve().parent.parent / "static"
    digest = hashlib.sha256()  # not security-sensitive; sha256 keeps the SAST gate happy
    for name in ("app.js", "app.css"):
        path = base / name
        if path.exists():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:8]


templates.env.globals["asset_v"] = _asset_version()


def ui_actor(actor: Actor | None = Depends(get_actor)) -> Actor:
    if actor is None or actor.principal is None:
        raise HTTPException(303, headers={"Location": "/login"})
    return actor


def _require(actor: Actor, perm: str) -> None:
    if not actor.has(perm):
        raise HTTPException(404, "Not found")  # hide surfaces, don't advertise them


def _split(value: str) -> list[str]:
    return [s for s in value.replace(",", " ").split() if s]


def _int_field(value: str, name: str) -> int:
    value = (value or "").strip()
    if not value:
        return 0
    try:
        return int(value)
    except ValueError:
        raise HTTPException(422, f"{name} must be a whole number (0 = unlimited)")


def _icon_apply(db, request: Request, actor: Actor, kind: str, obj_id: str,
                mode: str, value: str, data: str) -> str:
    """Shared handler behind the icon dialog: one of emoji / url / upload /
    detect / remove, applied to an agent, route, or credential. Returns the
    flash message."""
    value = value.strip()
    if mode == "upload":
        crud.set_icon_upload(db, request, actor, kind, obj_id, data)
        return "Icon updated."
    if mode == "url":
        if kind == "agent":
            _, ok = crud.set_agent_icon_from_url(db, request, actor, obj_id, value)
        elif kind == "route":
            _, ok = crud.set_route_icon_from_url(db, request, actor, obj_id, value)
        else:
            _, ok = crud.set_credential_icon_from_url(db, request, actor, obj_id, value)
        return ("Icon fetched and stored." if ok else
                "That URL didn't return a usable image (small raster, max 50 KB).")
    if mode == "detect" and kind == "route":
        route = crud.detect_route_icon(db, request, actor, obj_id)
        return ("Icon set from the upstream's favicon."
                if route.icon.startswith("data:") else "No favicon found on the upstream.")
    # emoji, or remove (an empty emoji clears)
    emoji = "" if mode == "remove" else value
    if kind == "agent":
        crud.update_agent(db, request, actor, obj_id, icon=emoji)
    elif kind == "route":
        crud.update_route(db, request, actor, obj_id, icon=emoji)
    else:
        crud.update_credential(db, request, actor, obj_id, icon=emoji)
    return "Icon removed." if mode == "remove" else "Icon updated."


def render(request: Request, template: str, actor: Actor | None = None, **ctx):
    settings = get_settings()
    return templates.TemplateResponse(
        request,
        template,
        {
            "actor": actor,
            "accent": settings.ui_accent,
            "oidc_enabled": settings.oidc_enabled,
            "flash": request.session.pop("flash", None),
            "secret_reveal": request.session.pop("secret_reveal", None),
            **ctx,
        },
    )


def _flash(request: Request, message: str, kind: str = "ok") -> None:
    request.session["flash"] = {"message": message, "kind": kind}


@router.get("/")
def index(actor: Actor | None = Depends(get_actor)):
    if actor is not None and actor.principal is not None:
        return RedirectResponse("/ui/agents", status_code=302)
    return RedirectResponse("/login", status_code=302)


@router.get("/login")
def login_page(request: Request, actor: Actor | None = Depends(get_actor)):
    if actor is not None and actor.principal is not None:
        return RedirectResponse("/ui/agents", status_code=302)
    return render(request, "login.html")


_AVATAR_RE = __import__("re").compile(r"^data:image/(?:png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$")


@router.post("/ui/profile/avatar")
def profile_avatar(
    request: Request,
    data: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    """Set (or clear) the signed-in user's own profile photo. `data` is a
    client-resized image data URI, or empty to remove. Validated strictly:
    only png/jpeg/webp base64 (the strict charset can't inject into the CSS
    url() it's rendered in), capped in size."""
    import base64

    data = data.strip()
    if not data:
        actor.principal.avatar = None
        db.commit()
        _flash(request, "Profile photo removed.")
    else:
        if not _AVATAR_RE.match(data):
            raise HTTPException(422, "Not a valid PNG, JPEG, or WebP image.")
        b64 = data.split(",", 1)[1]
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception:
            raise HTTPException(422, "Image data is not valid base64.")
        if len(raw) > 200_000:
            raise HTTPException(413, "Image is too large (keep it under ~200 KB after resize).")
        actor.principal.avatar = data
        db.commit()
        _flash(request, "Profile photo updated.")
    dest = request.headers.get("referer", "")
    if not dest.startswith(str(request.base_url)):
        dest = "/ui/agents"
    return RedirectResponse(dest, status_code=303)


# -------------------------------------------------------------------- agents


@router.get("/ui/agents")
def agents_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    agents = crud.visible_agents(db, actor)
    return render(request, "agents.html", actor, agents=agents, nav="agents")


@router.post("/ui/agents")
def agents_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    icon: str = Form(""),
    icon_upload: str = Form(""),
    scopes: str = Form(""),
    resources: str = Form(""),
    owner_email: str = Form(""),
    federated_issuer: str = Form(""),
    federated_subject: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    val = icon.strip()
    is_url = val.lower().startswith(("http://", "https://"))
    try:
        agent, secret = crud.create_agent(
            db,
            request,
            actor,
            name=name.strip(),
            description=description.strip(),
            icon=("" if is_url else val),
            allowed_scopes=_split(scopes),
            allowed_resources=_split(resources),
            owner_email=owner_email.strip() or None,
            federated_issuer=federated_issuer.strip() or None,
            federated_subject=federated_subject.strip() or None,
        )
    except HTTPException as exc:
        _flash(request, f"Could not create agent: {exc.detail}", "warn")
        return RedirectResponse("/ui/agents", status_code=303)
    if is_url:
        crud.set_agent_icon_from_url(db, request, actor, agent.id, val)
    elif icon_upload:
        crud.set_icon_upload(db, request, actor, "agent", agent.id, icon_upload)
    if secret is not None:
        # Secretless (federated) agents have no secret to reveal.
        request.session["secret_reveal"] = {
            "client_id": agent.client_id,
            "client_secret": secret,
            "agent_name": agent.name,
        }
    else:
        _flash(request, "Federated agent created — it authenticates with its "
                        "platform JWT; no client secret is issued.")
    return RedirectResponse(f"/ui/agents/{agent.id}", status_code=303)


@router.get("/ui/agents/{agent_id}")
def agent_detail(
    request: Request,
    agent_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    from ..models import CredentialGrant, RouteGrant

    agent = crud.get_visible_agent(db, actor, agent_id)
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.agent_id == agent.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(25)
    ).all()

    def _can(action: str) -> bool:
        if actor.has(f"agents:{action}:all"):
            return True
        return agent.owner_id == actor.principal.id and actor.has(f"agents:{action}")

    # This agent's access grants, shown only for credentials/routes the actor is
    # allowed to see — a grant to something you can't see is omitted, preserving
    # the same existence-hiding the credential/route pages use.
    creds = {c.id: c for c in crud.visible_credentials(db, actor)}
    routes = {r.id: r for r in crud.visible_routes(db, actor)}
    cred_grant_ids = set(db.scalars(
        select(CredentialGrant.credential_id).where(CredentialGrant.agent_id == agent.id)
    ).all())
    route_grant_ids = set(db.scalars(
        select(RouteGrant.route_id).where(RouteGrant.agent_id == agent.id)
    ).all())
    granted_creds = [creds[i] for i in cred_grant_ids if i in creds]
    granted_routes = [routes[i] for i in route_grant_ids if i in routes]
    # Mirror the credential/route pages' write gate for showing grant controls;
    # crud.grant_* still enforces the per-object grant permission on submit.
    can_grant_cred = actor.has("credentials:create") or actor.has("credentials:update:all")
    can_grant_route = actor.has("routes:create") or actor.has("routes:update:all")
    grantable_creds = (
        [c for c in creds.values() if c.id not in cred_grant_ids] if can_grant_cred else []
    )
    grantable_routes = (
        [r for r in routes.values() if r.id not in route_grant_ids] if can_grant_route else []
    )

    return render(
        request, "agent_detail.html", actor,
        agent=agent, events=events, nav="agents",
        can_update=_can("update"), can_rotate=_can("rotate"), can_revoke=_can("revoke"),
        granted_creds=granted_creds, granted_routes=granted_routes,
        grantable_creds=grantable_creds, grantable_routes=grantable_routes,
        can_grant_cred=can_grant_cred, can_grant_route=can_grant_route,
    )


@router.post("/ui/agents/{agent_id}/update")
def agent_update(
    request: Request,
    agent_id: str,
    description: str = Form(""),
    icon: str = Form(""),
    scopes: str = Form(""),
    resources: str = Form(""),
    federated_issuer: str = Form(""),
    federated_subject: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    val = icon.strip()
    is_url = val.lower().startswith(("http://", "https://"))
    try:
        crud.update_agent(
            db,
            request,
            actor,
            agent_id,
            description=description.strip(),
            allowed_scopes=_split(scopes),
            allowed_resources=_split(resources),
            icon=(None if (is_url or not val) else val),
            # Both empty clears the binding; both set (re)binds. The edit form
            # always submits the current values, so an untouched save is a no-op.
            federated_issuer=federated_issuer.strip(),
            federated_subject=federated_subject.strip(),
        )
    except HTTPException as exc:
        _flash(request, f"Could not update agent: {exc.detail}", "warn")
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    if is_url:
        crud.set_agent_icon_from_url(db, request, actor, agent_id, val)
    _flash(request, "Agent updated.")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/icon")
def agent_icon(
    request: Request,
    agent_id: str,
    mode: str = Form(...),
    value: str = Form(""),
    data: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _flash(request, _icon_apply(db, request, actor, "agent", agent_id, mode, value, data))
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/rotate")
def agent_rotate(
    request: Request,
    agent_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    agent, secret = crud.rotate_agent_secret(db, request, actor, agent_id)
    request.session["secret_reveal"] = {
        "client_id": agent.client_id,
        "client_secret": secret,
        "agent_name": agent.name,
    }
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/revoke")
def agent_revoke(
    request: Request,
    agent_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.revoke_agent(db, request, actor, agent_id)
    _flash(request, "Agent revoked. Its credentials no longer mint tokens.", "warn")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/unrevoke")
def agent_unrevoke(
    request: Request,
    agent_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.unrevoke_agent(db, request, actor, agent_id)
    _flash(request, "Agent reactivated. Tokens issued before the revocation stay dead.")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/archive")
def agent_archive(
    request: Request,
    agent_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    try:
        result = crud.archive_agent(db, request, actor, agent_id)
    except HTTPException as exc:
        _flash(request, f"Could not archive: {exc.detail}", "warn")
        return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)
    _flash(request, f"Agent '{result['archived']}' archived — its name is reusable; "
                    "its audit trail lives on in the graveyard.", "warn")
    return RedirectResponse("/ui/agents", status_code=303)


# Manage this agent's access grants from its own page. The crud calls enforce
# the per-credential / per-route grant permission, so these are thin wrappers.
@router.post("/ui/agents/{agent_id}/grant-credential")
def agent_grant_credential(
    request: Request,
    agent_id: str,
    credential_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.grant_credential(db, request, actor, credential_id, agent_id)
    _flash(request, "Credential granted.")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/revoke-credential")
def agent_revoke_credential(
    request: Request,
    agent_id: str,
    credential_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.revoke_credential_grant(db, request, actor, credential_id, agent_id)
    _flash(request, "Credential grant revoked.", "warn")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/grant-route")
def agent_grant_route(
    request: Request,
    agent_id: str,
    route_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.grant_route(db, request, actor, route_id, agent_id)
    _flash(request, "Route granted.")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


@router.post("/ui/agents/{agent_id}/revoke-route")
def agent_revoke_route(
    request: Request,
    agent_id: str,
    route_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.revoke_route_grant(db, request, actor, route_id, agent_id)
    _flash(request, "Route grant revoked.", "warn")
    return RedirectResponse(f"/ui/agents/{agent_id}", status_code=303)


# ------------------------------------------------------------------ policies


@router.get("/ui/policies")
def policies_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    if not (actor.has("policies:read") or actor.has("policies:read:all")):
        raise HTTPException(404, "Not found")
    policies = crud.visible_policies(db, actor)
    routes = crud.visible_routes(db, actor)
    agents = crud.visible_agents(db, actor)
    # Resolve attachment targets to display labels (route slug / agent name).
    from ..models import Agent as AgentModel, GatewayRoute

    route_names = {r.id: f"/gw/{r.slug}" for r in db.scalars(select(GatewayRoute)).all()}
    agent_names = {a.id: a.name for a in db.scalars(select(AgentModel)).all()}
    labels = {}
    for p in policies:
        for a in p.attachments:
            labels[a.id] = (route_names if a.target_type == "route" else agent_names).get(
                a.target_id, a.target_id
            )
    return render(
        request, "policies.html", actor,
        policies=policies, routes=routes, agents=agents, nav="policies",
        can_create=actor.has("policies:create") or actor.has("policies:update:all"),
        can_update=actor.has("policies:update") or actor.has("policies:update:all"),
        can_apply=actor.has("policies:apply") or actor.has("policies:apply:all"),
        attachment_labels=labels,
    )


def _parse_params_form(request: Request, raw: str):
    import json

    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _flash(request, f"Parameters are not valid JSON: {exc}", kind="warn")
        return _BAD_JSON


@router.post("/ui/policies")
def policies_create(
    request: Request,
    name: str = Form(...),
    type: str = Form(...),
    params: str = Form(""),
    description: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    parsed = _parse_params_form(request, params)
    if parsed is _BAD_JSON:
        return RedirectResponse("/ui/policies", status_code=303)
    try:
        crud.create_policy(
            db, request, actor, name=name.strip(), type=type,
            params=parsed, description=description.strip(),
        )
    except HTTPException as exc:
        _flash(request, f"Could not create policy: {exc.detail}", "warn")
        return RedirectResponse("/ui/policies", status_code=303)
    _flash(request, f"Policy '{name}' created. It enforces nothing until attached.")
    return RedirectResponse("/ui/policies", status_code=303)


@router.post("/ui/policies/{policy_id}/update")
def policies_update(
    request: Request,
    policy_id: str,
    description: str = Form(""),
    params: str = Form(""),
    active: str = Form("true"),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    parsed = _parse_params_form(request, params)
    if parsed is _BAD_JSON:
        return RedirectResponse("/ui/policies", status_code=303)
    try:
        crud.update_policy(
            db, request, actor, policy_id,
            description=description.strip(),
            params=parsed or None,
            active=(active == "true"),
        )
    except HTTPException as exc:
        _flash(request, f"Could not update policy: {exc.detail}", "warn")
        return RedirectResponse("/ui/policies", status_code=303)
    _flash(request, "Policy updated.")
    return RedirectResponse("/ui/policies", status_code=303)


@router.post("/ui/policies/{policy_id}/delete")
def policies_delete(
    request: Request,
    policy_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    result = crud.delete_policy(db, request, actor, policy_id)
    _flash(request, f"Policy deleted ({result['attachments_removed']} attachment(s) removed).", "warn")
    return RedirectResponse("/ui/policies", status_code=303)


@router.post("/ui/policies/{policy_id}/attach")
def policies_attach(
    request: Request,
    policy_id: str,
    target: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    target_type, _, target_id = target.partition(":")
    crud.attach_policy(db, request, actor, policy_id, target_type, target_id)
    _flash(request, "Policy attached — enforcing on the next request.")
    return RedirectResponse("/ui/policies", status_code=303)


@router.post("/ui/policies/{policy_id}/detach")
def policies_detach(
    request: Request,
    policy_id: str,
    target_type: str = Form(...),
    target_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.detach_policy(db, request, actor, policy_id, target_type, target_id)
    _flash(request, "Policy detached.", "warn")
    return RedirectResponse("/ui/policies", status_code=303)


# --------------------------------------------------------------------- users


@router.get("/ui/users")
def users_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    _require(actor, "users:read")
    users = crud.list_principals(db, actor)
    crud.actor_tenant(db, actor)
    roles = crud.list_roles(db, actor)
    agent_counts = {
        owner_id: count
        for owner_id, count in db.execute(
            select(Agent.owner_id, func.count(Agent.id))
            .where(Agent.tenant_id == actor.tenant_id)
            .group_by(Agent.owner_id)
        ).all()
    }
    return render(
        request, "users.html", actor,
        users=users, roles=roles, agent_counts=agent_counts,
        can_manage=actor.has("users:manage"), nav="users",
    )


@router.post("/ui/users")
def users_create(
    request: Request,
    email: str = Form(...),
    display_name: str = Form(""),
    role: str = Form("agent-manager"),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "users:manage")
    crud.create_principal(
        db, request, actor.label, email=email.strip(), display_name=display_name.strip(),
        role=role, tenant=crud.actor_tenant(db, actor), granted_by=actor,
    )
    _flash(request, f"User {email} added. They can sign in via SSO.")
    return RedirectResponse("/ui/users", status_code=303)


@router.post("/ui/users/{user_id}/update")
def users_update(
    request: Request,
    user_id: str,
    display_name: str = Form(""),
    role: str = Form("agent-manager"),
    active: str = Form("true"),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "users:manage")
    crud.update_principal(
        db,
        request,
        actor,
        user_id,
        display_name=display_name.strip(),
        role=role,
        active=(active == "true"),
    )
    _flash(request, "User updated.")
    return RedirectResponse("/ui/users", status_code=303)


@router.post("/ui/users/{user_id}/delete")
def users_delete(
    request: Request,
    user_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "users:manage")
    result = crud.delete_principal(db, request, actor, user_id)
    _flash(
        request,
        f"Deleted {result['deleted']}; revoked {result['agents_revoked']} agent(s).",
        "warn",
    )
    return RedirectResponse("/ui/users", status_code=303)


# --------------------------------------------------------------------- roles


@router.get("/ui/roles")
def roles_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    _require(actor, "roles:read")
    crud.actor_tenant(db, actor)
    roles = crud.list_roles(db, actor)
    from ..models import Principal

    usage = {
        role_id: count
        for role_id, count in db.execute(
            select(Principal.role_id, func.count(Principal.id))
            .where(Principal.tenant_id == actor.tenant_id)
            .where(Principal.deleted_at.is_(None))
            .group_by(Principal.role_id)
        ).all()
    }
    return render(
        request, "roles.html", actor,
        roles=roles, usage=usage, catalog=PERMISSIONS,
        can_manage=actor.has("roles:manage"), nav="roles",
    )


@router.post("/ui/roles")
async def roles_create(
    request: Request,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "roles:manage")
    form = await request.form()
    crud.create_role(
        db, request, actor,
        name=str(form.get("name", "")),
        description=str(form.get("description", "")),
        permissions=[str(p) for p in form.getlist("permissions")],
    )
    _flash(request, f"Role '{form.get('name')}' created.")
    return RedirectResponse("/ui/roles", status_code=303)


@router.post("/ui/roles/{role_id}/update")
async def roles_update(
    request: Request,
    role_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "roles:manage")
    form = await request.form()
    crud.update_role(
        db, request, actor, role_id,
        description=str(form.get("description", "")),
        permissions=[str(p) for p in form.getlist("permissions")],
    )
    _flash(request, "Role updated.")
    return RedirectResponse("/ui/roles", status_code=303)


@router.post("/ui/roles/{role_id}/delete")
def roles_delete(
    request: Request,
    role_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _require(actor, "roles:manage")
    result = crud.delete_role(db, request, actor, role_id)
    _flash(request, f"Role '{result['deleted']}' deleted.", "warn")
    return RedirectResponse("/ui/roles", status_code=303)


# -------------------------------------------------------------- service keys


@router.get("/ui/service-keys")
def service_keys_page(
    request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    _require(actor, "service_keys:read")
    crud.actor_tenant(db, actor)
    keys = crud.list_service_keys(db, actor)
    roles = crud.list_roles(db, actor)
    return render(
        request, "system_keys.html", actor,
        keys=keys, roles=roles,
        can_manage=actor.has("service_keys:manage"), nav="service-keys",
    )


@router.post("/ui/service-keys")
async def service_keys_create(
    request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    _require(actor, "service_keys:manage")
    form = await request.form()
    try:
        key, secret = crud.create_service_key(
            db, request, actor,
            name=str(form.get("name", "")),
            role=str(form.get("role", "")),
            description=str(form.get("description", "")),
        )
    except HTTPException as exc:
        _flash(request, f"Could not create service key: {exc.detail}", "warn")
        return RedirectResponse("/ui/service-keys", status_code=303)
    # Reuse the shared shown-once reveal panel (base.html); api_key selects the
    # service-key layout.
    request.session["secret_reveal"] = {"name": key.name, "api_key": secret}
    return RedirectResponse("/ui/service-keys", status_code=303)


@router.post("/ui/service-keys/{key_id}/revoke")
def service_keys_revoke(
    request: Request, key_id: str,
    actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    _require(actor, "service_keys:manage")
    key = crud.revoke_service_key(db, request, actor, key_id)
    _flash(request, f"Service key '{key.name}' revoked.", "warn")
    return RedirectResponse("/ui/service-keys", status_code=303)


# --------------------------------------------------------------------- audit


@router.get("/ui/audit")
def audit_page(
    request: Request,
    event: str = "",
    actor_q: str = "",
    before: str = "",
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    from .audit_api import apply_before

    page_size = 200
    q = scoped_audit_query(actor).order_by(
        AuditEvent.created_at.desc(), AuditEvent.id.desc()
    )
    if event:
        q = q.where(AuditEvent.event == event)
    if actor_q:
        q = q.where(AuditEvent.actor == actor_q)
    if before:
        q = apply_before(q, db, actor, before)
    events = list(db.scalars(q.limit(page_size + 1)).all())
    next_before = ""
    if len(events) > page_size:
        events = events[:page_size]
        next_before = events[-1].id
    agent_names = {a.id: a.name for a in db.scalars(select(Agent)).all()}
    # Archived agents are gone from the table but their audit rows remain —
    # resolve those ids through the graveyard.
    agent_names = {**crud.tombstone_names(db, actor.tenant_id), **agent_names}
    return render(
        request, "audit.html", actor,
        events=events, agent_names=agent_names, nav="audit",
        event_filter=event, actor_filter=actor_q,
        next_before=next_before, paged=bool(before),
    )


@router.get("/ui/graveyard")
def graveyard_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    tombstones = crud.list_graveyard(db, actor)  # 404s without audit:read:all
    return render(request, "graveyard.html", actor, tombstones=tombstones, nav="graveyard")


# --------------------------------------------------------------- credentials


@router.get("/ui/credentials")
def credentials_page(
    request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    if not (actor.has("credentials:read") or actor.has("credentials:read:all")):
        raise HTTPException(404, "Not found")
    creds = crud.visible_credentials(db, actor)
    agents = crud.visible_agents(db, actor)
    can_write = actor.has("credentials:create") or actor.has("credentials:update:all")
    from .. import secretbox

    # For ssh-ca credentials, derive the CA *public* key so the page can show
    # copy-paste host setup. Public half only; best-effort.
    ssh_pub: dict[str, str] = {}
    if secretbox.backend_ready():
        from ..credential_providers import ssh_ca

        for c in creds:
            if c.provider == "ssh-ca":
                try:
                    ssh_pub[c.id] = ssh_ca.public_openssh(secretbox.decrypt(c.secret_encrypted))
                except Exception:
                    pass
    return render(
        request, "credentials.html", actor,
        creds=creds, agents=agents, can_write=can_write, ssh_pub=ssh_pub,
        broker_configured=secretbox.backend_ready(),
        issuer=get_settings().issuer, nav="credentials",
    )


@router.post("/ui/credentials")
def credentials_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    secret: str = Form(...),
    icon: str = Form(""),
    icon_upload: str = Form(""),
    provider: str = Form(""),
    provider_config: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    provider = provider.strip() or None
    config = None
    if provider and provider_config.strip():
        import json

        try:
            config = json.loads(provider_config)
        except json.JSONDecodeError as exc:
            _flash(request, f"Provider config is not valid JSON: {exc}", kind="warn")
            return RedirectResponse("/ui/credentials", status_code=303)
    val = icon.strip()
    is_url = val.lower().startswith(("http://", "https://"))
    cred = crud.create_credential(
        db, request, actor, name=name.strip(), description=description.strip(),
        secret=secret, icon=("" if is_url else val),
        provider=provider, provider_config=config,
    )
    if is_url:
        crud.set_credential_icon_from_url(db, request, actor, cred.id, val)
    elif icon_upload:
        crud.set_icon_upload(db, request, actor, "credential", cred.id, icon_upload)
    _flash(request, f"Credential '{name}' stored (encrypted). Grant agents below.")
    return RedirectResponse("/ui/credentials", status_code=303)


@router.post("/ui/credentials/{credential_id}/update")
def credentials_update(
    request: Request,
    credential_id: str,
    description: str = Form(""),
    secret: str = Form(""),
    provider_config: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    config = None
    if provider_config.strip():
        import json

        try:
            config = json.loads(provider_config)
        except json.JSONDecodeError as exc:
            _flash(request, f"Provider config is not valid JSON: {exc}", kind="warn")
            return RedirectResponse("/ui/credentials", status_code=303)
    crud.update_credential(
        db, request, actor, credential_id,
        description=description.strip(), secret=secret or None,
        provider_config=config,
    )
    _flash(request, "Credential updated." + (" Secret replaced." if secret else ""))
    return RedirectResponse("/ui/credentials", status_code=303)


@router.post("/ui/credentials/{credential_id}/delete")
def credentials_delete(
    request: Request,
    credential_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    result = crud.delete_credential(db, request, actor, credential_id)
    _flash(request, f"Credential '{result['deleted']}' deleted.", "warn")
    return RedirectResponse("/ui/credentials", status_code=303)


@router.post("/ui/credentials/{credential_id}/icon")
def credential_icon(
    request: Request,
    credential_id: str,
    mode: str = Form(...),
    value: str = Form(""),
    data: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _flash(request, _icon_apply(db, request, actor, "credential", credential_id, mode, value, data))
    return RedirectResponse("/ui/credentials", status_code=303)


@router.post("/ui/credentials/{credential_id}/grant")
def credentials_grant(
    request: Request,
    credential_id: str,
    agent_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.grant_credential(db, request, actor, credential_id, agent_id)
    _flash(request, "Agent granted.")
    return RedirectResponse("/ui/credentials", status_code=303)


@router.post("/ui/credentials/{credential_id}/revoke-grant")
def credentials_revoke_grant(
    request: Request,
    credential_id: str,
    agent_id: str = Form(...),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    crud.revoke_credential_grant(db, request, actor, credential_id, agent_id)
    _flash(request, "Grant revoked.", "warn")
    return RedirectResponse("/ui/credentials", status_code=303)


# ------------------------------------------------------------------- gateway

_BAD_JSON = object()  # sentinel: the form held invalid JSON; a flash was set


def _parse_passthrough_form(request: Request, raw: str):
    """Empty string clears the config ({} -> validate_passthrough -> None);
    otherwise the textarea must hold the JSON object."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    import json

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _flash(request, f"Passthrough config is not valid JSON: {exc}", kind="warn")
        return _BAD_JSON


@router.get("/ui/routes")
def routes_page(request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)):
    if not (actor.has("routes:read") or actor.has("routes:read:all")):
        raise HTTPException(404, "Not found")
    routes = crud.visible_routes(db, actor)
    creds = crud.visible_credentials(db, actor)
    agents = crud.visible_agents(db, actor)
    can_write = actor.has("routes:create") or actor.has("routes:update:all")
    from ..config import get_settings as _gs
    from ..route_catalog import CATALOG

    return render(
        request, "routes.html", actor,
        routes=routes, creds=creds, agents=agents, can_write=can_write,
        catalog=CATALOG, issuer=_gs().issuer, nav="routes",
    )


@router.post("/ui/routes")
def routes_create(
    request: Request,
    slug: str = Form(...),
    description: str = Form(""),
    icon: str = Form(""),
    upstream_base: str = Form(...),
    credential_name: str = Form(...),
    inject_mode: str = Form("bearer"),
    inject_header: str = Form("Authorization"),
    methods: str = Form(""),
    prefixes: str = Form(""),
    rate_limit_per_minute: str = Form(""),
    daily_quota: str = Form(""),
    skip_tls_verify: str = Form(""),
    git_http: str = Form(""),
    passthrough: str = Form(""),
    icon_upload: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    pt_cfg = _parse_passthrough_form(request, passthrough)
    if pt_cfg is _BAD_JSON:
        return RedirectResponse("/ui/routes", status_code=303)
    val = icon.strip()
    is_url = val.lower().startswith(("http://", "https://"))
    route = crud.create_route(
        db, request, actor,
        slug=slug.strip(), description=description.strip(), icon=("" if is_url else val),
        upstream_base=upstream_base.strip(),
        credential_name=credential_name, inject_mode=inject_mode, inject_header=inject_header.strip(),
        allowed_methods=_split(methods), allowed_path_prefixes=_split(prefixes),
        rate_limit_per_minute=_int_field(rate_limit_per_minute, "rate limit"),
        daily_quota=_int_field(daily_quota, "daily quota"),
        verify_tls=(skip_tls_verify != "on"), git_http=(git_http == "on"),
        passthrough=pt_cfg,
    )
    if is_url:  # a pasted image URL is fetched server-side
        crud.set_route_icon_from_url(db, request, actor, route.id, val)
    elif icon_upload:
        crud.set_icon_upload(db, request, actor, "route", route.id, icon_upload)
    elif not val:  # blank -> best-effort auto-favicon
        crud.detect_route_icon(db, request, actor, route.id, only_if_empty=True)
    _flash(request, f"Route /gw/{slug} created. Grant agents below.")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/update")
def routes_update(
    request: Request,
    route_id: str,
    description: str = Form(""),
    icon: str = Form(""),
    upstream_base: str = Form(""),
    credential_name: str = Form(""),
    inject_mode: str = Form("bearer"),
    inject_header: str = Form("Authorization"),
    methods: str = Form(""),
    prefixes: str = Form(""),
    rate_limit_per_minute: str = Form(""),
    daily_quota: str = Form(""),
    active: str = Form("true"),
    skip_tls_verify: str = Form(""),
    git_http: str = Form(""),
    passthrough: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    pt_cfg = _parse_passthrough_form(request, passthrough)
    if pt_cfg is _BAD_JSON:
        return RedirectResponse("/ui/routes", status_code=303)
    crud.update_route(
        db, request, actor, route_id,
        description=description.strip(), upstream_base=upstream_base.strip() or None,
        credential_name=credential_name or None,
        inject_mode=inject_mode, inject_header=inject_header.strip(),
        allowed_methods=_split(methods), allowed_path_prefixes=_split(prefixes),
        rate_limit_per_minute=_int_field(rate_limit_per_minute, "rate limit"),
        daily_quota=_int_field(daily_quota, "daily quota"),
        active=(active == "true"),
        verify_tls=(skip_tls_verify != "on"), git_http=(git_http == "on"),
        passthrough=pt_cfg,
        # blank = keep current; a URL is handled below; else an emoji
        icon=(None if (icon.strip().lower().startswith(("http://", "https://")) or not icon.strip()) else icon.strip()),
    )
    val = icon.strip()
    if val.lower().startswith(("http://", "https://")):  # pasted image URL, fetched server-side
        _, ok = crud.set_route_icon_from_url(db, request, actor, route_id, val)
        _flash(request, "Route updated." if ok else "Route updated — but that image URL didn't return a usable image.")
    else:
        _flash(request, "Route updated.")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/icon")
def route_icon(
    request: Request,
    route_id: str,
    mode: str = Form(...),
    value: str = Form(""),
    data: str = Form(""),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    _flash(request, _icon_apply(db, request, actor, "route", route_id, mode, value, data))
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/detect-icon")
def routes_detect_icon(
    request: Request,
    route_id: str,
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    route = crud.detect_route_icon(db, request, actor, route_id)
    _flash(request, "Icon set from the upstream's favicon."
           if route.icon.startswith("data:") else "No favicon found on the upstream.")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/test")
def routes_test(
    request: Request,
    route_id: str,
    test_path: str = Form("/"),
    actor: Actor = Depends(ui_actor),
    db: Session = Depends(get_db),
):
    res = crud.probe_route(db, request, actor, route_id, test_path.strip() or "/")
    mark = "✓" if res["ok"] else "✗"
    # One favicon-discovery attempt rides every test click (Test / Discover).
    # Best-effort: a viewer without update permission just gets the probe.
    try:
        before = crud.get_visible_route(db, actor, route_id).icon
        route = crud.detect_route_icon(db, request, actor, route_id)
        if route.icon != before:
            disc = " · favicon discovered ✓"
        elif route.icon.startswith("data:"):
            disc = " · favicon unchanged"
        else:
            disc = " · no favicon found on the upstream"
    except HTTPException:
        disc = ""
    _flash(request, f"{mark} Test {test_path.strip() or '/'} — {res['detail']}{disc}")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/delete")
def routes_delete(
    request: Request, route_id: str,
    actor: Actor = Depends(ui_actor), db: Session = Depends(get_db),
):
    result = crud.delete_route(db, request, actor, route_id)
    _flash(request, f"Route /gw/{result['deleted']} deleted.", "warn")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/grant")
def routes_grant(
    request: Request, route_id: str, agent_id: str = Form(...),
    actor: Actor = Depends(ui_actor), db: Session = Depends(get_db),
):
    crud.grant_route(db, request, actor, route_id, agent_id)
    _flash(request, "Agent granted.")
    return RedirectResponse("/ui/routes", status_code=303)


@router.post("/ui/routes/{route_id}/revoke-grant")
def routes_revoke_grant(
    request: Request, route_id: str, agent_id: str = Form(...),
    actor: Actor = Depends(ui_actor), db: Session = Depends(get_db),
):
    crud.revoke_route_grant(db, request, actor, route_id, agent_id)
    _flash(request, "Grant revoked.", "warn")
    return RedirectResponse("/ui/routes", status_code=303)


# ---------------------------------------------------------------- access map


@router.get("/ui/access-map")
def access_map_page(
    request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    can_routes = actor.has("routes:read") or actor.has("routes:read:all")
    can_creds = actor.has("credentials:read") or actor.has("credentials:read:all")
    if not (can_routes or can_creds):
        raise HTTPException(404, "Not found")
    routes = crud.visible_routes(db, actor) if can_routes else []
    creds = crud.visible_credentials(db, actor) if can_creds else []
    graph = crud.build_access_graph(db, actor, routes, creds)
    scope_all = actor.has("routes:read:all") or actor.has("credentials:read:all")
    return render(request, "access_map.html", actor,
                  graph=graph, scope_all=scope_all, nav="map")


# -------------------------------------------------------------------- system


@router.get("/ui/system")
def system_page(
    request: Request, actor: Actor = Depends(ui_actor), db: Session = Depends(get_db)
):
    """Read-only architecture overview for admins. Names, types, booleans and
    key IDs only — never key material, secret values, or raw env dumps."""
    if not actor.is_admin:
        raise HTTPException(404, "Not found")
    from importlib.metadata import entry_points, version as _dist_version

    from .. import federation, keys, secretbox
    from ..db import get_engine
    from ..keystore import supports_named_keyrings

    s = get_settings()

    ring: list = []
    ks_healthy = False
    try:
        ring = keys.keys_info(db).get("default", [])
        ks_healthy = keys.keystore_healthy()
    except Exception:
        pass
    active_key = next((k for k in ring if k.get("active")), None)
    try:
        named_keyrings = supports_named_keyrings(s.keystore)
    except Exception:
        named_keyrings = False

    plugin_keystores = sorted(
        ep.name for ep in entry_points(group="cipherlatch.keystores")
    )
    enterprise_version = None
    for dist in ("cipherlatch-enterprise", "cipherlatch-enterprise"):
        try:
            enterprise_version = _dist_version(dist)
            break
        except Exception:
            continue

    info = {
        "keystore": {
            "backend": s.keystore,
            "enterprise_backend": s.keystore not in ("file", "vault"),
            "healthy": ks_healthy,
            "active_kid": (active_key or {}).get("kid"),
            "active_age": (active_key or {}).get("age_seconds"),
            "key_count": len(ring),
            "named_keyrings": named_keyrings,
            "retention_seconds": s.key_retention_seconds,
            "auto_rotate_seconds": s.key_max_age_seconds,
        },
        "credentials": {
            "backend": s.credential_backend,
            "ready": secretbox.backend_ready(),
            "scheme": ("AES-256-GCM · HKDF per-credential keys"
                       if s.credential_backend == "local" else "Vault Transit (server-side)"),
        },
        "security": {
            "dpop": s.dpop_enabled,
            "fips": s.fips_mode,
            "admin_keys": len(s.admin_api_key_list),
            "email_pinning": s.admin_email_pinning,
            "proxy_hops": s.trust_proxy_hops if s.trust_proxy_ip else 0,
            "session_hours": s.session_max_age // 3600,
            "lockout": f"{s.lockout_threshold} tries / {s.lockout_seconds}s",
            "token_ttl": s.token_ttl_seconds,
            "token_ttl_max": s.token_ttl_max_seconds,
        },
        "gateway": {
            "body_cap_mb": s.gateway_max_body_bytes // (1024 * 1024),
            "timeout_seconds": s.gateway_timeout_seconds,
            "policy_hook": bool(s.gateway_policy_url),
            "policy_fail_open": s.gateway_policy_fail_open,
            "ip_rate_per_minute": s.rate_limit_per_minute,
        },
        "identity": {
            "oidc_issuer": s.oidc_issuer or "",
            "jit": s.jit_provisioning,
            "default_role": s.default_role,
            "admin_emails": len(s.admin_email_list),
            "federated_issuers": len(federation.allowed_issuers()),
            "tenant_domains": len(s.tenant_domain_pairs),
        },
        "enterprise": {
            "installed": bool(plugin_keystores or enterprise_version),
            "version": enterprise_version,
            "keystores": plugin_keystores,
        },
        "runtime": {
            "issuer": s.issuer,
            "audience": s.audience,
            "database": get_engine().url.get_backend_name(),
            "metrics": s.metrics_enabled,
            "log_format": "json" if s.log_json else (s.log_format or "text"),
            "log_level": s.log_level,
        },
    }
    return render(request, "system.html", actor, info=info, nav="system")
