"""The enforcing proxy.

    agent --Bearer Cipherlatch-JWT--> /gw/<slug>/<subpath>  --> upstream (+injected cred)

Cipherlatch validates the token, confirms the agent holds a grant on the route,
enforces the method/path policy, injects the downstream credential
server-side, proxies the request, and audits the transaction. The agent never
sees the credential and can never reach anything outside the route's upstream.
"""

import base64
import time

import httpx
from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import StreamingResponse
from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import (
    audit, gateway_limits, gateway_policy as gp, lineage, policy_hook,
    policy_native, secretbox,
)
from ..authz import client_ip
from ..config import get_settings
from ..db import get_db
from ..keys import public_jwks
from ..models import Agent, GatewayRoute, RouteGrant

router = APIRouter(tags=["gateway"])

_PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def _deny(status: int, detail: str, headers: dict | None = None) -> Response:
    import json

    return Response(
        content=json.dumps({"error": "gateway_denied", "detail": detail}),
        status_code=status,
        media_type="application/json",
        headers=headers,
    )


# A 401 with this challenge lets protocol-native clients (git) know to retry
# with HTTP Basic credentials — without it, git aborts on the first request.
_AUTH_CHALLENGE = {"WWW-Authenticate": 'Basic realm="Cipherlatch"'}


async def _read_capped(request: Request, cap: int) -> bytes | None:
    """Read the request body but stop as soon as it exceeds `cap` bytes,
    returning None instead of buffering an unbounded upload into memory."""
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > cap:
            return None
    return bytes(buf)


def _authenticate_agent(
    db: Session, request: Request
) -> tuple[Agent | None, dict | None, str | None]:
    """Validate the presented Cipherlatch token (Bearer or DPoP), including
    revocation, and — for DPoP-bound tokens — require a matching fresh proof.
    Returns (agent, claims, error_detail)."""
    from ..tokens import verify_token

    settings = get_settings()
    auth = request.headers.get("Authorization", "")
    scheme, _, cred = auth.partition(" ")
    if scheme in ("Bearer", "DPoP"):
        token = cred
    elif scheme == "Basic" and cred:
        # Protocol-native CLIs (git) can only present the token via HTTP Basic
        # auth, where it rides as the password (user:token). It is validated
        # exactly like a Bearer token below, so transport adds no exposure.
        try:
            user, _, pw = base64.b64decode(cred).decode().partition(":")
        except Exception:
            return None, None, "malformed basic auth"
        token = pw or user
    else:
        token = ""
    if not token:
        return None, None, "missing bearer token"

    claims = verify_token(db, token)
    if claims is None:
        return None, None, "invalid, expired, or revoked token"

    # RFC 9449: a DPoP-bound token (cnf.jkt) requires a fresh proof from the
    # same key on this request, so a stolen token alone is useless.
    cnf = claims.get("cnf") or {}
    if cnf.get("jkt"):
        from .. import proof

        if scheme != "DPoP":
            return None, None, "DPoP-bound token requires DPoP scheme"
        try:
            jkt = proof.verify_dpop(request.headers.get("DPoP", ""), request.method, str(request.url))
        except proof.ProofError as exc:
            return None, None, f"DPoP proof: {exc}"
        if jkt != cnf["jkt"]:
            return None, None, "DPoP key mismatch"

    agent = db.scalar(select(Agent).where(Agent.client_id == claims.get("client_id")))
    if agent is None or not agent.active:
        return None, None, "unknown or revoked agent"
    return agent, claims, None


def _try_passthrough(db: Session, request: Request, slug: str, subpath: str):
    """Resolve a request bearing a *witnessed* ephemeral credential (credential
    lineage) instead of an agent token. Returns (route, agent, credential) or
    None. The witness row — created only inside an agent-authenticated brokered
    response — is what authenticates the caller and attributes the traffic."""
    auth = request.headers.get("Authorization", "")
    scheme, _, cred = auth.partition(" ")
    if scheme.lower() != "bearer" or not cred:
        return None
    witness = lineage.lookup(db, cred)
    if witness is None:
        return None
    route = db.get(GatewayRoute, witness.route_id)
    if route is None or not route.active or route.slug != slug:
        return None
    prefixes = (route.passthrough_config or {}).get("prefixes") or []
    path = "/" + subpath
    if not any(path.startswith(p) for p in prefixes):
        return None
    agent = db.get(Agent, witness.agent_id)
    if agent is None or not agent.active:
        return None
    return route, agent, cred


@router.api_route("/gw/{slug}/{subpath:path}", methods=_PROXY_METHODS)
@router.api_route("/gw/{slug}", methods=_PROXY_METHODS)
async def proxy(slug: str, request: Request, subpath: str = "", db: Session = Depends(get_db)):
    settings = get_settings()
    ip = client_ip(request)

    passthrough_cred: str | None = None
    agent, claims, err = _authenticate_agent(db, request)
    if err is not None:
        # Not an agent token — the one other identity we accept is a witnessed
        # ephemeral credential on a passthrough prefix (credential lineage).
        pt = _try_passthrough(db, request, slug, subpath)
        if pt is None:
            audit.record(db, "gateway.denied", ip=ip, detail={"slug": slug, "reason": err})
            return _deny(401, err, headers=_AUTH_CHALLENGE)
        route, agent, passthrough_cred = pt
        claims = None
    else:
        route = db.scalar(
            select(GatewayRoute).where(
                GatewayRoute.tenant_id == agent.tenant_id, GatewayRoute.slug == slug
            )
        )
        granted = route is not None and db.scalar(
            select(RouteGrant).where(RouteGrant.route_id == route.id, RouteGrant.agent_id == agent.id)
        )
        if route is None or not route.active or not granted:
            # Identical response for unknown / inactive / not-granted: no enumeration.
            audit.record(
                db, "gateway.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"slug": slug, "reason": "not_granted"},
            )
            return _deny(403, "route not available to this agent")

    try:
        gp.check_request_allowed(route, request.method, "/" + subpath)
        target = gp.build_upstream_url(route, subpath)
    except Exception as exc:
        detail = getattr(exc, "detail", str(exc))
        audit.record(
            db, "gateway.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "method": request.method, "path": "/" + subpath, "reason": detail},
        )
        return _deny(getattr(exc, "status_code", 403), detail)

    # Rate/budget limits (per granted agent, per route).
    limited = gateway_limits.check_and_count(route, agent.id)
    if limited is not None:
        audit.record(
            db, "gateway.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": limited},
        )
        return _deny(429, "route rate limit exceeded" if limited == "rate_limited"
                     else "route daily quota exceeded")

    # Native contextual policies (change freeze, business hours, CIDR fence):
    # additive veto between the built-in checks and the external hook. Applies
    # to relayed (passthrough) requests too — they're attributed to an agent.
    denial = policy_native.evaluate(db, route=route, agent=agent, ip=ip)
    if denial is not None:
        policy, reason = denial
        audit.record(
            db, "policy.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "policy": policy.name, "type": policy.type,
                    "reason": reason},
        )
        return _deny(403, f"denied by policy '{policy.name}': {reason}")

    # External policy hook (OPA / cedar-agent), when configured.
    if policy_hook.enabled():
        allowed, reason = policy_hook.evaluate({
            "tenant": agent.tenant.slug,
            "agent": {"id": agent.id, "client_id": agent.client_id, "name": agent.name,
                      "owner": agent.owner.email if agent.owner else None},
            "route": {"slug": route.slug, "upstream_base": route.upstream_base},
            "request": {"method": request.method, "path": "/" + subpath},
            "scopes": (claims.get("scope") or "").split() if claims else [],
        })
        if not allowed:
            audit.record(
                db, "gateway.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"slug": slug, "reason": reason},
            )
            return _deny(403, "denied by policy")

    # Git smart-HTTP: stream both directions past the body cap (packfiles are
    # large) and inject the credential as Basic. All policy checks above still
    # apply — git-mode only changes the transport, not the enforcement.
    if route.git_http and passthrough_cred is None:
        return await _git_http_proxy(db, request, route, agent, ip, slug, subpath, target, settings)

    if passthrough_cred is not None:
        # Credential-lineage relay: forward the caller's witnessed ephemeral
        # credential instead of injecting — the upstream minted it and expects
        # it back. The stored route credential is never decrypted on this path.
        fwd_headers = gp.forward_request_headers(dict(request.headers))
        fwd_headers["Authorization"] = f"Bearer {passthrough_cred}"
    else:
        secret = secretbox.decrypt(route.credential.secret_encrypted)
        inj_name, inj_value = gp.injected_auth_header(route.inject_mode, route.inject_header, secret)
        fwd_headers = gp.inject_credential_header(
            gp.forward_request_headers(dict(request.headers)), inj_name, inj_value
        )

    # Read the client body under a hard cap so an oversized upload can't be
    # buffered into memory (the cap applies before anything is forwarded).
    cap = settings.gateway_max_body_bytes
    body = await _read_capped(request, cap)
    if body is None:
        audit.record(
            db, "gateway.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": "request_too_large"},
        )
        return _deny(413, "request body too large")
    if request.url.query:
        target = f"{target}?{request.url.query}"

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=settings.gateway_timeout_seconds, verify=route.verify_tls
        ) as client:
            async with client.stream(
                request.method, target, headers=fwd_headers, content=body or None
            ) as upstream:
                # Stream the response with the same cap, aborting before an
                # oversized (or hostile) upstream body is fully buffered.
                buf = bytearray()
                too_large = False
                async for chunk in upstream.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > cap:
                        too_large = True
                        break
                status_code = upstream.status_code
                resp_headers = gp.forward_response_headers(upstream.headers)
                content_type = upstream.headers.get("content-type")
    except httpx.TimeoutException:
        audit.record(
            db, "gateway.error", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": "upstream_timeout"},
        )
        return _deny(504, "upstream timeout")
    except httpx.HTTPError:
        audit.record(
            db, "gateway.error", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": "upstream_unreachable"},
        )
        return _deny(502, "upstream unreachable")

    if too_large:
        audit.record(
            db, "gateway.error", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": "response_too_large", "bytes": len(buf)},
        )
        return _deny(502, "upstream response too large")
    content = bytes(buf)

    # Credential lineage: witness ephemeral credentials the upstream just minted
    # in this brokered response (hash only), so the follow-up requests that
    # authenticate with them can be relayed on the passthrough prefixes.
    if (
        passthrough_cred is None
        and route.passthrough_config
        and status_code < 300
    ):
        captured = lineage.capture(db, route, agent, "/" + subpath, content, content_type)
        if captured:
            audit.record(
                db, "gateway.credential_witnessed", tenant_id=agent.tenant_id,
                agent_id=agent.id, ip=ip,
                detail={"slug": slug, "path": "/" + subpath, "count": captured,
                        "ttl_seconds": (route.passthrough_config or {}).get("ttl_seconds")},
            )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    audit.record(
        db, "gateway.proxied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
        detail={
            "slug": slug, "method": request.method, "path": "/" + subpath,
            "status": upstream.status_code, "bytes": len(content), "ms": elapsed_ms,
            **({"passthrough": True} if passthrough_cred is not None else {}),
        },
    )
    return Response(
        content=content,
        status_code=status_code,
        headers=resp_headers,
        media_type=content_type,
    )


# Response headers safe to forward for a git stream. Unlike the REST path we
# KEEP content-encoding (raw, still-encoded bytes are forwarded) and let
# StreamingResponse own content-type (via media_type) and the framing.
_GIT_STRIP_RESPONSE_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
    "content-type", "set-cookie",
}


def _git_response_headers(headers) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _GIT_STRIP_RESPONSE_HEADERS}


async def _git_http_proxy(db, request, route, agent, ip, slug, subpath, target, settings):
    """Streaming passthrough for git smart-HTTP (clone / fetch / push).

    The agent authenticated with a short-lived Cipherlatch token (presented as
    the Basic password, since git can't send a Bearer). We inject the stored git
    credential as HTTP Basic to the upstream and stream both directions with no
    body cap and no read timeout, so large packfiles ride through.
    """
    secret = secretbox.decrypt(route.credential.secret_encrypted)
    # git-http Basic auth is <user>:<pat>. A bare PAT gets the conventional
    # `oauth2` username (accepted by GitLab and GitHub); a secret that already
    # carries a colon is taken verbatim as user:pass.
    userpass = secret if ":" in secret else f"oauth2:{secret}"
    basic = base64.b64encode(userpass.encode()).decode()

    if request.url.query:
        target = f"{target}?{request.url.query}"

    # forward_request_headers already strips the client's Authorization (its
    # Cipherlatch token); we set the injected credential in its place.
    fwd = gp.forward_request_headers(dict(request.headers))
    fwd["Authorization"] = f"Basic {basic}"

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.gateway_timeout_seconds, read=None, write=None),
        verify=route.verify_tls,
    )
    try:
        req = client.build_request(
            request.method, target, headers=fwd, content=request.stream()
        )
        upstream = await client.send(req, stream=True)
    except httpx.HTTPError:
        await client.aclose()
        audit.record(
            db, "gateway.error", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"slug": slug, "reason": "upstream_unreachable", "git": True},
        )
        return _deny(502, "upstream unreachable")

    audit.record(
        db, "gateway.proxied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
        detail={"slug": slug, "method": request.method, "path": "/" + subpath,
                "status": upstream.status_code, "git": True},
    )

    async def body():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    return StreamingResponse(
        body(),
        status_code=upstream.status_code,
        headers=_git_response_headers(upstream.headers),
        media_type=upstream.headers.get("content-type"),
    )
