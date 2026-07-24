from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import JSONResponse
from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, secretbox
from ..authz import client_ip
from ..config import get_settings
from ..db import get_db
from ..keys import public_jwks
from ..models import Agent, CredentialGrant, DownstreamCredential
from ..security import DUMMY_SECRET_HASH, verify_secret
from ..tokens import mint_token

router = APIRouter(tags=["oauth"])

GRANT_CLIENT_CREDENTIALS = "client_credentials"
GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_AUTHORIZATION_CODE = "authorization_code"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"


def _error(status: int, code: str, description: str) -> JSONResponse:
    # RFC 6749 §5.2 error format
    return JSONResponse(
        status_code=status,
        content={"error": code, "error_description": description},
        headers={"Cache-Control": "no-store"},
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime | None) -> datetime | None:
    # SQLite round-trips naive datetimes; treat stored values as UTC.
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _valid_resource(resource: str) -> bool:
    parsed = urlparse(resource)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and not parsed.fragment


def _owner_suspended(agent: Agent) -> bool:
    """An agent acts *for* its owner; a deactivated or deleted owner suspends
    every delegation they granted (the SCIM/admin deprovisioning story)."""
    owner = agent.owner
    return owner is None or not owner.active or owner.deleted_at is not None


def _authenticate_client(
    db: Session, ip: str, client_id: str, client_secret: str
) -> tuple[Agent | None, JSONResponse | None]:
    """Shared client authentication: lockout window, timing-equalized secret
    check, failure counting, revocation. Returns (agent, error_response)."""
    settings = get_settings()
    agent = db.scalar(select(Agent).where(Agent.client_id == client_id))

    locked_until = _as_aware(agent.locked_until) if agent else None
    if agent is not None and locked_until is not None and locked_until > _now():
        audit.record(
            db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "locked_out", "locked_until": locked_until.isoformat()},
        )
        return None, _error(401, "invalid_client", "Client temporarily locked; try again later")

    # Always run the hash comparison so unknown client_ids aren't distinguishable by timing.
    secret_ok = verify_secret(client_secret, agent.secret_hash if agent else DUMMY_SECRET_HASH)
    if agent is None or not secret_ok:
        if agent is not None:
            agent.failed_attempts += 1
            if agent.failed_attempts >= settings.lockout_threshold:
                agent.locked_until = _now() + timedelta(seconds=settings.lockout_seconds)
                agent.failed_attempts = 0
                db.commit()
                audit.record(
                    db, "token.locked", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                    detail={"lockout_seconds": settings.lockout_seconds},
                )
            else:
                db.commit()
            audit.record(
                db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"reason": "bad_credentials"},
            )
        else:
            audit.record(
                db, "token.denied", ip=ip,
                detail={"client_id": client_id, "reason": "bad_credentials"},
            )
        return None, _error(401, "invalid_client", "Unknown client or bad secret")

    if not agent.active:
        audit.record(
            db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "revoked"},
        )
        return None, _error(401, "invalid_client", "Agent is revoked")

    if _owner_suspended(agent):
        audit.record(
            db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "owner_suspended"},
        )
        return None, _error(401, "invalid_client", "Agent owner is suspended")

    if agent.failed_attempts or agent.locked_until:
        agent.failed_attempts = 0
        agent.locked_until = None
        db.commit()

    return agent, None


@router.post("/oauth/token")
def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    scope: str = Form(""),
    resource: str = Form(""),
    subject_token: str = Form(""),
    subject_token_type: str = Form(""),
    audience: str = Form(""),
    client_assertion: str = Form(""),
    client_assertion_type: str = Form(""),
    public_key: str = Form(""),  # provider param (ssh-ca: agent's OpenSSH pubkey)
    code: str = Form(""),
    redirect_uri: str = Form(""),
    code_verifier: str = Form(""),
    db: Session = Depends(get_db),
):
    ip = client_ip(request)

    if grant_type == GRANT_CLIENT_CREDENTIALS:
        return _client_credentials(
            request, db, ip, client_id, client_secret, scope, resource,
            client_assertion, client_assertion_type,
        )
    if grant_type == GRANT_TOKEN_EXCHANGE:
        return _token_exchange(
            request, db, ip, client_id, client_secret, subject_token, subject_token_type,
            audience, client_assertion, params={"public_key": public_key},
        )
    if grant_type == GRANT_AUTHORIZATION_CODE and get_settings().mcp_as_enabled:
        return _authorization_code(request, db, ip, client_id, code,
                                   redirect_uri, code_verifier)
    return _error(400, "unsupported_grant_type",
                  "Supported: client_credentials, token-exchange")


def _authenticate_with_assertion(db, ip, client_id, assertion):
    """Assertion-based client auth. Routed by the assertion's (unverified)
    iss claim: iss == client_id is private_key_jwt (RFC 7523, the agent's
    registered key); an external iss matching the agent's federated binding
    is workload identity federation (SPIFFE JWT-SVID, K8s SA token, ...).
    Returns (agent, error_response)."""
    from .. import federation, proof

    settings = get_settings()
    agent = db.scalar(select(Agent).where(Agent.client_id == client_id))
    if agent is None or not agent.active:
        audit.record(db, "token.denied", ip=ip,
                     detail={"client_id": client_id, "reason": "bad_client_assertion"})
        return None, _error(401, "invalid_client", "Unknown client or bad assertion")

    assertion_iss = federation.peek_issuer(assertion)
    if agent.federated_issuer and assertion_iss != client_id:
        try:
            federation.verify_federated_assertion(assertion, agent)
        except federation.FederationError as exc:
            audit.record(db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                         detail={"reason": "bad_federated_assertion", "detail": str(exc)})
            return None, _error(401, "invalid_client", "Client assertion invalid")
    elif agent.auth_public_jwk:
        try:
            proof.verify_client_assertion(assertion, agent.auth_public_jwk, settings.issuer, client_id)
        except proof.ProofError as exc:
            audit.record(db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                         detail={"reason": "bad_client_assertion", "detail": str(exc)})
            return None, _error(401, "invalid_client", "Client assertion invalid")
    else:
        audit.record(db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                     detail={"reason": "no_assertion_authenticator"})
        return None, _error(401, "invalid_client", "Unknown client or bad assertion")

    if _owner_suspended(agent):
        audit.record(db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                     detail={"reason": "owner_suspended"})
        return None, _error(401, "invalid_client", "Agent owner is suspended")
    return agent, None


def _client_credentials(
    request, db, ip, client_id, client_secret, scope, resource,
    client_assertion="", client_assertion_type="",
):
    settings = get_settings()
    if client_assertion:
        agent, err = _authenticate_with_assertion(db, ip, client_id, client_assertion)
    else:
        agent, err = _authenticate_client(db, ip, client_id, client_secret)
    if err is not None:
        return err

    allowed = set(agent.allowed_scopes or [])
    requested = scope.split() if scope else sorted(allowed)
    excess = set(requested) - allowed
    if excess:
        audit.record(
            db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "scope_not_granted", "scopes": sorted(excess)},
        )
        return _error(400, "invalid_scope", f"Scope(s) not granted: {' '.join(sorted(excess))}")

    # RFC 8707: bind the token audience to the requested resource.
    aud = settings.audience
    if resource:
        if not _valid_resource(resource):
            return _error(400, "invalid_target", "resource must be an absolute http(s) URI without fragment")
        allowed_resources = agent.allowed_resources or []
        if allowed_resources and resource not in allowed_resources:
            audit.record(
                db, "token.denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"reason": "resource_not_granted", "resource": resource},
            )
            return _error(400, "invalid_target", "Resource not granted to this agent")
        aud = resource

    # DPoP (RFC 9449): if the client presents a proof, bind the token to it.
    cnf_jkt = None
    token_type = "Bearer"
    dpop_header = request.headers.get("DPoP", "")
    if settings.dpop_enabled and dpop_header:
        from .. import proof

        try:
            cnf_jkt = proof.verify_dpop(dpop_header, "POST", str(request.url))
            token_type = "DPoP"
        except proof.ProofError as exc:
            return _error(400, "invalid_dpop_proof", str(exc))

    access_token, jti, expires_in = mint_token(agent, requested, audience=aud, cnf_jkt=cnf_jkt)
    audit.record(
        db, "token.issued", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
        detail={"scopes": requested, "aud": aud, "jti": jti, "dpop": bool(cnf_jkt)},
    )
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": expires_in,
            "scope": " ".join(requested),
        },
        headers={"Cache-Control": "no-store"},
    )


def _authorization_code(request, db, ip, client_id, code, redirect_uri, code_verifier):
    """OAuth 2.1 code redemption for MCP clients (public clients registered by
    Client ID Metadata Document; no client secret — PKCE is the proof). A
    replayed code revokes the token it originally minted (§4.1.2 SHOULD)."""
    import base64
    import hashlib
    from datetime import timedelta

    from ..models import AuthorizationCode, ConsentGrant, MCPClient, Principal, RevokedToken
    from ..tokens import mint_user_token

    settings = get_settings()
    if not code or not redirect_uri or not code_verifier or not client_id:
        return _error(400, "invalid_request",
                      "client_id, code, redirect_uri and code_verifier are required")

    row = db.scalar(select(AuthorizationCode).where(
        AuthorizationCode.code_sha256 == hashlib.sha256(code.encode()).hexdigest()
    ))
    if row is None:
        audit.record(db, "token.denied", ip=ip,
                     detail={"grant": "authorization_code", "reason": "unknown_code"})
        return _error(400, "invalid_grant", "Authorization code is invalid")

    if row.used_at is not None:
        # Replay: burn the token this code minted, then refuse.
        if row.issued_jti and db.get(RevokedToken, row.issued_jti) is None:
            db.add(RevokedToken(
                jti=row.issued_jti, agent_id=None,
                expires_at=_now() + timedelta(seconds=settings.mcp_token_ttl_seconds),
            ))
            db.commit()
        audit.record(db, "token.denied", tenant_id=row.tenant_id, ip=ip,
                     detail={"grant": "authorization_code", "reason": "code_replayed",
                             "revoked_jti": row.issued_jti})
        return _error(400, "invalid_grant", "Authorization code already used")

    expires_at = _as_aware(row.expires_at)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=").decode()
    )
    if (
        expires_at < _now()
        or client_id != row.client_id_url
        or redirect_uri != row.redirect_uri
        or challenge != row.code_challenge
    ):
        audit.record(db, "token.denied", tenant_id=row.tenant_id, ip=ip,
                     detail={"grant": "authorization_code", "reason": "code_mismatch"})
        return _error(400, "invalid_grant",
                      "Authorization code is expired or does not match this request")

    principal = db.get(Principal, row.principal_id)
    client = db.scalar(select(MCPClient).where(MCPClient.client_id_url == client_id))
    consent = db.scalar(select(ConsentGrant).where(
        ConsentGrant.principal_id == row.principal_id,
        ConsentGrant.client_id_url == client_id,
        ConsentGrant.resource == row.resource,
        ConsentGrant.revoked_at.is_(None),
    ))
    if (
        principal is None or not principal.active or principal.deleted_at is not None
        or client is None or not client.active
        or consent is None
    ):
        audit.record(db, "token.denied", tenant_id=row.tenant_id, ip=ip,
                     detail={"grant": "authorization_code", "reason": "grant_withdrawn"})
        return _error(400, "invalid_grant",
                      "The authorization behind this code has been withdrawn")

    # DPoP (RFC 9449): same optional sender-constraining as client_credentials.
    cnf_jkt = None
    token_type = "Bearer"
    dpop_header = request.headers.get("DPoP", "")
    if settings.dpop_enabled and dpop_header:
        from .. import proof

        try:
            cnf_jkt = proof.verify_dpop(dpop_header, "POST", str(request.url))
            token_type = "DPoP"
        except proof.ProofError as exc:
            return _error(400, "invalid_dpop_proof", str(exc))

    access_token, jti, expires_in = mint_user_token(
        principal, client_id, row.scopes or [], row.resource, cnf_jkt=cnf_jkt,
    )
    row.used_at = _now()
    row.issued_jti = jti
    db.commit()
    audit.record(db, "token.issued", tenant_id=row.tenant_id, ip=ip,
                 actor=principal.email,
                 detail={"grant": "authorization_code", "client_id": client_id,
                         "aud": row.resource, "scopes": row.scopes or [],
                         "jti": jti, "dpop": bool(cnf_jkt)})
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": expires_in,
            "scope": " ".join(row.scopes or []),
        },
        headers={"Cache-Control": "no-store"},
    )


def _token_exchange(request, db, ip, client_id, client_secret, subject_token,
                    subject_token_type, audience, client_assertion="", params=None):
    """RFC 8693: a granted agent trades its (fresh) Cipherlatch token for a
    downstream credential. Requires client auth AND a valid subject token
    for the same agent, so neither a stolen token nor a stolen secret is
    sufficient alone."""
    settings = get_settings()

    if client_assertion:
        agent, err = _authenticate_with_assertion(db, ip, client_id, client_assertion)
    else:
        agent, err = _authenticate_client(db, ip, client_id, client_secret)
    if err is not None:
        return err

    if subject_token_type != TOKEN_TYPE_ACCESS:
        return _error(400, "invalid_request",
                      f"subject_token_type must be {TOKEN_TYPE_ACCESS}")
    if not subject_token or not audience:
        return _error(400, "invalid_request", "subject_token and audience are required")

    # Validate the subject token through the canonical verifier so the exchange
    # honors the SAME revocation controls as the gateway and introspection: the
    # per-jti denylist AND the per-agent generation counter (token_gen). A raw
    # decode here (signature/iss/exp only) would let a revoked-but-unexpired
    # token still be cashed in for a downstream credential — defeating
    # revocation on the highest-value path. The client_id binding is kept so a
    # token issued to a different client can't be exchanged here.
    from ..tokens import verify_token

    claims = verify_token(db, subject_token)
    if claims is None:
        audit.record(
            db, "token.exchange_denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "subject_token_invalid", "audience": audience},
        )
        return _error(400, "invalid_grant", "subject_token is invalid, expired, or revoked")
    if claims.get("client_id") != agent.client_id:
        audit.record(
            db, "token.exchange_denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "subject_token_mismatch", "audience": audience},
        )
        return _error(400, "invalid_grant", "subject_token was not issued to this client")

    # If the subject token is DPoP-bound, exchanging it requires proving
    # possession of the same key — consistent with the gateway, so a stolen
    # sender-constrained token can't be cashed in for a downstream credential.
    cnf = claims.get("cnf") or {}
    if cnf.get("jkt"):
        from .. import proof

        try:
            jkt = proof.verify_dpop(request.headers.get("DPoP", ""), "POST", str(request.url))
        except proof.ProofError as exc:
            return _error(400, "invalid_dpop_proof", str(exc))
        if jkt != cnf["jkt"]:
            audit.record(
                db, "token.exchange_denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"reason": "subject_token_dpop_mismatch", "audience": audience},
            )
            return _error(400, "invalid_grant", "subject_token DPoP binding not proven")

    cred = db.scalar(
        select(DownstreamCredential).where(
            DownstreamCredential.tenant_id == agent.tenant_id,
            DownstreamCredential.name == audience,
        )
    )
    grant = None
    if cred is not None:
        grant = db.scalar(
            select(CredentialGrant).where(
                CredentialGrant.credential_id == cred.id,
                CredentialGrant.agent_id == agent.id,
            )
        )
    if cred is None or grant is None:
        # Identical response for "unknown" and "not granted": no enumeration.
        audit.record(
            db, "token.exchange_denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"reason": "not_granted" if cred is not None else "unknown_credential",
                    "audience": audience},
        )
        return _error(400, "invalid_target", "Credential not available to this agent")

    seed = secretbox.decrypt(cred.secret_encrypted)

    # Provider-backed: mint short-lived material scoped to this agent instead
    # of returning the stored secret.
    if cred.provider:
        from .. import credential_providers as cp

        try:
            provider = cp.get_provider(cred.provider)
            issued = provider.issue(cp.IssueContext(
                seed=seed, config=cred.provider_config or {},
                agent_id=agent.id, agent_name=agent.name,
                owner_email=agent.owner.email if agent.owner else "",
                jti=claims.get("jti", ""), params=params or {},
            ))
        except cp.ProviderError as exc:
            audit.record(
                db, "token.exchange_denied", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
                detail={"reason": "provider_error", "credential": cred.name, "detail": str(exc)},
            )
            return _error(400, "invalid_request", str(exc))
        cred.last_exchanged_at = _now()
        db.commit()
        audit.record(
            db, "token.exchanged", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
            detail={"credential": cred.name, **issued.detail},
        )
        return JSONResponse(
            content={
                "access_token": issued.secret,
                "issued_token_type": issued.token_type,
                "token_type": "N_A",  # not a bearer token; material is protocol-specific
                "expires_in": issued.expires_in,
            },
            headers={"Cache-Control": "no-store"},
        )

    cred.last_exchanged_at = _now()
    db.commit()
    audit.record(
        db, "token.exchanged", tenant_id=agent.tenant_id, agent_id=agent.id, ip=ip,
        detail={"credential": cred.name},
    )
    return JSONResponse(
        content={
            "access_token": seed,
            "issued_token_type": TOKEN_TYPE_ACCESS,
            "token_type": "Bearer",
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/oauth/introspect")
def introspect(
    request: Request,
    token: str = Form(...),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    db: Session = Depends(get_db),
):
    """RFC 7662: a resource server checks whether a token is active. Caller
    authenticates as any valid agent (client_credentials) — introspection is
    not public."""
    from ..tokens import verify_token

    caller, err = _authenticate_client(db, client_ip(request), client_id, client_secret)
    if err is not None:
        return err

    claims = verify_token(db, token)
    if claims is None:
        return JSONResponse({"active": False}, headers={"Cache-Control": "no-store"})
    return JSONResponse(
        {
            "active": True,
            "client_id": claims.get("client_id"),
            "sub": claims.get("sub"),
            "scope": claims.get("scope"),
            "aud": claims.get("aud"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "owner": claims.get("owner"),
            "cnf": claims.get("cnf"),
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/oauth/revoke")
def revoke(
    request: Request,
    token: str = Form(...),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    db: Session = Depends(get_db),
):
    """RFC 7009: an agent revokes one of its own tokens by jti. Always returns
    200 per spec (even for unknown/foreign tokens), but only records a
    revocation when the token verifiably belongs to the authenticated agent."""
    from datetime import datetime, timezone

    from ..models import RevokedToken
    from ..tokens import verify_token

    agent, err = _authenticate_client(db, client_ip(request), client_id, client_secret)
    if err is not None:
        return err

    claims = verify_token(db, token)
    if claims is not None and claims.get("client_id") == agent.client_id:
        jti = claims.get("jti")
        if jti and db.get(RevokedToken, jti) is None:
            exp = datetime.fromtimestamp(claims.get("exp", 0), tz=timezone.utc)
            db.add(RevokedToken(jti=jti, agent_id=agent.id, expires_at=exp))
            audit.record(
                db, "token.revoked", tenant_id=agent.tenant_id, agent_id=agent.id,
                ip=client_ip(request), detail={"jti": jti},
            )
    return Response(status_code=200)
