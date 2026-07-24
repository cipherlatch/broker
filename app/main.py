import hashlib
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import itsdangerous
from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware


class Sha256SessionMiddleware(SessionMiddleware):
    """Starlette signs session cookies with HMAC-SHA1 by default; SHA-1 is not
    FIPS-approved. Sign with HMAC-SHA256 instead. (Existing SHA-1 cookies stop
    validating, so logged-in users simply re-authenticate via SSO.)"""

    def __init__(self, app, secret_key, **kwargs):
        super().__init__(app, secret_key, **kwargs)
        self.signer = itsdangerous.TimestampSigner(
            str(secret_key), digest_method=hashlib.sha256
        )

from .config import get_settings
from .db import init_db
from .keys import get_signing_key, maybe_auto_rotate
from .observability import http_metrics_middleware, metrics_endpoint, setup_logging
from .routers import (
    agents, audit_api, auth, authorize, automation, credentials_api, gateway,
    keys_api, mcp_api, oauth, policies_api, roles, routes_api, scim,
    service_keys_api, tenants, ui, users, wellknown,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.fips_mode:
        from . import fips

        fips.enforce()  # abort boot rather than run non-compliantly
    if settings.db_auto_create:
        init_db()
    from . import secretbox

    if secretbox.credential_key_is_weak():
        import logging

        logging.getLogger("cipherlatch").warning(
            "BROKER_CREDENTIAL_KEY is shorter than %d chars — the credential KEK "
            "is derived with a fast KDF, so use a high-entropy value "
            "(e.g. `python -c 'import secrets;print(secrets.token_urlsafe(32))'`)",
            secretbox.MIN_CREDENTIAL_KEY_LEN,
        )
    get_signing_key()  # generate on first boot
    rotated = maybe_auto_rotate(settings.key_max_age_seconds)
    if rotated:
        import logging

        logging.getLogger("cipherlatch").info("startup key rotation -> kid %s", rotated)
    if not settings.admin_api_key_list:
        # Keyless is a supported posture; make the recovery story explicit in
        # the boot log when no admin login exists yet either.
        import logging

        from sqlalchemy.orm import Session

        from . import crud
        from .db import get_engine

        try:
            with Session(get_engine()) as db:
                has_admin = crud.any_active_admin_exists(db)
        except Exception:
            has_admin = True
        if not has_admin:
            logging.getLogger("cipherlatch").warning(
                "no admin key configured and no active admin user — recover "
                "with `python -m app.admin promote <email>` from a shell"
            )
    yield


async def security_headers(request: Request, call_next):
    """Baseline hardening headers for the server-rendered UI (and cheap on the
    API). CSP is deliberately strict: the UI ships its own CSS/JS from /static
    and inlines only a small theme bootstrap, so no third-party origins are
    allowed and framing is denied outright (clickjacking defense)."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'",
    )
    if get_settings().issuer.startswith("https://"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
    return response


async def origin_guard(request: Request, call_next):
    """CSRF defense-in-depth for cookie-session state changes: cross-origin
    browser writes are rejected. Header-authenticated API calls (no Origin)
    are unaffected, as is the session cookie's SameSite=lax attribute."""
    if request.method in ("POST", "PATCH", "PUT", "DELETE"):
        origin = request.headers.get("origin")
        if origin and request.cookies.get("cipherlatch_session"):
            origin_host = urlparse(origin).netloc
            if origin_host and origin_host != request.headers.get("host", ""):
                return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})
    return await call_next(request)


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_json, settings.log_level, settings.log_format)
    app = FastAPI(
        title="Cipherlatch — Broker for Agentic Access Management",
        version="0.3.0",
        lifespan=lifespan,
        # FastAPI's built-in Swagger UI / ReDoc load their JS+CSS from a public
        # CDN, which the strict Content-Security-Policy (see security_headers)
        # blocks. Disable the defaults and serve Swagger UI from self-hosted
        # /static assets instead (custom_swagger_ui below), so /docs works under
        # the no-third-party CSP and in air-gapped deployments.
        docs_url=None,
        redoc_url=None,
    )

    session_secret = settings.session_secret
    if not session_secret:
        # Ephemeral fallback keeps dev/tests working; sessions reset on restart.
        session_secret = secrets.token_urlsafe(32)

    from .ratelimit import rate_limit_middleware

    app.middleware("http")(security_headers)
    app.middleware("http")(origin_guard)
    app.middleware("http")(rate_limit_middleware)
    if settings.metrics_enabled:
        app.middleware("http")(http_metrics_middleware)
        app.add_api_route("/metrics", metrics_endpoint, include_in_schema=False)
    app.add_middleware(
        Sha256SessionMiddleware,
        secret_key=session_secret,
        session_cookie="cipherlatch_session",
        max_age=settings.session_max_age,
        same_site="lax",
        https_only=settings.issuer.startswith("https://"),
    )

    app.include_router(oauth.router)
    app.include_router(authorize.router)
    app.include_router(mcp_api.router)
    app.include_router(wellknown.router)
    app.include_router(agents.router)
    app.include_router(users.router)
    app.include_router(roles.router)
    app.include_router(service_keys_api.router)
    app.include_router(keys_api.router)
    app.include_router(credentials_api.router)
    app.include_router(routes_api.router)
    app.include_router(policies_api.router)
    app.include_router(tenants.router)
    app.include_router(gateway.router)
    app.include_router(audit_api.router)
    app.include_router(auth.router)
    app.include_router(scim.router)
    app.include_router(automation.router)
    app.include_router(ui.router)

    # SCIM errors use the RFC 7644 error schema, not FastAPI's {"detail": ...}.
    app.add_exception_handler(
        scim.ScimError, lambda request, exc: scim._scim_error_response(exc)
    )

    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
        name="static",
    )

    @app.get("/docs", include_in_schema=False)
    def custom_swagger_ui():
        # Self-hosted Swagger UI: assets served from /static (vendored
        # swagger-ui-dist), so no external origin is needed and the strict CSP
        # is satisfied. See docs_url=None on the FastAPI() constructor above.
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=f"{app.title} — API docs",
            swagger_js_url="/static/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui.css",
            swagger_favicon_url="/static/favicon.png",
        )

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        """Readiness for load balancers: DB reachable and keystore usable."""
        from sqlalchemy import text

        from .db import get_engine
        from .keys import keystore_healthy

        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        ks_ok = keystore_healthy()
        content = {"database": "ok" if db_ok else "unavailable",
                   "keystore": "ok" if ks_ok else "unavailable"}
        fips_ok = True
        if get_settings().fips_mode:
            from . import fips

            # Boot already enforced this; keep reporting it so a provider
            # regression flips readiness rather than passing silently.
            fips_ok = fips._openssl_fips_enabled()
            content["fips"] = "ok" if fips_ok else "unavailable"
        if db_ok and not get_settings().admin_api_key_list:
            # Running keyless is a supported posture, but flag the state where
            # the ONLY way back in is the host-shell CLI. Warning, not a 503 —
            # never take a serving broker out of rotation over it.
            from sqlalchemy.orm import Session

            from . import crud

            try:
                with Session(get_engine()) as check_db:
                    has_admin = crud.any_active_admin_exists(check_db)
            except Exception:
                has_admin = True  # don't warn on a half-initialized schema
            content["admin_access"] = (
                "ok" if has_admin
                else "warning: no admin key configured and no active admin user "
                     "(recover via `python -m app.admin promote <email>`)"
            )
        status = 200 if (db_ok and ks_ok and fips_ok) else 503
        return JSONResponse(status_code=status, content=content)

    return app


app = create_app()
