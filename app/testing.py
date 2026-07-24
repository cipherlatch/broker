"""Reusable test-app factory.

The core suite's conftest builds its `make_app` fixture from this, and plugin
packages (cipherlatch-enterprise) import it so their suites boot the app exactly the
way core tests do — one definition instead of drifting copies. Kept
pytest-agnostic: the caller supplies monkeypatch/tmp_path equivalents.
"""

import os

ADMIN_KEY = "test-admin-key"


def build_app(monkeypatch, tmp_path, env: dict):
    """Boot a fresh app instance with a hermetic BROKER_* environment.

    Ambient BROKER_* variables (a deploy env or CI variable like
    BROKER_KEYSTORE must never change test behavior) are cleared first, then
    only the declared defaults + overrides are set. CI sets TEST_DATABASE_URL
    to run against real Postgres; otherwise each call gets a throwaway SQLite
    file under tmp_path.
    """
    for key in [k for k in os.environ if k.startswith("BROKER_")]:
        monkeypatch.delenv(key, raising=False)

    db_url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path}/broker.db"
    defaults = {
        "BROKER_DATABASE_URL": db_url,
        "BROKER_KEYS_DIR": str(tmp_path / "keys"),
        "BROKER_ADMIN_API_KEY": ADMIN_KEY,
        "BROKER_ISSUER": "http://testserver",
        "BROKER_SESSION_SECRET": "test-session-secret",
        "BROKER_OIDC_ISSUER": "https://idp.test",
        "BROKER_OIDC_CLIENT_ID": "cipherlatch-test",
        "BROKER_OIDC_CLIENT_SECRET": "cipherlatch-test-secret",
        "BROKER_LOCKOUT_THRESHOLD": "3",
        "BROKER_LOCKOUT_SECONDS": "60",
        "BROKER_KEYSTORE": "file",
        "BROKER_CREDENTIAL_BACKEND": "local",
        "BROKER_CREDENTIAL_KEY": "test-credential-encryption-key",
        # Rate limiting off by default so token-heavy tests aren't throttled;
        # the dedicated rate-limit test turns it on explicitly.
        "BROKER_RATE_LIMIT_PER_MINUTE": "0",
    }
    defaults.update(env)
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)

    reset_app_state()

    if os.environ.get("TEST_DATABASE_URL"):
        # Shared Postgres database: start each test from a clean slate.
        from app import models  # noqa: F401
        from app.db import Base, get_engine

        Base.metadata.drop_all(bind=get_engine())

    from app.main import create_app

    return create_app()


def reset_app_state() -> None:
    """Clear every process-level cache the app keeps, so the next build_app
    (or the next test file) starts from the declared environment."""
    from app.config import get_settings
    from app.db import reset_engine
    from app.keys import reset_key_cache

    get_settings.cache_clear()
    reset_engine()
    reset_key_cache()
