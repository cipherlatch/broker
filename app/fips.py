"""FIPS mode self-check.

Every primitive the broker uses is FIPS-approved (ES256 / FIPS 186-5,
AES-256-GCM / SP 800-38D, HMAC-SHA256, SHA-256), but FIPS 140-3
*compliance* additionally requires those primitives to execute inside a
CMVP-validated module. An application cannot make that true — it can only
verify it and refuse to run while claiming otherwise.

That is exactly what BROKER_FIPS_MODE=true does: at startup the broker
checks that the underlying OpenSSL is operating in FIPS mode (the
`cryptography` package's OpenSSL backend exposes the provider state) and
aborts if it is not, so a deployment that *claims* FIPS can never silently
run on a non-validated provider. `/readyz` reports `"fips": "ok"` when the
mode is on. See ARCHITECTURE.md § "FIPS deployment profile" for the full recipe
(FIPS-mode OpenSSL, validated keystore, what remains out of scope).

`_openssl_fips_enabled` is a seam for tests.
"""

import logging


def _openssl_fips_enabled() -> bool:
    from cryptography.hazmat.backends.openssl import backend

    return bool(getattr(backend, "_fips_enabled", False))


def openssl_version() -> str:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except Exception:  # pragma: no cover
        return "unknown"


def status(enabled_setting: bool) -> dict:
    return {
        "fips_mode": enabled_setting,
        "openssl_fips": _openssl_fips_enabled(),
        "openssl": openssl_version(),
    }


def enforce() -> None:
    """Called at startup when BROKER_FIPS_MODE=true. Raises (aborting boot)
    unless OpenSSL reports FIPS mode — fail closed, never run while
    claiming a compliance property the crypto provider doesn't have."""
    if _openssl_fips_enabled():
        logging.getLogger("cipherlatch").info(
            "FIPS mode verified: %s (FIPS provider active)", openssl_version()
        )
        return
    raise RuntimeError(
        "BROKER_FIPS_MODE=true but OpenSSL is not operating in FIPS mode "
        f"({openssl_version()}). Run a FIPS-validated OpenSSL provider "
        "(e.g. a FIPS-enabled base image with OpenSSL 3 fips=yes) or unset "
        "BROKER_FIPS_MODE. Refusing to start."
    )
