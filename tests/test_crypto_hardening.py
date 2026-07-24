"""AES-256-GCM credential encryption and SHA-256 session signing (FIPS/PQ)."""

import base64
import hashlib

from fastapi.testclient import TestClient


def test_local_backend_is_aes256_gcm(app):
    from app import secretbox

    blob = secretbox.encrypt("s3cret-value")
    assert blob.startswith("gcm2:")  # HKDF-derived KEK (v2)
    assert "s3cret-value" not in blob
    assert len(secretbox._aes256_key()) == 32  # AES-256
    assert secretbox.decrypt(blob) == "s3cret-value"


def test_legacy_gcm_sha256_blobs_still_decrypt(app):
    """Credentials written with the pre-HKDF (bare SHA-256) KEK stay readable."""
    import base64
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from app import secretbox

    nonce = os.urandom(12)
    ct = AESGCM(secretbox._aes256_key_legacy()).encrypt(nonce, b"old-secret", None)
    legacy = "gcm:" + base64.b64encode(nonce + ct).decode()
    assert secretbox.decrypt(legacy) == "old-secret"


def test_weak_credential_key_flagged(make_app):
    from app import secretbox

    make_app(BROKER_CREDENTIAL_KEY="short")  # configures settings for this test
    assert secretbox.credential_key_is_weak() is True


def test_gcm_nonce_is_unique_per_encryption(app):
    from app import secretbox

    a = secretbox.encrypt("same")
    b = secretbox.encrypt("same")
    assert a != b  # random 96-bit nonce per record
    assert secretbox.decrypt(a) == secretbox.decrypt(b) == "same"


def test_gcm_tamper_is_rejected(app):
    from app import secretbox

    blob = secretbox.encrypt("value")
    raw = bytearray(base64.b64decode(blob[len("gcm2:"):]))
    raw[-1] ^= 0x01  # flip a bit in the GCM tag
    tampered = "gcm2:" + base64.b64encode(bytes(raw)).decode()
    try:
        secretbox.decrypt(tampered)
        raise AssertionError("tampered ciphertext must not decrypt")
    except Exception as exc:
        assert "AssertionError" not in type(exc).__name__


def test_legacy_fernet_blobs_still_decrypt(app):
    """Credentials written before AES-256 (Fernet/AES-128) remain readable."""
    from cryptography.fernet import Fernet

    from app import secretbox

    key = base64.urlsafe_b64encode(
        hashlib.sha256(b"test-credential-encryption-key").digest()
    )
    legacy = Fernet(key).encrypt(b"pre-existing").decode()
    assert not legacy.startswith("gcm:")
    assert secretbox.decrypt(legacy) == "pre-existing"


def test_session_cookie_signed_with_sha256(app):
    from app.main import Sha256SessionMiddleware

    # The middleware installed on the app must use a SHA-256 signer.
    for mw in app.user_middleware:
        if mw.cls is Sha256SessionMiddleware:
            break
    else:
        raise AssertionError("Sha256SessionMiddleware not installed")

    import itsdangerous

    signer = itsdangerous.TimestampSigner("k", digest_method=hashlib.sha256)
    assert signer.digest_method().name == "sha256"


def test_login_still_works_end_to_end(login):
    # Functional proof the SHA-256-signed session round-trips through the app.
    c, resp = login("crypto@example.com")
    assert resp.status_code == 302
    assert c.get("/ui/agents").status_code == 200


def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
