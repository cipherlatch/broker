"""Encryption for downstream credentials at rest.

Local backend uses AES-256-GCM (FIPS SP 800-38D AEAD; 256-bit resists Grover
far better than the old AES-128 Fernet). Key = SHA-256(BROKER_CREDENTIAL_KEY),
a random 96-bit nonce per record stored alongside the ciphertext.

Backends (BROKER_CREDENTIAL_BACKEND):
- local         — AES-256-GCM on the host (`gcm:` blobs).
- vault-transit — Vault transit engine encrypt/decrypt; the KEK never leaves
                  Vault and can be HSM-backed (`vault:vN:...` blobs).

Ciphertexts are self-describing, so switching backends never strands stored
secrets, and pre-AES-256 Fernet blobs still decrypt for backward compatibility
(new writes never produce them). The feature stays disabled — clear 503 — until
its backend is configured.
"""

import base64
import hashlib
import os

import httpx
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException

from .config import get_settings

_VAULT_PREFIX = "vault:"
_GCM_PREFIX = "gcm:"     # legacy: KEK = SHA-256(key). Decrypt-only.
_GCM2_PREFIX = "gcm2:"   # current: KEK = HKDF-SHA256(key). New writes.
_NONCE_LEN = 12  # 96-bit, the AES-GCM standard nonce size
_HKDF_INFO = b"cipherlatch/credential-kek/v2"
# Length floor below which BROKER_CREDENTIAL_KEY is flagged at boot: the KEK
# derivation is fast (not a password hash), so the key must carry its own
# entropy. token_urlsafe(24)-style values clear this comfortably.
MIN_CREDENTIAL_KEY_LEN = 24


def _require_key() -> str:
    secret = get_settings().credential_key
    if not secret:
        raise HTTPException(503, "Credential brokering is disabled: set BROKER_CREDENTIAL_KEY")
    return secret


def _aes256_key_legacy() -> bytes:
    return hashlib.sha256(_require_key().encode()).digest()  # 32 bytes -> AES-256


def _aes256_key() -> bytes:
    # HKDF-SHA256 domain-separates the KEK from the raw secret (info label) and
    # is the correct KDF for high-entropy input keying material. salt=None is a
    # deterministic derivation so any replica reproduces the same KEK.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(
        _require_key().encode()
    )


def _gcm_encrypt(plaintext: str) -> str:
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(_aes256_key()).encrypt(nonce, plaintext.encode(), None)
    return _GCM2_PREFIX + base64.b64encode(nonce + ct).decode()


def _gcm_decrypt(blob: str, prefix: str) -> str:
    raw = base64.b64decode(blob[len(prefix):])
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    key = _aes256_key() if prefix == _GCM2_PREFIX else _aes256_key_legacy()
    return AESGCM(key).decrypt(nonce, ct, None).decode()


def _legacy_fernet_decrypt(blob: str) -> str:
    # Pre-AES-256 credentials used Fernet (AES-128-CBC). Decrypt-only.
    key = base64.urlsafe_b64encode(hashlib.sha256(_require_key().encode()).digest())
    return Fernet(key).decrypt(blob.encode()).decode()


def _transit_url(op: str) -> str:
    s = get_settings()
    if not s.vault_addr or not s.vault_token:
        raise HTTPException(
            503, "vault-transit credential backend requires BROKER_VAULT_ADDR / _TOKEN"
        )
    return f"{s.vault_addr.rstrip('/')}/v1/{s.vault_transit_mount}/{op}/{s.vault_transit_key}"


def _transit_encrypt(plaintext: str) -> str:
    b64 = base64.b64encode(plaintext.encode()).decode()
    resp = httpx.post(
        _transit_url("encrypt"),
        headers={"X-Vault-Token": get_settings().vault_token},
        json={"plaintext": b64},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["data"]["ciphertext"]  # "vault:v1:...."


def _transit_decrypt(ciphertext: str) -> str:
    resp = httpx.post(
        _transit_url("decrypt"),
        headers={"X-Vault-Token": get_settings().vault_token},
        json={"ciphertext": ciphertext},
        timeout=10,
    )
    resp.raise_for_status()
    b64 = resp.json()["data"]["plaintext"]
    return base64.b64decode(b64).decode()


def encrypt(plaintext: str) -> str:
    if get_settings().credential_backend == "vault-transit":
        return _transit_encrypt(plaintext)
    return _gcm_encrypt(plaintext)


def decrypt(ciphertext: str) -> str:
    # Route by ciphertext shape so a backend switch never strands old secrets.
    if ciphertext.startswith(_VAULT_PREFIX):
        return _transit_decrypt(ciphertext)
    if ciphertext.startswith(_GCM2_PREFIX):
        return _gcm_decrypt(ciphertext, _GCM2_PREFIX)
    if ciphertext.startswith(_GCM_PREFIX):
        return _gcm_decrypt(ciphertext, _GCM_PREFIX)
    return _legacy_fernet_decrypt(ciphertext)


def credential_key_is_weak() -> bool:
    """True when the local KEK is configured but shorter than the entropy
    floor. Advisory only (surfaced at boot) — never blocks operation."""
    s = get_settings()
    if s.credential_backend != "local" or not s.credential_key:
        return False
    return len(s.credential_key) < MIN_CREDENTIAL_KEY_LEN


def backend_ready() -> bool:
    s = get_settings()
    if s.credential_backend == "vault-transit":
        return bool(s.vault_addr and s.vault_token)
    return bool(s.credential_key)
