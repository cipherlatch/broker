import hashlib
import hmac
import secrets

CLIENT_ID_PREFIX = "aib_"
SECRET_PREFIX = "aibs_"
SERVICE_KEY_PREFIX = "csk_"  # Cipherlatch Service Key


def new_client_id() -> str:
    return CLIENT_ID_PREFIX + secrets.token_urlsafe(16)


def new_client_secret() -> str:
    # 256 bits of entropy; only the hash is stored.
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def new_service_key() -> str:
    # A machine control-plane credential. 256 bits; only the hash is stored.
    return SERVICE_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


# Compared against when a client_id doesn't exist, so lookup misses cost the same as hits.
DUMMY_SECRET_HASH = hash_secret("dummy-timing-equalizer")


def verify_secret(secret: str, secret_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), secret_hash)
