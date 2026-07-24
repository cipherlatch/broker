import time
from dataclasses import dataclass

from fastapi import HTTPException
from joserfc import jwt
from joserfc.jwk import ECKey

from ..config import get_settings


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class KeyEntry:
    created_ms: int
    key: ECKey

    @property
    def kid(self) -> str:
        return self.key.thumbprint()


class RotatingKeystore:
    """Base for software backends (file, vault) that can hold several EC keys:
    the newest signs, retired keys stay in JWKS until key_retention_seconds
    elapses so in-flight tokens keep verifying. One instance per keyring."""

    supports_named_keyrings = True

    def __init__(self, keyring: str = "default") -> None:
        self.keyring = keyring
        self._entries: list[KeyEntry] = sorted(
            self._load_entries(), key=lambda e: e.created_ms
        )
        if not self._entries:
            self._entries = [KeyEntry(now_ms(), ECKey.generate_key("P-256", private=True))]
            self._save_entries(self._entries)

    # backend hooks -----------------------------------------------------
    def _load_entries(self) -> list[KeyEntry]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _save_entries(self, entries: list[KeyEntry]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # shared behavior ----------------------------------------------------
    @property
    def _active(self) -> KeyEntry:
        return self._entries[-1]

    def kid(self) -> str:
        return self._active.kid

    def public_jwks(self) -> list[dict]:
        jwks = []
        for entry in self._entries:
            jwk = entry.key.as_dict(private=False)
            jwk.update({"kid": entry.kid, "use": "sig", "alg": "ES256"})
            jwks.append(jwk)
        return jwks

    def sign_jwt(self, header: dict, claims: dict) -> str:
        header = {**header, "kid": self.kid()}
        return jwt.encode(header, claims, self._active.key)

    def keys_info(self) -> list[dict]:
        return [
            {
                "kid": e.kid,
                "created_ms": e.created_ms,
                "age_seconds": max(0, (now_ms() - e.created_ms) // 1000),
                "active": e is self._active,
            }
            for e in reversed(self._entries)
        ]

    def rotate(self) -> str:
        """Mint a new active key; drop retired keys past the retention window."""
        retention_ms = get_settings().key_retention_seconds * 1000
        cutoff = now_ms() - retention_ms
        kept = [e for e in self._entries if e.created_ms >= cutoff]
        new = KeyEntry(now_ms(), ECKey.generate_key("P-256", private=True))
        kept.append(new)
        kept.sort(key=lambda e: e.created_ms)
        self._save_entries(kept)
        self._entries = kept
        return new.kid

    def active_age_seconds(self) -> int:
        return max(0, (now_ms() - self._active.created_ms) // 1000)

    def healthy(self) -> bool:
        return bool(self._entries)


class StaticKeystore:
    """Mixin behavior for backends with externally managed key material
    (HSM / cloud-KMS / JKS plugins): a single active key, rotation happens
    out-of-band."""

    supports_named_keyrings = False

    def keys_info(self) -> list[dict]:
        return [{"kid": self.kid(), "created_ms": None, "age_seconds": None, "active": True}]

    def rotate(self) -> str:
        raise HTTPException(
            409,
            "This keystore backend holds externally managed key material; "
            "rotate it out-of-band (keytool / HSM tooling) and restart.",
        )

    def active_age_seconds(self) -> int:
        return 0
