"""HashiCorp Vault KV v2 backend.

Stores the key set as JSON at {mount}/data/{path}:
  {"keys": [{"created_ms": 1751..., "pem": "-----BEGIN..."}, ...]}
A pre-rotation single-key document ({"pem": ...}) is adopted transparently.
Generated on first boot against an empty path. Recommended backend for
multi-replica deployments: every replica reads the same key set and nothing
lands on local disk.

Module-level _get/_put are seams for tests.
"""

import httpx
from joserfc.jwk import ECKey

from ..config import get_settings
from .base import KeyEntry, RotatingKeystore


def _url(keyring: str = "default") -> str:
    s = get_settings()
    if not s.vault_addr or not s.vault_token:
        raise RuntimeError("vault keystore requires BROKER_VAULT_ADDR and BROKER_VAULT_TOKEN")
    # Default ring keeps the pre-keyring path; named rings get a suffix.
    suffix = "" if keyring == "default" else f"-ring-{keyring}"
    return f"{s.vault_addr.rstrip('/')}/v1/{s.vault_mount}/data/{s.vault_path}{suffix}"


def _headers() -> dict:
    return {"X-Vault-Token": get_settings().vault_token}


def _get(keyring: str = "default") -> dict | None:
    resp = httpx.get(_url(keyring), headers=_headers(), timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()["data"]["data"]


def _put(doc: dict, keyring: str = "default") -> None:
    resp = httpx.post(_url(keyring), headers=_headers(), json={"data": doc}, timeout=10)
    resp.raise_for_status()


class VaultKeystore(RotatingKeystore):
    def _load_entries(self) -> list[KeyEntry]:
        doc = _get(self.keyring)
        if doc is None:
            return []
        if "keys" in doc:
            return [
                KeyEntry(int(item["created_ms"]), ECKey.import_key(item["pem"].encode()))
                for item in doc["keys"]
            ]
        if "pem" in doc:  # pre-rotation single-key layout
            return [KeyEntry(0, ECKey.import_key(doc["pem"].encode()))]
        return []

    def _save_entries(self, entries: list[KeyEntry]) -> None:
        _put(
            {
                "keys": [
                    {"created_ms": e.created_ms, "pem": e.key.as_pem(private=True).decode()}
                    for e in entries
                ]
            },
            self.keyring,
        )
