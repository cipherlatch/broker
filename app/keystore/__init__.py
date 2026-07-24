"""Pluggable signing-key storage with named keyrings.

Built-in backends (BROKER_KEYSTORE):
- file  — PEMs on disk (default; single-node)
- vault — HashiCorp Vault KV v2 (recommended for clustering)

Further backends plug in through the `cipherlatch.keystores` entry-point group: any
installed distribution may register `<name> = "module:KeystoreClass"` and
`BROKER_KEYSTORE=<name>` will find it. The commercially licensed
cipherlatch-enterprise package provides jks, pkcs11 (HSM), awskms, gcpkms and
azurekv this way. A backend class opts into named keyrings by setting
`supports_named_keyrings = True` (and accepting the keyring name as its one
constructor argument); backends holding externally managed key material leave
it False and serve only the default ring, with rotation happening out-of-band.

Keyrings isolate rotation blast radius: agents on ring A are unaffected when
ring B rotates. The `default` ring uses the pre-keyring storage layout, so
existing deployments keep their key untouched.

Named keyrings are tenant-scoped: the user-facing name on an agent resolves to
a storage ring of `<tenant-slug>.<name>` (the dot appears in neither charset,
so tenants can never collide). `default` remains the one shared ring —
platform infrastructure — which is why rotating it is platform-admin-only.
"""

import importlib
import re
from importlib.metadata import entry_points

from fastapi import HTTPException

from ..config import get_settings

DEFAULT_KEYRING = "default"
_BUILTIN = {
    "file": ("app.keystore.file", "FileKeystore"),
    "vault": ("app.keystore.vault", "VaultKeystore"),
}
_KEYRING_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

_providers: dict[str, object] = {}


def validate_keyring_name(name: str) -> str:
    if not _KEYRING_RE.match(name):
        raise HTTPException(
            422, "keyring must be lowercase alphanumeric/dash/underscore, max 64 chars"
        )
    return name


def resolve_storage_ring(tenant_slug: str | None, name: str | None) -> str:
    """Map an agent-facing keyring name to its storage ring. `default` is the
    shared pre-keyring ring; any other name is scoped to the agent's tenant."""
    name = (name or DEFAULT_KEYRING).strip() or DEFAULT_KEYRING
    if name == DEFAULT_KEYRING:
        return DEFAULT_KEYRING
    return f"{tenant_slug or 'default'}.{name}"


def backend_class(kind: str):
    """Resolve a backend name to its class — built-ins first, then the
    `cipherlatch.keystores` entry-point group. Resolution imports the backend module
    but does not construct it (construction may dial an HSM/KMS)."""
    if kind in _BUILTIN:
        module, cls = _BUILTIN[kind]
        return getattr(importlib.import_module(module), cls)
    for ep in entry_points(group="cipherlatch.keystores"):
        if ep.name == kind:
            return ep.load()
    raise ValueError(
        f"Unknown BROKER_KEYSTORE '{kind}' (built-in: file|vault; other backends "
        "are provided by installed plugin packages such as cipherlatch-enterprise)"
    )


def supports_named_keyrings(kind: str) -> bool:
    return bool(getattr(backend_class(kind), "supports_named_keyrings", False))


def get_provider(keyring: str = DEFAULT_KEYRING):
    if keyring in _providers:
        return _providers[keyring]

    kind = get_settings().keystore
    cls = backend_class(kind)
    if getattr(cls, "supports_named_keyrings", False):
        provider = cls(keyring)
    else:
        if keyring != DEFAULT_KEYRING:
            raise HTTPException(
                409, f"The {kind} keystore backend supports only the default keyring"
            )
        provider = cls()

    _providers[keyring] = provider
    return provider


def reset_provider_cache() -> None:
    _providers.clear()
