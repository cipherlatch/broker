from pathlib import Path

from joserfc.jwk import ECKey

from ..config import get_settings
from .base import KeyEntry, RotatingKeystore

_LEGACY_PEM = "signing-key.pem"


class FileKeystore(RotatingKeystore):
    """PEMs on local disk (`key-<created_ms>.pem`); generated on first boot.
    Single-node only — for replicas, use the vault backend. The pre-rotation
    `signing-key.pem` is adopted as the oldest key and pruned like any other.
    The default keyring lives at the keys dir root (pre-keyring layout);
    named keyrings live in `ring-<name>/` subdirectories."""

    def _dir(self) -> Path:
        keys_dir = Path(get_settings().keys_dir)
        if self.keyring != "default":
            keys_dir = keys_dir / f"ring-{self.keyring}"
        keys_dir.mkdir(parents=True, exist_ok=True)
        keys_dir.chmod(0o700)
        return keys_dir

    def _load_entries(self) -> list[KeyEntry]:
        entries = []
        for pem_path in self._dir().glob("key-*.pem"):
            try:
                created_ms = int(pem_path.stem.split("-", 1)[1])
            except ValueError:
                continue
            entries.append(KeyEntry(created_ms, ECKey.import_key(pem_path.read_bytes())))
        legacy = self._dir() / _LEGACY_PEM
        if legacy.exists():
            created_ms = int(legacy.stat().st_mtime * 1000)
            entries.append(KeyEntry(created_ms, ECKey.import_key(legacy.read_bytes())))
        return entries

    def _save_entries(self, entries: list[KeyEntry]) -> None:
        keys_dir = self._dir()
        keep_names = set()
        legacy = keys_dir / _LEGACY_PEM
        legacy_kid = None
        if legacy.exists():
            legacy_kid = ECKey.import_key(legacy.read_bytes()).thumbprint()

        for entry in entries:
            if entry.kid == legacy_kid:
                keep_names.add(_LEGACY_PEM)
                continue
            name = f"key-{entry.created_ms}.pem"
            keep_names.add(name)
            pem_path = keys_dir / name
            if not pem_path.exists():
                pem_path.write_bytes(entry.key.as_pem(private=True))
                pem_path.chmod(0o600)

        for pem_path in list(keys_dir.glob("key-*.pem")) + ([legacy] if legacy.exists() else []):
            if pem_path.name not in keep_names:
                pem_path.unlink()
