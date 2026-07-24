from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from .. import audit, keys
from ..authz import Actor, require_permission
from ..db import get_db
from ..keystore import DEFAULT_KEYRING, resolve_storage_ring, validate_keyring_name

router = APIRouter(prefix="/v1/keys", tags=["keys"])


@router.get("")
def key_status(
    actor: Actor = Depends(require_permission("keys:read")), db: Session = Depends(get_db)
):
    # Platform admin sees every storage ring; a tenant actor sees its own
    # rings (agent-facing names) plus the shared default.
    if actor.is_platform_admin:
        info = keys.keys_info(db)
    else:
        info = keys.tenant_keys_info(db, actor.tenant_slug)
    # `keys` mirrors the default ring for convenience/back-compat.
    return {"keys": info.get(DEFAULT_KEYRING, []), "keyrings": info}


@router.post("/rotate")
def rotate(
    request: Request,
    keyring: str = Query(DEFAULT_KEYRING),
    actor: Actor = Depends(require_permission("keys:manage")),
    db: Session = Depends(get_db),
):
    validate_keyring_name(keyring)
    # The default ring is shared platform infrastructure — every tenant's
    # agents may sign with it — so only the platform admin may rotate it.
    # Named rings are tenant-scoped: rotation touches only the actor's tenant
    # (the platform admin targets a tenant via X-Tenant, as everywhere else).
    if keyring == DEFAULT_KEYRING and not actor.is_platform_admin:
        raise HTTPException(
            403, "The default keyring is shared across tenants; only the "
            "platform admin may rotate it. Assign agents a named keyring "
            "to manage rotation within your tenant."
        )
    storage_ring = resolve_storage_ring(actor.tenant_slug, keyring)
    new_kid = keys.rotate_key(storage_ring)
    audit.record_request(
        db, request, "key.rotated", actor=actor.label,
        detail={"keyring": keyring, "storage_ring": storage_ring, "new_kid": new_kid},
    )
    info = keys.keys_info(db) if actor.is_platform_admin else keys.tenant_keys_info(db, actor.tenant_slug)
    return {"rotated": True, "keyring": keyring, "active_kid": new_kid, "keyrings": info}
