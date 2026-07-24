from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..keys import public_jwks

router = APIRouter(tags=["well-known"])


@router.get("/.well-known/jwks.json")
def jwks(db: Session = Depends(get_db)):
    return public_jwks(db)


@router.get("/.well-known/oauth-authorization-server")
def oauth_metadata():
    settings = get_settings()
    doc = {
        "issuer": settings.issuer,
        "token_endpoint": f"{settings.issuer}/oauth/token",
        "jwks_uri": f"{settings.issuer}/.well-known/jwks.json",
        "introspection_endpoint": f"{settings.issuer}/oauth/introspect",
        "revocation_endpoint": f"{settings.issuer}/oauth/revoke",
        "grant_types_supported": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt"],
        "dpop_signing_alg_values_supported": ["ES256", "RS256"],
    }
    if settings.mcp_as_enabled:
        # MCP authorization-server role: authorization_code + PKCE for CIMD-
        # registered public clients (see app/routers/authorize.py).
        doc.update({
            "authorization_endpoint": f"{settings.issuer}/oauth/authorize",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": doc["grant_types_supported"] + ["authorization_code"],
            "authorization_response_iss_parameter_supported": True,  # RFC 9207
            "client_id_metadata_document_supported": True,  # CIMD
        })
    return doc
