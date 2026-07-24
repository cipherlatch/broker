from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BROKER_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/broker.db"
    keys_dir: str = "./data/keys"

    # create_all on startup (dev/tests). Production runs Alembic via scripts/migrate.py
    # in the container entrypoint and sets this to false.
    db_auto_create: bool = True

    # Bootstrap/machine admin credential (CI, curl). Humans use OIDC login.
    # Machine/bootstrap admin key(s). Comma-separated list: any entry
    # authenticates, enabling zero-downtime rotation. Empty = header disabled
    # (recover via `python -m app.admin` from a shell instead).
    admin_api_key: str = ""

    issuer: str = "http://localhost:8000"
    audience: str = "agent-iam"
    token_ttl_seconds: int = 300
    token_ttl_max_seconds: int = 900

    # NIST 800-63B-style throttling for /oauth/token.
    lockout_threshold: int = 5
    lockout_seconds: int = 300

    # OIDC human login (any spec-compliant IdP; Authentik first).
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email"
    # IdP group -> Cipherlatch role mapping, e.g. "cipherlatch-admins=broker-admin,devs=agent-manager".
    # First match wins; when a mapping matches, the IdP is authoritative for the role.
    oidc_groups_claim: str = "groups"
    group_role_map: str = ""

    # Email-domain -> tenant-slug routing at login, e.g. "acme.com=acme,beta.io=beta".
    # Unmatched domains land in the default tenant.
    tenant_domain_map: str = ""

    # Create a principal automatically on first successful OIDC login.
    jit_provisioning: bool = True
    # Comma-separated emails that receive the broker-admin role on login.
    admin_emails: str = ""
    # When true (default), admin_emails accounts are re-promoted to
    # broker-admin at every login, so a UI demotion never sticks. Set false
    # once real admins exist: admin_emails then only seeds the role at JIT
    # provisioning, and the bootstrap admin can be demoted, deactivated, or
    # deleted like anyone else (the last-admin guard still applies).
    admin_email_pinning: bool = True
    # Role assigned to JIT-provisioned users.
    default_role: str = "agent-manager"

    # Signing-key storage backend: file | vault built in; other values are
    # resolved through the `cipherlatch.keystores` entry-point group (the
    # cipherlatch-enterprise package provides jks | pkcs11 | awskms | gcpkms |
    # azurekv, configured via its own BROKER_-prefixed settings).
    keystore: str = "file"
    # Retired keys stay in JWKS this long after rotation so in-flight tokens
    # still verify. Must exceed token_ttl_max_seconds.
    key_retention_seconds: int = 86400
    # Auto-rotate at startup when the active key is older than this (0 = off).
    key_max_age_seconds: int = 0

    # Downstream-credential encryption backend: local | vault-transit.
    #   local        — Fernet keyed from BROKER_CREDENTIAL_KEY (KEK on the box)
    #   vault-transit — envelope encryption via Vault's transit engine; the KEK
    #                   never leaves Vault (and can itself be HSM-backed)
    credential_backend: str = "local"
    # Encrypts downstream credentials at rest (any high-entropy string).
    # Credential brokering is disabled until this is set (local backend).
    credential_key: str = ""
    # vault-transit backend (reuses vault_addr / vault_token):
    vault_transit_mount: str = "transit"
    vault_transit_key: str = "cipherlatch-credentials"
    # vault backend (KV v2):
    vault_addr: str = ""
    vault_token: str = ""
    vault_mount: str = "secret"
    vault_path: str = "cipherlatch/signing-key"

    # Workload identity federation: comma-separated allowlist of external
    # OIDC issuers (SPIRE oidc-discovery-provider, Kubernetes API server,
    # GitLab, ...) whose tokens may authenticate federated agents. Empty =
    # federation disabled.
    federated_issuers: str = ""

    # FIPS self-check: when true, refuse to start unless OpenSSL is
    # operating in FIPS mode (see app/fips.py and ARCHITECTURE.md § FIPS).
    fips_mode: bool = False

    session_secret: str = ""
    session_max_age: int = 12 * 3600

    # SSO account (re)linking: bind an IdP `sub` to an existing account matching
    # its email only when the IdP asserts the email is verified. Guards against
    # an attacker who can obtain an IdP identity asserting a victim's email.
    # Defaults ON; set False only if your (single, trusted) IdP omits the
    # `email_verified` claim entirely.
    link_requires_verified_email: bool = True

    # Honor X-Forwarded-For from the reverse proxy for audit IPs and rate
    # limiting. The client can spoof the *left* of X-Forwarded-For, so the
    # real client is the Nth value from the right, where N =
    # trust_proxy_hops is the count of proxies that append a hop you control
    # (typically 1: your ingress). Set to your actual proxy depth; leaving it
    # too low reads a spoofable value, too high reads your own proxy's IP.
    # Defaults to OFF: a directly-exposed deployment must NOT trust a client-
    # supplied header (it would let a client forge its audit IP and rotate its
    # rate-limit key). Turn on only behind a proxy that appends the real peer.
    trust_proxy_ip: bool = False
    trust_proxy_hops: int = 1

    # UI theming: accent color injected as a CSS custom property.
    ui_accent: str = "#e3a94b"

    # Observability.
    log_json: bool = False
    metrics_enabled: bool = True
    # Root log level: debug | info | warning | error.
    log_level: str = "info"
    # Custom logging.Formatter format string for text mode (ignored with
    # BROKER_LOG_JSON=true, which has a fixed structure).
    log_format: str = ""
    # Which audit events reach the LOG MIRROR (the DB audit trail is always
    # complete — filtering and masking apply only to what leaves on stdout).
    # Comma-separated fnmatch patterns, e.g. "token.*,gateway.*,login.*".
    # Empty = all events. Exclude is applied after include.
    log_events: str = ""
    log_events_exclude: str = ""
    # Sensitive fields masked (recursively, incl. inside detail) in the log
    # mirror, e.g. "actor,ip,owner,email". Mode: hash (sha256 prefix — still
    # correlatable across events) | redact ("[masked]").
    log_mask_fields: str = ""
    log_mask_mode: str = "hash"

    # Enforcing gateway: cap on a single proxied response body (bytes) and the
    # upstream timeout (seconds). Gateway is enabled per-route, not globally.
    gateway_max_body_bytes: int = 10 * 1024 * 1024
    gateway_timeout_seconds: int = 30
    # External policy hook (OPA / cedar-agent data-API shape). Empty = off.
    gateway_policy_url: str = ""
    gateway_policy_timeout_seconds: float = 2.0
    # Deny on hook errors/timeouts (fail-closed) unless explicitly opened.
    gateway_policy_fail_open: bool = False

    # Per-client-IP rate limiting (fixed window, in-process per replica).
    # 0 disables. Applies to /oauth/token and /gw/*.
    rate_limit_per_minute: int = 120
    rate_limit_window_seconds: int = 60

    # DPoP (RFC 9449): when true, tokens minted with a DPoP proof are bound to
    # the proof key (cnf.jkt) and the gateway requires a matching DPoP header.
    dpop_enabled: bool = True

    # MCP authorization-server role: authorization_code + PKCE for MCP clients
    # (CIMD registration, RFC 8707 resource binding, consent). Off by default —
    # flipping this on is the deliberate go-live act for the MCP surface.
    mcp_as_enabled: bool = False
    # TTL class for user-delegated MCP tokens. Longer than agent tokens (no
    # refresh tokens in v1, so this bounds how often interactive clients must
    # re-authorize); consent revocation still kills tokens at verify time.
    mcp_token_ttl_seconds: int = 3600
    # Client ID Metadata Document fetching (the SSRF-sensitive surface).
    cimd_timeout_seconds: float = 5.0
    cimd_max_bytes: int = 65536
    cimd_cache_seconds: int = 3600
    # Permit client_id URLs that resolve to private/loopback addresses.
    # Only for air-gapped/homelab deployments where MCP clients live on RFC
    # 1918 space; leave false anywhere the broker can reach the internet.
    cimd_allow_private_ips: bool = False

    @property
    def admin_email_list(self) -> list[str]:
        return [e.strip().lower() for e in self.admin_emails.split(",") if e.strip()]

    @property
    def admin_api_key_list(self) -> list[str]:
        # Comma-separated so the key can rotate without a lockout window:
        # add the new key, redeploy, move callers, remove the old key.
        return [k.strip() for k in self.admin_api_key.split(",") if k.strip()]

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def group_role_pairs(self) -> list[tuple[str, str]]:
        pairs = []
        for item in self.group_role_map.split(","):
            if "=" in item:
                group, role = item.split("=", 1)
                if group.strip() and role.strip():
                    pairs.append((group.strip(), role.strip()))
        return pairs

    @property
    def tenant_domain_pairs(self) -> dict[str, str]:
        out = {}
        for item in self.tenant_domain_map.split(","):
            if "=" in item:
                domain, slug = item.split("=", 1)
                if domain.strip() and slug.strip():
                    out[domain.strip().lower()] = slug.strip()
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
