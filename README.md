# Cipherlatch — Broker for Agentic Access Management

Identity and access management for AI agents. Register agents as first-class
principals owned by a human, grant them scopes, and let them mint short-lived
signed tokens that any downstream service can verify with nothing but a JWKS
URL. Every issuance, denial, login, and lifecycle change is audited with
actor and IP.

Licensed **AGPL-3.0** (self-host freely); a commercial license and paid
support are available — see [COMMERCIAL.md](COMMERCIAL.md).

See [ARCHITECTURE.md](ARCHITECTURE.md) for how it works, [ROADMAP.md](ROADMAP.md)
for what's next, and [DECISIONS.md](DECISIONS.md) for the design rationale.

**Delivered capabilities:**

- **OIDC login** for humans (any spec-compliant IdP; Authentik first), with
  JIT provisioning or manual pre-provisioning, plus a machine admin key for
  CI/scripting.
- **User isolation**: users manage only their own agents; other users'
  agents are invisible (404, never 403 — existence doesn't leak). Admins see
  everything.
- **User management**: add (manual or JIT), modify (role/status/name), delete
  (soft-delete that revokes all owned agents). SCIM is a considered option —
  see ARCHITECTURE.md.
- **Configurable RBAC**: roles are permission sets (own-scoped vs `:all`
  variants). Built-ins `broker-admin`, `agent-manager`, `auditor`; create
  custom roles and assign permissions via the Roles UI or `/v1/roles`.
  Multiple admins supported, with a last-admin guard.
- **Pluggable keystores** (`BROKER_KEYSTORE`): `file` and HashiCorp `vault`
  built in; hardware/cloud key custody — `pkcs11` HSM, cloud KMS (`awskms`,
  `gcpkms`, `azurekv`), `jks` — ships in the commercially licensed
  [Cipherlatch Enterprise](COMMERCIAL.md) plugin package, discovered through the
  `cipherlatch.keystores` entry-point group. The credential-encryption KEK is
  separately pluggable (`BROKER_CREDENTIAL_BACKEND`: `local` or
  `vault-transit`, where the KEK never leaves Vault). See ARCHITECTURE.md §
  Keystores.
- **Credential brokering (RFC 8693)**: store downstream secrets (HA tokens,
  PATs) encrypted and write-only; granted agents exchange their Cipherlatch token
  for them at `/oauth/token` — the agent never holds the secret at rest:

  ```bash
  curl -s -X POST $Cipherlatch/oauth/token \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d client_id=aib_... -d client_secret=aibs_... \
    -d subject_token=$CIPHERLATCH_JWT \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    -d audience=ha-token
  ```
- **Keyrings**: assign agents to named signing keyrings; each ring rotates
  independently (`POST /v1/keys/rotate?keyring=...`), isolating rotation
  blast radius. Named rings are **tenant-scoped** — the same name in two
  tenants is two independent keys, and a tenant admin can only rotate its
  own; the shared `default` ring rotates only via the platform admin key.
  JWKS serves the union, so verifiers need no changes.
- **Enforcing gateway**: define a route (`/gw/<slug>`) bound to an upstream +
  stored credential + policy (allowed methods/paths, per-agent rate limit and
  daily quota); granted agents call *through* Cipherlatch, which injects the
  credential server-side and proxies — the agent never holds the secret and
  can't escape the route. Every transaction audited. Optionally, every
  request is also evaluated by an external OPA/Cedar policy endpoint
  (`BROKER_GATEWAY_POLICY_URL`, fail-closed).
- **Revocation & introspection** (RFC 7009/7662): `/oauth/revoke` kills a
  token now; `POST /v1/agents/{id}/revoke-tokens` mass-revokes an agent's
  outstanding tokens; `/oauth/introspect` reports active state.
- **Stronger client auth** (RFC 7523/9449): `private_key_jwt` (signed
  assertion, no shared secret) and **DPoP** (proof-of-possession — a stolen
  token is useless without the agent's private key). The gateway enforces
  DPoP binding.
- **Rate limiting**: per-IP throttle on `/oauth/*` and `/gw/*`
  (`BROKER_RATE_LIMIT_PER_MINUTE`).

  ```bash
  # agent calls the upstream via Cipherlatch with only its Cipherlatch token:
  curl -H "Authorization: Bearer $CIPHERLATCH_JWT" \
    https://cipherlatch.example.com/gw/ha-api/api/states
  ```
- **Cluster-ready**: stateless app (cookie sessions, DB-backed lockout),
  `/readyz` probe, advisory-locked migrations, shared key via Vault;
  [docker-compose.ha.yml](docker-compose.ha.yml) runs N replicas behind an
  nginx LB. See ARCHITECTURE.md § Scaling & HA.
- **Key rotation**: `POST /v1/keys/rotate` mints a new signing key while
  retired keys stay in JWKS through a retention window — in-flight tokens
  keep verifying. Optional startup auto-rotation by key age.
- **Observability**: Prometheus `/metrics` (audit-event counters, HTTP
  latency), JSON structured logs (`BROKER_LOG_JSON`), and the full audit
  stream mirrored to stdout for SIEM ingestion. The mirror is tunable:
  level/format (`BROKER_LOG_LEVEL`/`_FORMAT`), event selection
  (`BROKER_LOG_EVENTS`/`_EXCLUDE`, fnmatch patterns), and PII masking
  (`BROKER_LOG_MASK_FIELDS`, hash or redact) — the DB audit trail always
  stays complete.
- **IdP group→role mapping**: `BROKER_GROUP_ROLE_MAP="idp-group=role,..."`
  lets the IdP drive role assignment on every login (audited; JIT uses it
  too), so access management stays in your directory.
- **SCIM 2.0 provisioning** (`/scim/v2/Users`): the IdP pushes user
  create/update/deactivate/delete with a per-tenant bearer token
  (`POST /v1/scim-token`). Deactivating a user suspends every agent they
  own — new mints and outstanding tokens both — until reactivation;
  deleting revokes their agents permanently.
- **Secretless agents** (SPIFFE/OIDC workload federation): bind an agent to
  a `federated_issuer` + `federated_subject` (a SPIFFE ID, a Kubernetes
  service account, a GitLab CI job) and it authenticates with its
  platform-issued JWT — Cipherlatch never issues it a secret at all. Issuers are
  gated by the `BROKER_FEDERATED_ISSUERS` allowlist.
- **Dynamic credential providers**: a credential can mint short-lived
  material at exchange instead of storing a static secret. The `ssh-ca`
  provider signs a scoped, minutes-long OpenSSH certificate (agent submits
  its public key; delegation chain rides in the cert `key_id`) — an agent
  SSHes to a host holding no standing key. Zero new dependencies; `vault` /
  `aws-sts` / `postgres` providers are the roadmap.
- **Web UI**: agents, credentials (shown once), audit log, user admin.
  Themable (CSS custom properties, light/dark, `BROKER_UI_ACCENT`).
- **Supply-chain gates in CI**: pip-audit (blocking), bandit SAST, gitleaks
  secret detection, and a CycloneDX SBOM artifact per deploy — see
  [SECURITY.md](SECURITY.md) for the policy and hardening guide.
- **IaC-ready API**: idempotent natural-key upserts
  (`PUT /v1/agents/by-name/{name}`, ...) with `changed`/`unchanged`
  reporting, and declarative desired-state convergence
  (`POST /v1/apply`, `?dry_run=true` for check mode) — drive Cipherlatch from
  Ansible/Puppet/Chef with plain HTTP tasks.
- **Token-endpoint lockout** (NIST 800-63B-style throttling) and **RFC 8707
  `resource`** support: tokens are audience-bound to the requested resource,
  optionally restricted per agent.
- **Alembic migrations** (existing Phase 1 databases are adopted
  automatically on first start).

## Quick start (dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export BROKER_ADMIN_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
uvicorn app.main:app --reload
```

Add the owning human, then register an agent (secret is returned exactly once):

```bash
curl -s -X POST localhost:8000/v1/users \
  -H "X-Admin-Key: $BROKER_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'

curl -s -X POST localhost:8000/v1/agents \
  -H "X-Admin-Key: $BROKER_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "ha-bridge", "owner_email": "you@example.com",
       "allowed_scopes": ["ha:read", "ha:write"]}'
```

Or use the web UI at `http://localhost:8000/` once OIDC is configured.

The agent mints a token (standard OAuth2 client_credentials):

```bash
curl -s -X POST localhost:8000/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=aib_... -d client_secret=aibs_... \
  -d scope="ha:read"
```

Downstream services verify offline against `/.well-known/jwks.json`.
Audit trail: `GET /v1/audit` (admin). Interactive docs at `/docs`.

## Standards

Everything the broker does is an application of an existing spec: OAuth 2.1
client credentials for agent auth, RFC 7638 key thumbprints, RFC 8414
discovery metadata, and tokens shaped to NIST SP 800-63C assertion
requirements (signed, expiring, audience-restricted, issuer/subject
identified). On the roadmap: RFC 8707 resource indicators for per-service
audience binding (mandatory for MCP clients under the MCP authorization spec,
current revision 2025-11-25), RFC 8693 token exchange, NIST 800-63B
throttling, and RFC 9449 DPoP. The full mapping — including MCP
authorization-server requirements, the 2026 NIST/IETF agent-identity work
(NCCoE, CAISI, COSAiS, WIMSE, AIMS), and what is *not* implemented yet — is
in [ARCHITECTURE.md § Standards alignment](ARCHITECTURE.md#standards-alignment).

## Tests

```bash
pip install -r requirements-dev.txt && pytest
```

## Docker

```bash
echo "BROKER_ADMIN_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env
docker compose up --build
```

Note: the compose file joins an external reverse-proxy network, `edge` by
default (override the name with `EDGE_NETWORK` in `.env`). Create it once with
`docker network create edge`.

## Deployment (Kubernetes / Helm)

```bash
helm install cipherlatch charts/cipherlatch \
  --set broker.issuer=https://cipherlatch.example.com \
  --set broker.oidcIssuer=https://idp.example.com/application/o/cipherlatch/ \
  --set keystore.vault.addr=http://vault.vault:8200 \
  --set secrets.existingSecret=cipherlatch-secrets   # or --set secrets.*=...
```

External Postgres required (`BROKER_DATABASE_URL` in the secret); migrations
self-apply on pod start under an advisory lock, so rolling multi-replica
deploys are safe. Use the `vault` or a cloud-KMS keystore for >1 replica —
the chart refuses to render the single-node `file` keystore with replicas.
See [charts/cipherlatch/values.yaml](charts/cipherlatch/values.yaml) for the full surface.

## Deployment (CI -> Docker Compose)

A push to `main` can run the test suite and then redeploy the compose project
(broker + Postgres) in place; a complete pipeline example ships in
[.github/workflows/ci.yml](.github/workflows/ci.yml), and the checklist translates to any CI
system:

1. **Secrets as masked CI variables**: `BROKER_ADMIN_API_KEY`,
   `POSTGRES_PASSWORD`, `BROKER_OIDC_CLIENT_ID`, `BROKER_OIDC_CLIENT_SECRET`,
   `BROKER_SESSION_SECRET`. Non-secret settings (`DATA_DIR`, `BROKER_ISSUER`,
   `BROKER_OIDC_ISSUER`, `BROKER_ADMIN_EMAILS`, `TIMEZONE`, ...) can default
   in the pipeline file and be overridden per environment.
2. **Runner/executor** needs access to the Docker socket (or substitute your
   platform's native deploy step).
3. **Reverse proxy**: terminate TLS at your proxy or ingress and set
   `BROKER_ISSUER` to the public HTTPS URL. `/oauth/token` is unauthenticated
   by protocol design — the broker rate-limits and lockout-protects it, but
   volumetric protection belongs at the edge.
4. State lives under `DATA_DIR` (`keys/` signing key, `pgdata/`).
5. **Locked out?** Break-glass recovery needs only shell access to the host:
   `docker exec <container> python -m app.admin promote you@example.com`
   (see the [Administrator Guide](docs/customer/admin-guide.md)).

## OIDC setup (Authentik example)

1. In Authentik: create an **OAuth2/OpenID Provider** — authorization code
   flow, confidential client, redirect URI
   `https://<broker-host>/auth/callback`, RS256 signing. Create an
   **Application** (e.g. slug `cipherlatch`) bound to that provider.
2. Configure the broker:
   `BROKER_OIDC_ISSUER=https://auth.example.com/application/o/cipherlatch/`,
   `BROKER_OIDC_CLIENT_ID`, `BROKER_OIDC_CLIENT_SECRET`, and a stable
   `BROKER_SESSION_SECRET`.
3. `BROKER_ADMIN_EMAILS=you@example.com` grants (and keeps) the admin role at
   login. `BROKER_JIT_PROVISIONING=false` restricts sign-in to users you have
   added manually. Once real admins exist, set
   `BROKER_ADMIN_EMAIL_PINNING=false` so the list only seeds the role at first
   login and the bootstrap admin can afterwards be demoted, deactivated, or
   deleted like any other user (the last-admin guard still applies).

First login binds the OIDC `sub` to the matching pre-provisioned email (the
IdP must not report the email as unverified), or JIT-creates the account.

## Configuration

All settings via `BROKER_*` env vars (or `.env`): `DATABASE_URL`, `KEYS_DIR`,
`ADMIN_API_KEY` (comma-list rotates without downtime; empty disables the
header entirely — recovery is `python -m app.admin` from a shell, and every
key use is audited as `admin_key.used`), `ISSUER`, `AUDIENCE`, `TOKEN_TTL_SECONDS` (default 300),
`TOKEN_TTL_MAX_SECONDS` (default 900), `LOCKOUT_THRESHOLD` (default 5),
`LOCKOUT_SECONDS` (default 300), `OIDC_*` / `SESSION_*` / `JIT_PROVISIONING`
/ `ADMIN_EMAILS` (see above), `UI_ACCENT` (any CSS color), `DB_AUTO_CREATE`
(false in production — Alembic owns the schema), `TRUST_PROXY_IP`.
See [app/config.py](app/config.py).

## UI theming

The UI is a dependency-free server-rendered app themed entirely with CSS
custom properties ([app/static/app.css](app/static/app.css)): light/dark via
`prefers-color-scheme` plus a persisted manual toggle, and the accent color
injected from `BROKER_UI_ACCENT`. To retheme, override the `:root` /
`[data-theme="dark"]` token blocks.

## License

Copyright © 2026 Brian Bunner. Released under the **GNU Affero General
Public License v3.0** ([LICENSE](LICENSE)) — you may self-host, modify, and
redistribute under its terms, including the AGPL's requirement to share the
source of a modified network service.

The project retains full copyright over its code, so **dual licensing** is
available: if the AGPL's copyleft doesn't fit (embedding in a closed-source
product, running a modified hosted service without publishing changes),
a commercial license and paid support can be arranged — see
[COMMERCIAL.md](COMMERCIAL.md). External contributions require a Contributor
License Agreement so this stays possible.
