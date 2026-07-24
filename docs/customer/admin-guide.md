# Cipherlatch Administrator Guide

**Broker for Agentic Access Management** — deployment, configuration, and day-2
operations.

This guide is for the team that *runs* Cipherlatch: platform engineers, SREs, and
security administrators. If you are an agent owner who just wants to register an
agent and mint tokens, read the [User Guide](user-guide.md) instead.

> **A note on deployment dependence.** Many of Cipherlatch's security properties are
> *deployment* properties, not code properties. Wherever an answer changes with
> how you deploy, this guide marks it **[Deployment-dependent]** and spells out
> each case. Read those callouts before you make a compliance claim.

---

## 1. What Cipherlatch is (one paragraph)

Cipherlatch gives AI agents a real identity. Each agent is a first-class principal
**owned by a human**, granted a set of scopes, and able to mint short-lived
(default 5-minute) ES256-signed JWTs. Any downstream service verifies those
tokens offline with nothing but a JWKS URL. On top of that core, Cipherlatch can broker
downstream credentials (an agent exchanges its token for a stored secret it never
holds at rest), enforce access at a built-in gateway, and issue *no* long-lived
secret at all when agents bootstrap from SPIFFE / OIDC workload identity. Every
issuance, denial, login, and lifecycle change is audited with actor and IP.

---

## 2. Deployment topologies

Cipherlatch is one stateless FastAPI app plus a database and a signing key. The security
posture is set by *which* backends you wire in. Three supported topologies,
smallest to largest:

| Topology | Use case | Database | Keystore | Replicas |
|---|---|---|---|---|
| **Single-node (Compose)** | Evaluation, single-tenant, low volume | SQLite or PostgreSQL | `file` | 1 |
| **High availability (Compose)** | Production on one host | PostgreSQL | `vault` / cloud KMS | N behind a load balancer |
| **Kubernetes / Helm** | Production, multi-replica | External PostgreSQL | `vault` / cloud KMS / `pkcs11` HSM | N |

Key rule: **the `file` keystore is single-node only.** With more than one replica
the signing key must live somewhere all replicas share — Vault or a cloud KMS.
The Helm chart *refuses to render* a multi-replica deployment on the `file`
keystore. [Deployment-dependent]

### 2.1 Single-node (Docker Compose)

```bash
echo "BROKER_ADMIN_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" > .env
docker compose up --build
```

Front Cipherlatch with a TLS-terminating reverse proxy or ingress you control; the app
does not terminate TLS itself.

### 2.2 High availability (Compose)

The HA compose profile runs N app replicas behind a load balancer, sharing
PostgreSQL and a Vault-backed signing key. The app is stateless (cookie sessions,
DB-backed lockout state), exposes `/readyz`, and serializes migrations behind a
database advisory lock, so rolling deploys are safe. See ARCHITECTURE.md § Scaling & HA.

### 2.3 Kubernetes (Helm)

```bash
helm install cipherlatch charts/cipherlatch \
  --set broker.issuer=https://cipherlatch.example.com \
  --set broker.oidcIssuer=https://idp.example.com/application/o/cipherlatch/ \
  --set keystore.vault.addr=http://vault.vault:8200 \
  --set secrets.existingSecret=cipherlatch-secrets
```

External PostgreSQL is required (`BROKER_DATABASE_URL` in the secret). Migrations
self-apply on pod start under an advisory lock. Full surface in
`charts/cipherlatch/values.yaml`.

> **CI/CD.** Cipherlatch is a standard container image; deploy it with whatever pipeline
> you already use. Pushing a signed image to your registry and rolling the
> Deployment/compose project is all that's required — migrations self-apply on
> start.

---

## 3. First-boot bootstrap

Cipherlatch has two admin planes:

1. **Machine admin key** (`BROKER_ADMIN_API_KEY`) — a header-auth key
   (`X-Admin-Key`) for CI, scripting, and IaC. Does not need OIDC. Optional:
   leave it empty and the header path is disabled entirely. It accepts a
   comma-separated list (any entry authenticates) so it rotates with no
   lockout window, and **every use — reads included — is audited** as
   `admin_key.used`.
2. **Human admins** — real users who sign in via OIDC and hold the `broker-admin`
   role.

Bootstrap order:

```bash
# 1. Create the owning human (idempotent).
curl -s -X POST $Cipherlatch/v1/users \
  -H "X-Admin-Key: $BROKER_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'

# 2. Register an agent (client secret is returned exactly once — capture it).
curl -s -X POST $Cipherlatch/v1/agents \
  -H "X-Admin-Key: $BROKER_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "orders-sync", "owner_email": "you@example.com",
       "allowed_scopes": ["orders:read", "orders:write"]}'
```

`BROKER_ADMIN_EMAILS=you@example.com` grants the `broker-admin` role at login.
While `BROKER_ADMIN_EMAIL_PINNING=true` (the default) the role is re-applied at
every login, so you cannot lock yourself out of the human plane by demotion.
Once real admins exist, set it `false`: the list then only seeds the role at
first login, and the bootstrap account can be demoted, disabled, or deleted
like any other user (a last-admin guard still refuses removing the final
admin).

**Break-glass:** if every login path is ever lost (IdP outage, last admin
disabled, no admin key configured), recover from a shell on the broker host —
`docker exec <container> python -m app.admin promote you@example.com`
(`kubectl exec` on Kubernetes). Idempotent, and audited as `admin-cli`.

---

## 4. Configuration reference

All settings are `BROKER_*` environment variables (or `.env`). Source of truth:
`app/config.py`. The ones that matter most, grouped:

### 4.1 Identity & tokens

| Var | Default | Meaning |
|---|---|---|
| `BROKER_ISSUER` | `http://localhost:8000` | `iss` claim + discovery base. Must be the public HTTPS URL in production. |
| `BROKER_AUDIENCE` | `agent-iam` | Default static audience when no `resource` is requested. |
| `BROKER_TOKEN_TTL_SECONDS` | `300` | Default token lifetime (5 min). |
| `BROKER_TOKEN_TTL_MAX_SECONDS` | `900` | Ceiling an agent can request. |

### 4.2 Storage & schema

| Var | Default | Meaning |
|---|---|---|
| `BROKER_DATABASE_URL` | `sqlite:///./data/broker.db` | Use PostgreSQL for anything production / multi-replica. |
| `BROKER_DB_AUTO_CREATE` | `true` | **Set `false` in production** — Alembic owns the schema. |
| `BROKER_KEYS_DIR` | `./data/keys` | Where the `file` keystore writes the signing key. |

### 4.3 Keystore (signing key) — **[Deployment-dependent]**

`BROKER_KEYSTORE` selects where the token-signing private key lives:

- `file` — on-disk key. Single node only.
- `vault` — HashiCorp Vault KV. Shared across replicas.

The hardware/cloud custody backends require the **Cipherlatch Enterprise** package
(commercial license — see COMMERCIAL.md):

- `jks` — Java KeyStore file (`BROKER_JKS_*`).
- `awskms` / `gcpkms` / `azurekv` — cloud KMS; **the key never leaves the KMS**,
  Cipherlatch asks the KMS to sign.
- `pkcs11` — HSM; the token is signed *inside* the module. Validated against
  SoftHSM2. Required for the strongest key-custody claims.

This choice is the single biggest lever on your key-custody story. A FIPS or "key
never exportable" claim requires `pkcs11` (HSM) or a FIPS-endpoint cloud KMS — not
`file`.

### 4.4 Credential encryption (KEK) — **[Deployment-dependent]**

`BROKER_CREDENTIAL_BACKEND` protects the key that encrypts stored downstream
credentials:

- `local` — AES-256-GCM keyed from `BROKER_CREDENTIAL_KEY` (KEK on the box).
- `vault-transit` — the KEK never leaves Vault; Cipherlatch calls Transit to
  wrap/unwrap. Use this when "no plaintext key material on the app host" is a
  requirement.

### 4.5 OIDC (human login)

| Var | Meaning |
|---|---|
| `BROKER_OIDC_ISSUER` | Your IdP's OIDC issuer URL. |
| `BROKER_OIDC_CLIENT_ID` / `_SECRET` | Confidential client credentials. |
| `BROKER_SESSION_SECRET` | Stable secret for signed session cookies (HMAC-SHA256). Must be identical on every replica behind a load balancer. |
| `BROKER_JIT_PROVISIONING` | `true` = auto-create users on first login; `false` = only pre-provisioned users may sign in. |
| `BROKER_ADMIN_EMAILS` | Comma list granted `broker-admin` at login. |
| `BROKER_ADMIN_EMAIL_PINNING` | `true` (default) re-applies the role at every login (bootstrap safety); `false` seeds it at first login only, so the bootstrap admin can later be demoted or removed. |
| `BROKER_GROUP_ROLE_MAP` | `idp-group=role,...` — let the IdP drive roles on every login (audited). |

Any spec-compliant OIDC provider works (Okta, Microsoft Entra ID, Keycloak,
Ping, Authentik, …).

### 4.6 Multi-tenancy

| Var | Meaning |
|---|---|
| `BROKER_TENANT_DOMAIN_MAP` | Map email domains → tenants; unmatched domains land in the default tenant. |

Named keyrings, SCIM tokens, and gateway routes are **tenant-scoped**: the same
keyring name in two tenants is two independent keys, and a tenant admin can rotate
only its own. The shared `default` ring rotates only via the platform admin key.

### 4.7 Federation (secretless agents)

`BROKER_FEDERATED_ISSUERS` is the allowlist of OIDC issuers whose workload JWTs
(SPIFFE JWT-SVIDs, Kubernetes service-account tokens, CI job tokens) may
authenticate an agent bound to a `federated_issuer` + `federated_subject`. Empty
= federation off.

### 4.8 Gateway & rate limiting

| Var | Default | Meaning |
|---|---|---|
| `BROKER_RATE_LIMIT_PER_MINUTE` | `120` | Per-IP throttle on `/oauth/*` and `/gw/*`. |
| `BROKER_GATEWAY_POLICY_URL` | — | External OPA/Cedar endpoint evaluated per gateway request. |
| `BROKER_GATEWAY_POLICY_FAIL_OPEN` | `false` | Keep **false** — fail closed when the policy engine is unreachable. |
| `BROKER_GATEWAY_TIMEOUT_SECONDS` | `30` | Upstream proxy timeout. |
| `BROKER_GATEWAY_MAX_BODY_BYTES` | `10 MiB` | Max proxied body. |

### 4.9 FIPS — **[Deployment-dependent]**

`BROKER_FIPS_MODE=true` makes the broker verify at startup that OpenSSL is in FIPS
mode and **refuse to boot** otherwise, and keeps `/readyz` gated on it. All
algorithms are already FIPS-approved primitives (ES256, AES-256-GCM, HMAC-SHA256,
SHA-256), but *FIPS 140-3 compliance additionally requires a CMVP-validated
module* — a FIPS OpenSSL base image and/or the `pkcs11` keystore on a validated
HSM. See the FIPS deployment profile in ARCHITECTURE.md. TLS termination, OS entropy,
and the CMVP paperwork are out of the app's scope.

### 4.10 Observability

| Var | Meaning |
|---|---|
| `BROKER_METRICS_ENABLED` | Prometheus `/metrics` (audit counters, HTTP latency). |
| `BROKER_LOG_JSON` | Structured JSON logs. |
| `BROKER_LOG_LEVEL` / `_FORMAT` | Log verbosity/format for the audit mirror. |
| `BROKER_LOG_EVENTS` / `_EXCLUDE` | fnmatch selection of which audit events mirror to stdout. |
| `BROKER_LOG_MASK_FIELDS` / `_MODE` | PII masking (`hash` or `redact`) on the log mirror. The DB audit trail always stays complete. |

### 4.11 Proxy trust

`BROKER_TRUST_PROXY_IP` (default `true`): trust `X-Forwarded-For` for the audited
client IP and rate limiting. **Only enable behind a proxy you control** —
otherwise clients can spoof their audited IP. Set `false` if the broker is
reachable directly.

`BROKER_TRUST_PROXY_HOPS` (default `1`): how many proxies you control append to
`X-Forwarded-For`. The client IP is read as the Nth-from-right entry, so a
client cannot forge it by prepending values. Match your actual proxy depth
(e.g. `2` for CDN → ingress → broker); too low reads a spoofable value, too
high reads your own proxy's address.

---

### 4.12 Admin access & break-glass

| Var | Default | Meaning |
|---|---|---|
| `BROKER_ADMIN_API_KEY` | *(empty)* | Machine admin key(s), comma-separated — any entry authenticates, enabling zero-downtime rotation. Empty disables the header path; every use is audited as `admin_key.used`. |
| `BROKER_ADMIN_EMAIL_PINNING` | `true` | See § 4.5 — controls whether `BROKER_ADMIN_EMAILS` re-applies `broker-admin` at every login. |

Recovery without any network credential: `python -m app.admin promote <email>`
from a shell on the broker host (idempotent; audited as `admin-cli`). When the
broker has no admin key configured *and* no active admin-capable user,
`/readyz` adds an `admin_access` warning field (readiness stays 200) and the
boot log names the recovery command.

---

## 5. Identity provider setup

Cipherlatch delegates human login to your OIDC IdP. Generic steps:

1. In your IdP, create an **OAuth2/OpenID Connect application/client**:
   authorization-code flow, confidential client, redirect URI
   `https://<broker-host>/auth/callback`, RS256 (or ES256) signing.
2. Configure Cipherlatch: `BROKER_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, and a
   stable `BROKER_SESSION_SECRET`.
3. `BROKER_ADMIN_EMAILS` for admins; `BROKER_JIT_PROVISIONING=false` to restrict
   sign-in to users you added manually.

First login binds the OIDC `sub` to the matching pre-provisioned email (the IdP
must not report the email as unverified) or JIT-creates the account. For the
strongest assurance, use an IdP that enforces phishing-resistant MFA.

---

## 6. Access model (RBAC)

Roles are permission sets. Built-ins:

- **`broker-admin`** — full control across all users/agents/tenants.
- **`agent-manager`** — manage *own* agents only (default role).
- **`auditor`** — read the audit log.

Own-scoped vs `:all` permission variants let you build custom roles via the Roles
UI or `/v1/roles`. Users see only their own agents; other users' agents return
**404, never 403** — existence doesn't leak. A **last-admin guard** prevents
removing the final admin.

Assign roles manually, or drive them from the IdP with `BROKER_GROUP_ROLE_MAP` so
access management stays in your directory.

**Team coverage:** agents never go dormant when their owner is away — they
authenticate with their own credentials, and the owner matters only for
*changes*. For someone to manage a colleague's agents (vacation, on-call),
give them a custom role with the `:all` variants they need (`agents:read:all`,
`agents:update:all`, `agents:rotate:all`, `agents:revoke:all`, plus
`credentials:grant:all` / `routes:grant:all` if grants need touching).
Ownership itself is immutable — the `owner` claim in every token is the
delegation audit trail — so transferring an agent means revoking and
recreating it under the new owner.

---

## 7. Key management & rotation

- **Rotate:** `POST /v1/keys/rotate` mints a new signing key; retired keys stay in
  JWKS through `BROKER_KEY_RETENTION_SECONDS` (default 24h) so in-flight tokens
  keep verifying. Optional startup auto-rotation via `BROKER_KEY_MAX_AGE_SECONDS`.
- **Keyrings:** assign agents to named signing rings; each rotates independently
  (`POST /v1/keys/rotate?keyring=...`), isolating rotation blast radius.
  Tenant-scoped (see § 4.6). JWKS serves the union, so verifiers never change.
- **Verifiers need no coordination** — they always refetch JWKS by `kid`.
- **Machine admin key:** `BROKER_ADMIN_API_KEY` is a comma-separated list; any
  entry authenticates. Rotate with zero downtime: add the new key, redeploy,
  migrate callers, remove the old.

---

## 8. User lifecycle & provisioning

- **Manual:** `POST /v1/users`, or the Web UI user admin.
- **JIT:** created on first OIDC login when `BROKER_JIT_PROVISIONING=true`.
- **SCIM 2.0** (`/scim/v2/Users`): the IdP pushes create/update/deactivate/delete
  with a per-tenant bearer token (`POST /v1/scim-token`). **Deactivating a user
  suspends every agent they own** — new mints *and* outstanding tokens — until
  reactivation; **deleting revokes their agents permanently.**
- **Soft-delete:** deleting a user revokes all owned agents.

---

## 9. Security operations

### 9.1 The `/oauth/token` exposure

`/oauth/token` is unauthenticated by protocol design (client_credentials proves
identity by presenting the client secret in the body). Cipherlatch defends it with:

- **Token-endpoint lockout** (NIST 800-63B-style): consecutive failures lock a
  `client_id` for `BROKER_LOCKOUT_SECONDS`; rotation clears it.
- **Per-IP rate limit** (`BROKER_RATE_LIMIT_PER_MINUTE`).

**[Deployment-dependent]** Volumetric DoS protection at scale is the reverse
proxy / ingress / WAF's job. Front internet-facing deployments with edge
throttling; do not rely on the app's per-IP limit alone at the edge.

### 9.2 Proof-of-possession

DPoP (RFC 9449, `BROKER_DPOP_ENABLED`, default on) binds a token to the agent's
key — a stolen token is useless without the private key. The gateway enforces
DPoP binding. `private_key_jwt` (RFC 7523) removes the shared secret entirely.

### 9.3 Revocation & introspection

- `POST /oauth/revoke` — kill a token now (RFC 7009).
- `POST /v1/agents/{id}/revoke-tokens` — mass-revoke an agent's outstanding tokens.
- `POST /oauth/introspect` — resource servers check active state (RFC 7662).

### 9.4 Standing credentials & break-glass

Every use of the machine admin key — reads included — writes an
`admin_key.used` audit event with method and path. **Alert on it**: a root
credential should never be silent. Better still, run without one
(`BROKER_ADMIN_API_KEY` empty disables the header path); recovery is then
`python -m app.admin promote <email>` from a shell on the broker host, which
is idempotent and audited as `admin-cli`. When the broker is keyless and no
active admin-capable user exists, `/readyz` reports an `admin_access` warning
(readiness stays 200) and the boot log names the recovery command. The
last-admin guard means the API, UI, and SCIM can never remove the final
admin; the CLI is the way back in if every login path is lost anyway.

### 9.5 Supply chain

CI runs dependency vulnerability scanning (blocking), SAST, secret detection, and
emits a CycloneDX SBOM per deploy. Policy and hardening guide: `SECURITY.md`.

---

## 10. Observability & audit

- **Audit trail:** `GET /v1/audit` (admin/auditor). Every issuance, denial, login,
  lifecycle change — with actor and IP. The DB trail is always complete.
- **SIEM:** mirror the audit stream to stdout (JSON) and ship it; tune which
  events and mask PII per § 4.10 without ever thinning the DB record.
- **Metrics:** Prometheus `/metrics`.
- **Health:** `/readyz` (readiness, gated on keystore/FIPS state), plus the app
  liveness endpoint.

---

## 11. Day-2 runbook (quick reference)

| Task | Action |
|---|---|
| Add an agent owner | `POST /v1/users` |
| Register an agent | `POST /v1/agents` (secret shown once) |
| Rotate a compromised agent secret | rotate the agent; lockout clears automatically |
| Kill all of an agent's tokens now | `POST /v1/agents/{id}/revoke-tokens` |
| Off-board a person | SCIM deactivate, or soft-delete user (revokes their agents) |
| Rotate signing key | `POST /v1/keys/rotate` (retired keys linger in JWKS) |
| Suspected token theft | revoke token + rotate agent; confirm DPoP is on |
| Add a tenant | map its domain via `BROKER_TENANT_DOMAIN_MAP` |
| Upgrade schema | deploy new image; Alembic self-applies under advisory lock |
| Locked out (no admin login works) | `docker exec <container> python -m app.admin promote <email>` |
| Rotate the machine admin key | set `BROKER_ADMIN_API_KEY=newkey,oldkey`, redeploy, migrate callers, drop the old |
| Cover an absent colleague's agents | assign a custom role with the needed `agents:*:all` permissions |

---

## 12. Infrastructure as code

Cipherlatch exposes idempotent natural-key upserts (`PUT /v1/agents/by-name/{name}`, …)
that report `changed`/`unchanged`, plus declarative convergence (`POST /v1/apply`,
`?dry_run=true` for check mode). Drive it from your configuration-management
tooling with plain HTTP tasks against the machine admin key. See ARCHITECTURE.md
§ Automation / infrastructure-as-code.

---

## Appendix A — Deployment-dependent decisions, collected

These are the choices where your posture depends on how you deploy, not on the
code. Decide each explicitly and record it:

| Decision | Options | Drives |
|---|---|---|
| Signing keystore | `file` / `vault` free; KMS / `pkcs11` HSM (Enterprise) | Key custody, multi-replica, FIPS |
| Credential KEK | `local` / `vault-transit` | Whether plaintext key material sits on the host |
| Replicas | 1 / N | Forces shared keystore + PostgreSQL |
| FIPS | off / `BROKER_FIPS_MODE=true` on validated module | FIPS 140-3 claim |
| Edge exposure | private / internet-facing | DoS surface on `/oauth/token` |
| Rate/DoS | app per-IP only / + proxy/WAF | Abuse resistance at scale |
| Tenancy | single / multi (`TENANT_DOMAIN_MAP`) | Isolation of keyrings/SCIM/routes |
| Provisioning | manual / JIT / SCIM | Where user lifecycle is authoritative |
| TLS termination | reverse proxy / ingress | Not the app's job — must be configured |
