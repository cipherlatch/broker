# Cipherlatch (Broker for Agentic Access Management) — Architecture

How Cipherlatch works today. For where it's headed see [ROADMAP.md](ROADMAP.md);
for why it's built the way it is see [DECISIONS.md](DECISIONS.md).

An open-source identity and access management broker for AI agents. Agents get
first-class identities tied to a human owner, authenticate to the broker, and
receive short-lived, scoped credentials for downstream services. Humans and
policy decide what an agent may do; the broker mints, enforces, and audits.

## Why

AI agents today borrow their operator's credentials: long-lived API keys pasted
into env vars, personal OAuth tokens, shared service accounts. That breaks the
basics of IAM — no per-agent identity, no least privilege, no revocation, no
audit trail that distinguishes the human from the agent acting for them.

The broker fixes this by making the agent a principal:

- **Identity** — every agent is registered, owned by a human principal, and
  holds its own credential. Revoking one agent never touches another.
- **Least privilege** — agents are granted scopes; tokens are minted per-request
  as a subset of the grant, with short TTLs (minutes, not months).
- **Delegation** — tokens carry both the agent identity (`sub`) and the owning
  human (`owner`), so downstream services and logs can always answer "which
  agent, acting for whom?"
- **Audit** — every issuance, denial, and lifecycle event is recorded.

Multi-tenant and IdP-agnostic by design. Any OIDC provider (Authentik, Keycloak,
Okta, …) can be the human-facing IdP; the broker owns only *agent* identity.
MCP authorization compatibility is an explicit target: an MCP server can validate
broker-minted tokens with nothing but the JWKS URL.

## System shape

```
                 ┌───────────────────────────────────────────┐
   human ──OIDC──►  Broker                                    │
  (any IdP)      │  ┌─────────┐ ┌────────┐ ┌──────┐ ┌───────┐ │
                 │  │identity │ │ token  │ │policy│ │ audit │ │
   agent ──creds─►  │registry │ │ mint   │ │engine│ │ log   │ │
                 │  └─────────┘ └────────┘ └──────┘ └───────┘ │
                 └───────┬───────────────────────────────────┘
                         │  short-lived scoped JWTs
                         ▼
        downstream services verify via JWKS, or calls flow
        through the broker's enforcing proxy (credential injected server-side)
```

## What it does

- **Agent identity + token minting** — tenants, human principals, an agent
  registry; each agent has a `client_id` + high-entropy secret (stored hashed),
  rotatable and revocable. `POST /oauth/token` (client_credentials) mints
  ES256-signed JWTs (default 5-min TTL); requested scope must be a subset of the
  grant. `GET /.well-known/jwks.json` lets any service verify offline.
- **Human plane** — OIDC login for humans with JIT or manual provisioning; a
  server-rendered, themable Web UI for agents, users, and audit. A bootstrap
  machine key (`X-Admin-Key`) remains for CI/scripting.
- **Access model & RBAC** — roles are permission sets; per-user isolation
  (owners see only their own agents); multiple admins with a last-admin guard.
- **Credential brokering** — a granted agent trades its live broker token for a
  downstream secret (RFC 8693 token exchange), or the secret is injected
  server-side by the gateway so the agent never holds it.
- **Enforcing gateway** — `/gw/<slug>` proxies to an upstream with the credential
  injected server-side, method/path policy, per-agent rate/quota limits, and an
  optional external OPA/Cedar policy hook (fail-closed).
- **Stronger client auth** — `private_key_jwt` and DPoP proof-of-possession;
  token revocation and introspection (RFC 7009/7662).
- **Multi-tenancy** — every actor is bound to one tenant; per-tenant keyrings;
  a platform-admin plane manages tenants.
- **Pluggable keystores** — `file` and `vault` built in; HSM/cloud-KMS/JKS custody
  in the commercial plugin. The credential-encryption KEK is separately pluggable.
- **Secretless / workload federation** — SPIFFE / OIDC-federated agents
  authenticate with a platform-minted JWT; no broker secret exists.
- **Dynamic credentials** — provider-backed credentials mint short-lived material
  at exchange time (the `ssh-ca` provider ships).
- **Lifecycle provisioning** — SCIM 2.0; IdP group→role mapping.
- **Automation** — natural-key upserts and a declarative `POST /v1/apply` for
  Ansible/GitOps.
- **Observability** — Prometheus metrics, structured logs, and a tunable audit
  mirror to stdout for SIEM.

The rest of this document is the detail behind each of those.

## Access model (configurable RBAC)

- **Actors**: a human principal (OIDC session, carrying a **Role**), the
  machine admin key (`X-Admin-Key`; grants `*`, actor recorded as
  `admin-key`), or — with shell access to the broker host — the break-glass
  CLI (`python -m app.admin`, actor recorded as `admin-cli`). The UI accepts
  sessions only. The admin key is optional (empty disables the header path
  entirely), accepts a comma-separated list so it rotates with no lockout
  window, and **every use is audited** as `admin_key.used`, reads included —
  standing-credential activity is alertable, never silent.
- **Roles are permission sets** ([app/permissions.py](app/permissions.py)):
  flat strings where the bare form is own-scoped and `:all` crosses
  ownership (e.g. `agents:rotate` vs `agents:rotate:all`). Three immutable
  built-ins are seeded per tenant — `broker-admin` (`*`), `agent-manager`
  (own-agent lifecycle), `auditor` (read-everything, change-nothing) — and
  admins can create custom roles from any permission combination via
  `/v1/roles` or the Roles UI. Role edits take effect on the next request;
  no re-login needed.
- **Multiple admins** are just multiple principals holding `broker-admin`
  (or any role with `users:manage`). A last-admin guard refuses the
  demotion/disable/delete that would leave zero active admin-capable users.
- **Isolation**: non-admin lookups outside the actor's own agents return
  **404, not 403** — resource existence never leaks across users. The audit
  API is scoped the same way (own agents' events + own actions).
- **Audit pagination**: `/v1/audit` uses keyset pagination — `before=<event
  id>` returns strictly older events (ordered `created_at, id` desc) and an
  `X-Next-Before` response header carries the cursor while more pages exist.
  The body stays a plain list (backward compatible); the anchor id resolves
  through the actor's scope, so a foreign event id is a 404. Other list
  endpoints stay unpaginated deliberately — they are human-scale (agents,
  users, routes); the audit log is the only unbounded collection.
- **Account linking**: first OIDC login matches by `sub`; otherwise it binds
  `sub` to a pre-provisioned account with the same email, refused if the IdP
  reports the email as unverified. Deleted accounts never re-enter through
  JIT, even if the IdP later rotates their subject identifier.
- **Bootstrap admin**: `BROKER_ADMIN_EMAILS` grants `broker-admin` at login.
  While `BROKER_ADMIN_EMAIL_PINNING` is true (the default) the grant is
  re-applied at every login, so a demotion lasts only until the next
  sign-in — useful before any other admin exists. Set it false once real
  admins exist: the list then only seeds the role at first login, and the
  bootstrap account can be demoted, disabled, or deleted like any other user
  (the last-admin guard still applies).
- **UI sessions** are stateless signed cookies (HMAC-SHA256) carrying only
  the principal id; the principal's state (active/deleted/role) is re-read
  from the database on every request. Sessions therefore work across any
  replicas that share `BROKER_SESSION_SECRET` and one database, and a
  disable/demote/delete takes effect on every node at that user's next
  request — no server-side session store, nothing to invalidate.
- **CSRF**: session cookie is SameSite=lax; state-changing requests carrying
  the session cookie are additionally rejected on cross-origin `Origin`.

## Multi-tenancy

Every actor is bound to exactly one tenant — a human to their principal's tenant
(a tenant `broker-admin`'s `*` is bounded to that tenant, *not* global), the
machine admin key to an `X-Tenant` header (default `default`). Every data path
(agents, credentials, routes, users, roles, audit, tokens, gateway) filters by
the actor's tenant; cross-tenant reads return 404, never 403. Users route to a
tenant by email domain (`BROKER_TENANT_DOMAIN_MAP`) at login. The tenant plane —
create/list/delete tenants (`/v1/tenants`) — is the only cross-tenant surface and
is **platform-admin-only** (the machine key); the platform admin also sees
tenant-less system audit (key rotations, pre-auth denials). Each new tenant is
seeded with the built-in roles.

**Per-tenant keyrings**: named keyrings are tenant-scoped — the agent-facing name
resolves to a storage ring of `<tenant-slug>.<name>` (the dot appears in neither
the slug nor the ring-name charset, so tenants can never collide), meaning the
same name in two tenants is two independent keys. `GET /v1/keys` shows a tenant
actor its own rings by name (platform admin sees every storage ring);
`POST /v1/keys/rotate` rotates within the actor's tenant. The `default` ring is
the one deliberately shared piece — it keeps the pre-keyring storage layout so
existing deployments' keys are untouched — and is therefore **platform-admin-only
to rotate**.

## Credential brokering + scoped keys

- **RFC 8693 token exchange**: a granted agent trades its (fresh, unexpired)
  Cipherlatch token for a downstream credential — HA long-lived token, GitLab PAT,
  any API secret — which is never stored agent-side. Exchange requires client
  authentication **and** a valid subject token for the same agent, so neither
  a stolen token nor a stolen client secret suffices alone.
- **Credential store**: secrets encrypted at rest (AES-256-GCM keyed from
  `BROKER_CREDENTIAL_KEY`; feature disabled until set), **write-only** after
  creation (replace, never read), owner-scoped with explicit **per-agent
  grants** — deliberately not scope-based, since owners self-assign scopes.
  Grant/revoke/exchange/denial all audited; `invalid_target` is identical for
  "unknown" and "not granted" (no enumeration).
- **Keyrings**: agents are assigned a signing keyring (`default` unless set);
  each ring rotates independently, so one ring's rotation never touches
  another's tokens. JWKS serves the union of all active rings; downstream
  verifiers are unaffected. Backends with externally managed key material (the
  Cipherlatch Enterprise HSM/KMS/JKS plugins) support the default ring only.

## Enforcing policy gateway

- A **route** binds a slug (`/gw/<slug>/...`) to an upstream base URL, a stored
  credential, an injection mode (bearer / custom header / basic), and a policy
  (allowed methods + allowed path prefixes). Owner-scoped with explicit
  per-agent grants, managed via `/v1/routes` and a Gateway UI page.
- The proxy authenticates the agent's Cipherlatch token, confirms the route grant,
  enforces the method/path policy, **injects the credential server-side**,
  strips hop-by-hop/auth/cookie headers, proxies to the upstream, and audits
  the transaction (`gateway.proxied` / `gateway.denied` / `gateway.error` with
  status, bytes, latency). The agent never holds the downstream secret at all.
- Guardrails: URL-join defeats path traversal / absolute-URL escapes (a request
  can never leave the route's base), response-size cap, upstream timeout, and
  unknown/inactive/ungranted routes return an identical 403 (no enumeration).
- **Rate/budget limits**: per-route `rate_limit_per_minute` and `daily_quota`
  (0 = unlimited), enforced per granted agent with in-process fixed-window
  counters (per-replica; restarts reset — the trade-off for a DB-write-free hot
  path). Denials are 429 and audited (`rate_limited` / `quota_exceeded`).
- **External policy hook** (OPA / cedar-agent): when
  `BROKER_GATEWAY_POLICY_URL` is set, each request that passes the built-in
  checks is POSTed as an OPA-data-API document —
  `{"input": {tenant, agent{id,client_id,name,owner}, route{slug,upstream_base},
  request{method,path}, scopes}}` — and allowed only on `{"result": true}` or
  `{"result": {"allow": true}}`. Errors/timeouts **fail closed** (deny +
  audit `policy_unreachable`) unless `BROKER_GATEWAY_POLICY_FAIL_OPEN` makes
  the hook advisory. Write policy in Rego (OPA) or Cedar (cedar-agent) —
  the broker stays engine-agnostic.

## Stronger client auth, revocation, rate limiting

- **Token revocation + introspection** (RFC 7009 / 7662): `/oauth/revoke`
  denylists a token by `jti`; a per-agent generation counter mass-revokes
  every outstanding token (`POST /v1/agents/{id}/revoke-tokens`) without
  disabling the agent; `/oauth/introspect` (client-authenticated) reports
  active state. The gateway honors both.
- **Stronger client auth** (RFC 7523 / 9449): `private_key_jwt` — an agent
  registers a public JWK and authenticates with a signed assertion instead of
  a shared secret; **DPoP** — a proof binds the token to the client's key
  (`cnf.jkt`), and the gateway requires a fresh matching proof, so a stolen
  token is useless without the private key.
- **Built-in rate limiting**: per-client-IP fixed-window limiter on `/oauth/*`
  and `/gw/*` (in-process, per-replica).

## Workload identity federation (secretless)

An agent bound to (`federated_issuer`, `federated_subject`) authenticates by
presenting a JWT its *platform* minted — a SPIFFE JWT-SVID via SPIRE's OIDC
discovery provider, a Kubernetes service-account token, a GitLab CI id_token — as
the `client_assertion`, verified against the issuer's JWKS. No broker secret is
issued at all (the stored digest is of a discarded random value), killing
"secret zero": nothing is provisioned to the workload because the platform
already attests it. Trust is anchored twice: the platform-level
`BROKER_FEDERATED_ISSUERS` allowlist gates which issuers exist, and the assertion
must match the binding, be audience-restricted to the broker, and be unexpired.
Assertions route by their `iss`: `iss == client_id` stays private_key_jwt
(RFC 7523), an external `iss` is federated. Works for minting and RFC 8693 token
exchange — an OAuth `client_id` anchored to platform attestation instead of a
bare registration artifact.

## Keystores

`BROKER_KEYSTORE` selects where the ES256 signing key lives
([app/keystore/](app/keystore/)); JWKS, minting, and `kid` derivation are
backend-agnostic. `file` and `vault` are built in (AGPL); the hardware/cloud
custody backends below ship in the commercially licensed **cipherlatch-enterprise**
plugin package and register through the `cipherlatch.keystores` entry-point group —
any installed package can provide a backend the same way, and
`BROKER_KEYSTORE=<name>` is unchanged once it is installed.

| Backend | Key material | Generate on first boot | Notes |
|---|---|---|---|
| `file` (default) | PEM on disk, 0600 | yes | single-node |
| `vault` | Vault KV v2 (`BROKER_VAULT_*`) | yes | clustering default; token needs read+write on the path |
| `jks` | Java KeyStore (`BROKER_JKS_*`) | no — pre-provision with keytool | enterprise hand-off format; read-only |
| `pkcs11` | HSM via PKCS#11 (`BROKER_PKCS11_*`) | no — pre-provision on the token | private key never leaves the HSM; JWS assembled manually and signed inside the token. Validated against SoftHSM2 in the cipherlatch-enterprise suite; single worker per process, default keyring only |
| `awskms` | AWS KMS asymmetric key(s) (`BROKER_AWSKMS_KEY_IDS`, comma-separated; ECC_NIST_P256/SIGN_VERIFY) | no — create in KMS | signs inside KMS (one API call per mint); first listed key signs, the rest stay in JWKS so external rotation is create-key → prepend → drop-old-after-TTL, restart between steps. Default keyring only |
| `gcpkms` | GCP Cloud KMS (`BROKER_GCPKMS_KEY`, cryptoKey or pinned version; EC_SIGN_P256_SHA256) | no — create in KMS | signs inside KMS; all ENABLED versions served in JWKS, newest signs — external rotation is "add a version, restart". Default keyring only |
| `azurekv` | Azure Key Vault key (`BROKER_AZUREKV_VAULT_URL` + `_KEY_NAME`; EC P-256) | no — create in the vault | signs inside the vault; all enabled versions served in JWKS, newest signs — pairs with Key Vault's scheduled rotation policy. Default keyring only |

Each enterprise backend's SDK is an optional extra of `cipherlatch-enterprise`
(e.g. `cipherlatch-enterprise[awskms]`). The PKCS#11 path is exercised end-to-end
against SoftHSM2 in that repo's tests. Real HSM hardware (Luna, YubiHSM,
TPM-via-PKCS#11) should still be validated against your specific module before
production.

### Protecting the credential-encryption key

Downstream credentials are encrypted with a key-encryption key (KEK) selected
by `BROKER_CREDENTIAL_BACKEND`:

- `local` (default) — AES-256-GCM keyed from SHA-256(`BROKER_CREDENTIAL_KEY`),
  random 96-bit nonce per record; the KEK is derived on the host. (Pre-AES-256
  Fernet blobs still decrypt for backward compatibility.)
- `vault-transit` — encryption/decryption run through Vault's transit engine
  (`BROKER_VAULT_TRANSIT_MOUNT`/`_KEY`, reusing `BROKER_VAULT_ADDR`/`_TOKEN`).
  The KEK never leaves Vault, so a broker-host compromise cannot decrypt
  stored credentials offline; with Vault Enterprise the transit key can itself
  be HSM-backed (managed keys / seal-wrap) — the pragmatic "HSM-lite" path.

Ciphertexts are self-describing (`vault:v1:...` blobs route to transit on
decrypt regardless of the active backend), so switching backends never
strands previously stored secrets. Signing keys and the credential KEK are
independent — you can HSM-back either, both, or neither.

### Key rotation

`file` and `vault` backends hold a **set** of keys: the newest signs, retired
keys stay in JWKS for `BROKER_KEY_RETENTION_SECONDS` (default 24h, far beyond
max token TTL) so in-flight tokens keep verifying, then age out on the next
rotation. Rotate via `POST /v1/keys/rotate` (permission `keys:manage`), view
status via `GET /v1/keys` (`keys:read`; auditors have it). Both are
tenant-scoped. Optional `BROKER_KEY_MAX_AGE_SECONDS` auto-rotates at startup
when the active key is older. Enterprise-backend (HSM/KMS/JKS) key material is
externally managed; rotation there is out-of-band (keytool/HSM tooling) and the
endpoint says so with a 409.

## Dynamic credential providers

A stored credential may be **provider-backed** — on RFC 8693 exchange, instead of
decrypting a blob, Cipherlatch asks a provider plugin to **mint short-lived
material scoped to that agent, right now**. The `ssh-ca` provider is delivered
(see [ROADMAP.md](ROADMAP.md) for later providers).

Operator recipe (`ssh-ca`):

```bash
# 1. Generate a CA keypair; the private key is the credential seed.
ssh-keygen -t ed25519 -f cipherlatch_ssh_ca -N ''
# 2. Register it as a provider-backed credential (secret = the CA private key).
curl -X POST $Cipherlatch/v1/credentials -H "X-Admin-Key: $KEY" -d @- <<JSON
{ "name": "prod-ssh", "owner_email": "you@example.com", "provider": "ssh-ca",
  "secret": "$(cat cipherlatch_ssh_ca | jq -Rs .)",
  "provider_config": { "principals": ["agent-{name}"], "ttl": 300 } }
JSON
# 3. Grant the agent, then on target hosts trust the CA:
#    echo "@cert-authority *  $(cat cipherlatch_ssh_ca.pub)"  ->  TrustedUserCAKeys
# 4. The agent: generate its own keypair, exchange its PUBLIC key for a cert.
curl $Cipherlatch/oauth/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=$CID -d client_secret=$CSEC \
  -d subject_token=$CIPHERLATCH_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=prod-ssh --data-urlencode public_key@id_ed25519.pub
#    -> {"access_token": "<ssh cert>", "issued_token_type":
#        "urn:cipherlatch:params:oauth:token-type:ssh-certificate", "expires_in": 300}
# ssh -i id_ed25519 -o CertificateFile=<cert> user@host
```

Scope guard, decided up front: this is an *agent-side* seam only — see
[DECISIONS.md](DECISIONS.md) for why Cipherlatch is not a human entitlement engine
and never proxies the downstream protocol.

### The seam

```python
# app/credential_providers/base.py
class CredentialProvider:
    kind: str                       # "ssh-ca" | "postgres" | "aws-sts" | ...
    def issue(self, credential, agent, claims, params) -> Issued: ...

@dataclass
class Issued:
    secret: str        # what the agent receives (cert, password, creds bundle)
    token_type: str    # RFC 8693 issued_token_type URN for the material
    expires_in: int    # provider-chosen TTL (short — minutes)
```

Registry keyed by `kind` with lazy imports. Provider modules are leaves;
per-provider SDK extras go in a `requirements-providers.txt`, never the base image.

### `ssh-ca` provider (delivered)

Signs OpenSSH certificates against a CA key held (encrypted) as the credential
seed. `cryptography` ≥ 40 ships `SSHCertificateBuilder`, so this costs **zero new
dependencies**. Config is validated at credential create/update, never at exchange
time. Allowed extensions are allowlisted so a typo can't grant port forwarding.

- The agent generates its own keypair and submits the **public key** as an
  exchange parameter — private key never transits. The issued `secret` is
  the signed certificate; the agent connects with its own key + cert.
- `provider_config`: allowed principals (templated from the agent, e.g.
  `agent-{name}`), cert TTL (default 300s), extensions (default: none — no
  PTY for automation), optional source-address pinning.
- **The delegation chain rides in the cert `key_id`**:
  `cipherlatch:agent:<id>:owner:<email>:jti:<jti>` — every sshd auth log line then
  answers "which agent, acting for whom, from which token", extending the
  audit trail onto boxes Cipherlatch never sees.
- Honest revocation stance: SSH certs are not introspectable — the control
  is the short TTL. Mass-revoke (`token_gen`) stops *new* issuance immediately
  but cannot recall a live cert; the reason the default TTL is 5 minutes.

## Automation / infrastructure-as-code

Built for Ansible/Puppet/Chef/GitOps without custom modules:

- **Natural-key upserts** — `PUT /v1/users/by-email/{email}`,
  `/v1/roles/by-name/{name}`, `/v1/credentials/by-name/{name}`,
  `/v1/agents/by-name/{name}`, `/v1/routes/by-slug/{slug}`. Create-or-converge
  semantics: fields you provide are converged, fields you omit are untouched, and
  the response speaks Ansible's vocabulary (`"changed": true/false`,
  `"action": created|updated|unchanged`, a `changes` diff). Secrets are returned
  only on create and never regenerated by an update. Route/credential upserts take
  `granted_agents` as the exact desired set — grants converge, additions and
  revocations both.
- **Declarative apply** — `POST /v1/apply` converges a whole desired-state
  document (roles → users → credentials → agents → routes, so forward references
  resolve) and returns a per-item report plus one-time secrets for created agents.
  `?dry_run=true` computes the same report without writing — Ansible check mode /
  CI plan step. Apply converges what you declare; it never deletes undeclared
  resources.
- Everything runs through the same crud layer as the plain endpoints, so
  permissions, guards, and the audit trail are identical. Secretless federated
  agents pair especially well with automation: creation is fully re-runnable
  because there is no one-time secret to capture.

## Scaling & HA

The broker is stateless by construction: sessions are signed cookies, OIDC
handshake state rides in the session, and lockout counters live in the database.
What replicas must share:

| Concern | Answer |
|---|---|
| Signing key | Pluggable keystore. `vault` is the clustering default — every replica reads the same key and nothing touches local disk. `file` is single-node. |
| Schema migrations | Container entrypoint runs Alembic under a Postgres advisory lock, so N replicas starting simultaneously upgrade exactly once. |
| Health | `/healthz` (liveness) and `/readyz` (DB + keystore) for LB checks. |
| Sticky sessions | Not needed. |

[docker-compose.ha.yml](docker-compose.ha.yml) runs N replicas behind an nginx LB
on one Docker host. Single-host compose is resilience against process crashes, not
node loss — for true multi-node failover run on Kubernetes.

**Kubernetes:** [charts/cipherlatch](charts/cipherlatch) is the Helm chart —
deployment (liveness `/healthz`, readiness `/readyz`, non-root security context,
config/secret checksum-based pod rolls), service, optional ingress, and a
ConfigMap/Secret pair (or `secrets.existingSecret` for external-secrets shops).
Postgres is external by design; migrations self-apply on pod start under the
advisory lock. `keystore.type=vault` (or a cloud-KMS backend) is the multi-replica
default; the chart *refuses to render* `file` keystore with more than one replica.

## Observability

- **Metrics** (`/metrics`, Prometheus; `BROKER_METRICS_ENABLED`):
  `cipherlatch_audit_events_total{event}` — one counter family covering token
  issuance/denial/lockouts, logins, and every lifecycle event — plus HTTP
  latency histograms and in-flight gauge. Unauthenticated by design; keep it
  inside the network boundary.
- **Structured logs**: `BROKER_LOG_JSON=true` switches stdout to one JSON object
  per line; every audit event is mirrored to the `cipherlatch.audit` logger with
  actor/IP/detail, so a log shipper gets the full audit stream without database
  access.
- **Configurable log mirror** — the DB audit trail is always complete and
  unmasked; what leaves on stdout is tunable: `BROKER_LOG_LEVEL` /
  `BROKER_LOG_FORMAT`; `BROKER_LOG_EVENTS` / `_EXCLUDE` (fnmatch patterns);
  `BROKER_LOG_MASK_FIELDS` with `BROKER_LOG_MASK_MODE=hash` (stable across events
  for SIEM correlation) or `redact`.

## IdP group → role mapping

`BROKER_GROUP_ROLE_MAP="idp-group=role,..."` (claim named by
`BROKER_OIDC_GROUPS_CLAIM`, default `groups`). First matching pair wins; when a
mapping matches, the IdP is authoritative — role changes sync on every login and
are audited as actor `idp-groups`. JIT provisioning uses the mapping for the
initial role. Precedence: `BROKER_ADMIN_EMAILS` > group map >
`BROKER_DEFAULT_ROLE`. The last-admin guard also applies to group-driven
demotions. Manual role assignment remains for principals no mapping matches.

## SCIM

SCIM 2.0 (RFC 7643/7644) lets the IdP push user lifecycle
(create/update/deactivate/delete) instead of JIT/manual. `/scim/v2/Users` maps
onto `Principal` — userName→email (tenant-unique), externalId→OIDC `sub`,
active→active — with the discovery documents, filtering, pagination, PUT and PATCH
(including Entra's quirks), and RFC 7644 error responses.

- **Auth**: a per-tenant bearer token (`POST /v1/scim-token`, permission
  `users:manage`), stored as a SHA-256 digest. The token maps requests to exactly
  one tenant — a tenant's IdP can never touch another tenant's users.
- **Lifecycle semantics** match the admin API: DELETE soft-deletes and revokes
  owned agents; the last-admin guard refuses deactivating/deleting the last
  admin-capable user; re-POSTing a soft-deleted userName revives the principal.
- **Deprovisioning actually deprovisions**: the token endpoint and
  `verify_token()` reject agents whose owner is inactive or deleted, so
  `active=false` from the IdP suspends the human's whole delegation tree —
  outstanding tokens included — and reactivation restores it.
- **Groups are deliberately not implemented** — role assignment stays with the
  OIDC group→role map at login (see [DECISIONS.md](DECISIONS.md)).

## Standards alignment

Every mechanism is an application of an existing spec.

| Standard | What it governs here |
|---|---|
| OAuth 2.1 / RFC 6749 client credentials | How agents authenticate and request tokens (`/oauth/token`, RFC 6749 §5.2 error format) |
| RFC 7638 (JWK thumbprint) | Signing key `kid` derivation |
| RFC 8414 (AS metadata) | `/.well-known/oauth-authorization-server` discovery (minimal) |
| RFC 8707 (Resource Indicators) | `resource` parameter → audience-bound tokens per downstream service. Optional per-agent resource allowlist. Required by the MCP authorization spec. |
| RFC 8693 (Token Exchange) | Trading a broker token for a downstream credential |
| RFC 9449 (DPoP) | Proof-of-possession binding so a stolen token is useless without the agent's key |
| RFC 7009 / 7662 (Revocation / Introspection) | Kill a token now; resource servers check active state |
| RFC 7523 (private_key_jwt) | Signed client assertion instead of a shared secret |
| RFC 7643/7644 (SCIM 2.0) | IdP-pushed user lifecycle |
| SPIFFE / OIDC workload federation | Secretless agent bootstrap; no broker secret exists |
| OAuth 2.1 authorization code + PKCE | Human-delegated MCP client access (`/oauth/authorize`, S256 only, behind `BROKER_MCP_AS_ENABLED`) |
| RFC 9207 (`iss` in authorization responses) | Mix-up defense on every authorize redirect, success and error |
| Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document) | MCP client registration: an https URL *is* the client_id; redirect URIs pinned to the fetched document |

### MCP authorization compatibility

The broker can serve as the authorization server for any MCP server, per the MCP
spec's authorization section (current revision **2025-11-25**; verify at
[modelcontextprotocol.io/specification/versioning](https://modelcontextprotocol.io/specification/versioning)).
What the current revision demands, and where we stand:

| MCP requirement (AS side) | Status |
|---|---|
| OAuth 2.1 semantics at the token endpoint | ✅ (client_credentials + authorization_code) |
| RFC 8414 or OIDC discovery metadata | ✅ (RFC 8414; advertises the full MCP surface when enabled) |
| Honor RFC 8707 `resource` and audience-bind tokens | ✅ |
| Short-lived access tokens | ✅ (5-min agent TTL; 1-hour default for user-delegated MCP tokens) |
| PKCE + `code_challenge_methods_supported` in metadata | ✅ (S256 only) |
| Client ID Metadata Documents | ✅ (DCR deliberately not offered — the MCP spec deprecates it) |
| RFC 9207 `iss` in authorization responses | ✅ |

The whole surface ships dark behind **`BROKER_MCP_AS_ENABLED`** (default off).
When on: MCP servers are **registered resources** — an admin enrolls each server
URI per tenant, and the broker never mints a token for an audience it doesn't
know. A user delegates through a consent screen; approvals persist per
(client, resource) pair and are revocable by the user or an admin, and revoking
consent invalidates outstanding tokens at verification time, not just future
grants. A replayed authorization code burns the token it originally minted
(OAuth 2.1 §4.1.2). There are no refresh tokens: the longer `mcp_token_ttl`
class bounds re-authorization friction instead, keeping every credential
short-lived. CIMD fetches are SSRF-hardened (https-only, public-address
resolution enforced, no redirects, size-capped).

The corresponding RFC 9728 protected-resource-metadata document lives on each MCP
server, not here. Upcoming MCP revision hardening is tracked in
[ROADMAP.md](ROADMAP.md).

### NIST alignment

NIST SP 800-63 (rev 4) is written for *human* identity; the broker deliberately
applies its principles to agents as non-person entities. "Designed in alignment
with," not a certified compliance statement.

- **SP 800-63B (authenticators):** agent secrets are high-entropy random
  (256-bit), stored only as digests, rotatable, and revocable. Failed-attempt
  throttling locks the client_id for a configurable window; rotation clears it.
- **SP 800-63C (federation & assertions):** minted tokens follow 63C assertion
  requirements — signed (ES256), expiring (minutes), replay-scoped (`jti`),
  audience-restricted (per-resource via RFC 8707), issuer and subject identified.
  The `owner` claim carries the delegation chain from human principal to agent.
- **SP 800-207 (Zero Trust):** the broker is the policy decision point for agent
  access; the enforcing proxy is the policy enforcement point, with per-request
  evaluation and full-flight audit.

The customer-facing 800-53 control mapping lives in
[docs/customer/nist-800-53-mapping.md](docs/customer/nist-800-53-mapping.md).

### Cryptographic posture (FIPS)

All algorithms are FIPS-approved primitives: **ES256** (ECDSA P-256 + SHA-256,
FIPS 186-5) for token signatures, **AES-256-GCM** (SP 800-38D) for credentials at
rest, **HMAC-SHA256** for session cookies, **SHA-256** for agent-secret digests
and key thumbprints. *FIPS 140-3 compliance* additionally requires these to run
inside a CMVP-validated module — a FIPS-mode crypto library and/or the PKCS#11
keystore on a validated HSM — a deployment property, not an app property.

**`BROKER_FIPS_MODE=true`** makes that property enforced instead of assumed: at
startup the broker verifies OpenSSL (via the `cryptography` backend) is operating
in FIPS mode and **refuses to boot** otherwise; `/readyz` keeps reporting the
provider state so a regression flips readiness rather than passing.

**FIPS deployment profile:**

1. **Crypto provider**: run on a FIPS-validated OpenSSL 3 (FIPS-enabled base image,
   e.g. Red Hat UBI in FIPS mode) and set `BROKER_FIPS_MODE=true`.
2. **Signing keys**: the `pkcs11` keystore on a FIPS 140-2/3 validated HSM (private
   key never leaves the module) or a cloud KMS against a FIPS endpoint.
3. **Credentials at rest**: `vault-transit` with Vault's FIPS variant, or the
   default AES-256-GCM under the FIPS-mode provider from step 1.
4. **Out of scope for the app**: TLS termination, OS entropy, and the CMVP
   certificate paperwork. The broker's part is refusing to run non-compliantly
   while you claim otherwise.

## Supply chain

CI gates every deploy behind supply-chain checks (see [SECURITY.md](SECURITY.md)):
`pip-audit` over resolved production dependencies (blocking), `bandit` SAST
(medium+ fails), `gitleaks` secret detection over full history, and a CycloneDX
SBOM artifact per deploy. Image signing (cosign) is tracked in
[ROADMAP.md](ROADMAP.md), unclaimed until images are published to a registry.

## Token shape

```json
{
  "iss": "https://broker.example.com",
  "sub": "agent:5f0c...",            // stable agent id
  "client_id": "aib_x9k2...",
  "owner": "owner@example.com",       // owning human principal
  "tenant": "default",
  "scope": "ha:read gitlab:api",
  "aud": "agent-iam",
  "iat": 1751800000,
  "exp": 1751800300,
  "jti": "..."
}
```

The `owner` claim deliberately exposes the owning human's email (PII) to every
downstream service — that visibility *is* the delegation audit trail. Deployments
that must not leak owner identity downstream should use opaque principal
identifiers as owner emails.
