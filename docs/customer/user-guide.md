# Cipherlatch User Guide

**For agent owners.** You own one or more AI agents. This guide shows you how to
register an agent, give it a real identity, let it mint tokens, and — when needed
— let it reach downstream systems without ever holding a long-lived secret.

If you operate the broker itself (deploy, configure, rotate keys), see the
[Administrator Guide](admin-guide.md).

---

## 1. Concepts in 60 seconds

- **Agent** — a non-human principal (a script, an MCP server, an autonomous
  worker). You own it. It has a `client_id` (`aib_…`) and, usually, a
  `client_secret` (`aibs_…`).
- **Scope** — a capability label (`orders:read`, `orders:write`) you grant the
  agent. The agent can only mint tokens for scopes it was granted.
- **Token** — a short-lived (default 5-minute) ES256-signed JWT the agent mints by
  presenting its credentials. Downstream services verify it offline.
- **Owner claim** — every token carries who owns the agent, so the human behind an
  action is always identifiable.
- **You see only your own agents.** Other people's agents are invisible to you
  (they return 404). Admins see everything.

---

## 2. Register an agent

Two ways: the Web UI (sign in at the broker URL and use **Agents → New**) or the
API. Via API you need either the admin key (usually your platform team runs this
for you) or your own session.

```bash
curl -s -X POST $Cipherlatch/v1/agents \
  -H "X-Admin-Key: $BROKER_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "orders-sync", "owner_email": "you@example.com",
       "allowed_scopes": ["orders:read", "orders:write"]}'
```

The response includes the **`client_secret` exactly once**. Store it in your
secret manager immediately — Cipherlatch keeps only a digest and cannot show it again. If
you lose it, rotate the agent to get a new one.

---

## 3. Mint a token (client credentials)

Standard OAuth 2.1 client-credentials. Your agent does this itself, at runtime,
whenever it needs a fresh token:

```bash
curl -s -X POST $Cipherlatch/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=aib_... -d client_secret=aibs_... \
  -d scope="orders:read"
```

You get back a JWT with `expires_in` (default 300s). Mint on demand and let it
expire — don't cache it long. To pin the token to a specific downstream service,
add `-d resource=https://orders.example.com` (RFC 8707): the token's audience is
bound to that service and cannot be replayed against another.

**Downstream verification** needs no call back to Cipherlatch — the service fetches
`$Cipherlatch/.well-known/jwks.json` once, caches it, and verifies the signature and
claims offline.

---

## 4. Stronger authentication (recommended for production agents)

You don't have to use a shared secret. Two upgrades:

- **`private_key_jwt`** — the agent signs a client assertion with its own private
  key; Cipherlatch holds only the public key. No shared secret to leak.
- **DPoP** — the agent proves possession of its key on every token use. A stolen
  token is useless to anyone without the private key. DPoP is enforced at the
  gateway.

Ask your platform team which is required for your environment.

---

## 5. Reaching downstream systems

You often want your agent to call some API that needs its *own* secret. Three
patterns, from least to most locked-down. Pick based on how much you want the
agent to never touch the raw secret.

### 5.1 Credential exchange (RFC 8693)

Your admin stores the downstream secret in Cipherlatch, encrypted and **write-only**, and
grants your agent access to it. At runtime the agent exchanges its Cipherlatch token for
the secret:

```bash
curl -s -X POST $Cipherlatch/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=aib_... -d client_secret=aibs_... \
  -d subject_token=$CIPHERLATCH_JWT \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=orders-api-token
```

The agent receives the secret only at the moment of use and never has it at rest
in its own config.

### 5.2 Enforcing gateway (agent never holds the secret at all)

Better: your admin defines a **route** (`/gw/<slug>`) bound to an upstream + a
stored credential + a policy (allowed methods/paths, per-agent rate limit and
daily quota). Your agent calls *through* Cipherlatch with only its Cipherlatch token — Cipherlatch
injects the real credential server-side and proxies the request:

```bash
curl -H "Authorization: Bearer $CIPHERLATCH_JWT" \
  $Cipherlatch/gw/orders-api/v1/orders
```

The agent never sees the upstream secret and cannot escape the route's allowed
methods/paths. Every transaction is audited.

### 5.3 Dynamic credentials (nothing stored, minted per use)

For SSH, the `ssh-ca` provider mints a **short-lived, scoped OpenSSH certificate**
at exchange time. Your agent generates its own keypair and submits the *public*
key; Cipherlatch returns a certificate valid for minutes:

```bash
# exchange your public key for a cert
curl -s -X POST $Cipherlatch/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=aib_... -d client_secret=aibs_... \
  -d subject_token=$CIPHERLATCH_JWT \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=ssh-prod \
  --data-urlencode requested_token_type=urn:cipherlatch:params:oauth:token-type:ssh-certificate \
  --data-urlencode "public_key=$(cat id_ed25519.pub)"
# then:
ssh -i id_ed25519 -o CertificateFile=<cert> user@host
```

The host holds no standing key for your agent — it trusts the CA. When the cert
expires (minutes later), access is gone with no revocation step.

---

## 6. Secretless agents (SPIFFE / OIDC federation)

If your agent already runs somewhere with a platform identity — a Kubernetes
service account, a SPIFFE workload, a CI job — it can authenticate to Cipherlatch with
that platform-issued JWT and **Cipherlatch never issues it a secret at all**. Your admin
binds the agent to a `federated_issuer` + `federated_subject` and allowlists the
issuer. Your agent then presents its workload JWT as a `client_assertion` instead
of a client secret. Nothing to store, nothing to rotate.

---

## 7. Managing your agent

| I want to… | Do this |
|---|---|
| See my agents | Web UI **Agents**, or `GET /v1/agents` (yours only) |
| Change scopes / name | Web UI edit, or `PATCH /v1/agents/{id}` |
| Get a new secret | Rotate the agent (invalidates the old secret) |
| Kill all outstanding tokens now | `POST /v1/agents/{id}/revoke-tokens` |
| Revoke a single token | `POST /oauth/revoke` |
| See what my agent did | Ask your admin/auditor for the audit trail — every action is logged with actor and IP |

---

Your agents don't need you online: they authenticate with their own
credentials and keep minting tokens while you're away. Only *changes* —
scopes, rotation, grants — need you, or a teammate holding a coverage role
with `:all` permissions (ask your admin).

## 8. Good habits

- **Mint short, mint often.** Don't stash tokens; let them expire.
- **Never put a downstream secret in your agent's config** — use the gateway
  (§ 5.2) or dynamic credentials (§ 5.3) so the secret stays server-side.
- **Request the narrowest scope** the task needs, and use `resource` to bind the
  token to exactly the service it's for.
- **Rotate on any suspicion.** Rotation gives a new secret and clears any lockout.
- **Prefer `private_key_jwt` / DPoP / federation** over shared secrets for
  anything long-lived.

---

## 9. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `invalid_client` | Wrong `client_id`/`client_secret`, or the agent was rotated. |
| `invalid_scope` | You requested a scope the agent wasn't granted. |
| Locked out after several failures | Token-endpoint lockout tripped; wait the window out or rotate the agent to clear it. |
| `404` on another agent | Working as designed — you can only see your own agents. |
| Downstream rejects the token | Check the token's `aud` matches the service (use `resource=`), and that the service is fetching current JWKS. |
| Gateway `403` on a path | The route policy doesn't allow that method/path. |
| Token works but calls fail after minutes | Token expired — mint a fresh one. |
