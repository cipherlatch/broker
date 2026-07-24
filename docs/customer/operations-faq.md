# Cipherlatch — Operations FAQ

The questions teams ask when adopting and running Cipherlatch — from engineering teams
onboarding agents, security reviewers, auditors, platform/SRE, and leadership —
with the answers. Where an answer depends on **how Cipherlatch is deployed**, that is
called out; substitute your environment's choices from the
[Admin Guide](admin-guide.md) Appendix A.

---

## For teams onboarding agents

**Q: How do I get an agent onto Cipherlatch?**
Provide the agent's name, the owning human's email, and the scopes it needs. Your
platform team registers it and hands you the `client_secret` once (put it straight
in your secret manager). Better still, if your agent runs in Kubernetes/CI/SPIFFE,
request a *federated* agent — no secret at all. See the [User Guide](user-guide.md).

**Q: My agent needs to call an internal API. Do I get that API's key?**
No, and that's the point. The credential is stored in Cipherlatch and your agent either
(a) exchanges its token for it at use time, or (b) — preferred — calls *through* a
gateway route so it never touches the secret. Provide the upstream, the allowed
methods/paths, and a rate/quota, and the route is wired.

**Q: How long do tokens last?**
Five minutes by default (ceiling 15). Mint on demand; don't cache. This is
intentional — short tokens are the main reason a leak isn't a catastrophe.

**Q: Downstream service — how does it verify tokens?**
It fetches the JWKS URL once and verifies offline. Any JWT library, any language,
no SDK, no call back on every request. For MCP servers, point the server's RFC
9728 protected-resource-metadata at Cipherlatch as the authorization server.

**Q: What if my agent's secret leaks?**
Rotate it — old secret dead immediately, lockout cleared. If tokens may already be
out, mass-revoke the agent's outstanding tokens too. With DPoP on, a token grabbed
without the private key was never usable.

---

**Q: A colleague is on vacation — can I manage their agents? Do they stop?**
The agents never stop: they authenticate with their own credentials, and the
owner's presence is only needed for *changes*. To manage a colleague's agents
you need a role carrying the `:all` permission variants (or an admin does
it) — plain users cannot even see each other's agents (404 by design). Off-
boarding is different: deleting a user permanently revokes every agent they
own, so move production agents to a service-owner account first.

## For security reviewers

**Q: `/oauth/token` is unauthenticated. Isn't that a hole?**
It's how OAuth client-credentials works — the client authenticates *by* posting
its secret. Cipherlatch defends it with per-`client_id` lockout on repeated failures and
a per-IP rate limit. **[Deployment-dependent]** Volumetric DoS protection is the
edge's job; front internet-facing deployments with a reverse proxy / WAF and don't
rely on the app's per-IP limit alone at the edge.

**Q: Where does the signing key live? Can it be exfiltrated?**
**[Deployment-dependent].** With the `pkcs11` HSM or a cloud-KMS keystore
(Cipherlatch Enterprise) the
private key never leaves the module — Cipherlatch asks it to sign. With the `file`
keystore the key is on disk (fine for single-node/evaluation, not for a
key-non-exportability claim). State which one your deployment uses.

**Q: How are downstream credentials stored?**
Encrypted with AES-256-GCM, write-only (they can't be displayed back). The
encryption KEK is either on the host (`local`) or — **[deployment-dependent]** — in
Vault Transit (`vault-transit`), where it never touches the app host. Regulated
deployments should use `vault-transit`.

**Q: Is it FIPS compliant?**
The algorithms are all FIPS-approved (ES256, AES-256-GCM, HMAC-SHA256, SHA-256).
*FIPS 140-3 compliance* additionally needs a CMVP-validated module.
**[Deployment-dependent]:** a FIPS deployment runs a FIPS-validated OpenSSL base
image plus an HSM/FIPS-KMS keystore and sets `BROKER_FIPS_MODE=true`, which makes
the broker **refuse to boot** if the provider isn't actually in FIPS mode — so it
can't silently drift out of compliance. TLS, OS entropy, and the CMVP paperwork
are outside the app.

**Q: Can one user see or touch another user's agents?**
No. Non-owned agents return 404 (not 403 — existence doesn't leak). Admins see
everything; the audit trail records who did what.

**Q: Can an agent escalate its own privileges?**
No. Agents can only mint tokens for scopes they were granted, can only hit gateway
routes/paths on their policy, and are subject to per-agent rate and daily quota.
Optionally every gateway request is also checked against an external OPA/Cedar
policy that fails closed.

**Q: What stops a stolen token being replayed against a different service?**
Audience binding (RFC 8707) — a token minted with `resource=serviceA` won't
validate at serviceB, and MCP servers must reject tokens not bound to them. DPoP
additionally binds the token to the agent's key.

**Q: Supply-chain assurance?**
Every change runs dependency vulnerability scanning (blocking on known CVEs), SAST,
and secret detection; each deploy emits a CycloneDX SBOM. Policy is in
`SECURITY.md`.

---

## For auditors / compliance

**Q: What does the audit trail cover, and can it be tampered with?**
Every issuance, denial, login, token exchange, gateway transaction, and lifecycle
change — with actor and IP. The database trail is always complete; the SIEM mirror
can mask PII but never thins the DB record. **[Deployment-dependent]**
tamper-evidence and retention come from where you ship the mirror (WORM/SIEM);
Cipherlatch generates the records, your logging stack preserves them.

**Q: Can you prove which human is behind an agent action?**
Yes — every agent is owned by a named human and that owner rides in every token
and audit record. That's the non-repudiation property (maps to AU-3 / IA-9).

**Q: Which NIST 800-53 controls does this support?**
See [nist-800-53-mapping.md](nist-800-53-mapping.md). Short version: Cipherlatch directly
implements the agent-facing IA/AC/AU technical controls and the cryptographic SC
controls; strong-assurance variants (FIPS validation, non-exportable keys,
transport, authoritative provisioning) are deployment-dependent and listed there.

**Q: How do people get off-boarded?**
**[Deployment-dependent]** on whether SCIM is wired. With SCIM, deactivating a
user in the IdP suspends every agent they own automatically (new mints *and*
outstanding tokens), and deletion revokes them. Without SCIM, soft-delete the user
in Cipherlatch, which revokes their agents. Role changes can also be driven from IdP
groups so authority stays in the directory.

---

## For platform / SRE

**Q: Is it stateless? Can we run multiple replicas?**
Yes — cookie sessions, DB-backed lockout, `/readyz`, advisory-locked self-applying
migrations. **[Deployment-dependent]:** more than one replica requires a shared
signing key (Vault or cloud KMS) and PostgreSQL; the Helm chart refuses to render
multi-replica on the `file` keystore.

**Q: How do upgrades work?**
Deploy the new image; Alembic applies migrations under an advisory lock, so rolling
multi-replica deploys are safe.

**Q: How do we manage it as code (IaC)?**
Yes — Cipherlatch is Infrastructure-as-Code friendly. Idempotent natural-key upserts
and a declarative `POST /v1/apply` (`dry_run` check
mode). Drive it from your config-management tooling against the machine admin key —
agents, users, roles, routes all version-controlled.

**Q: What do we monitor?**
Prometheus `/metrics` (audit-event counters, HTTP latency), `/readyz` for readiness
(gated on keystore/FIPS state so a regression flips readiness), and the JSON audit
mirror into the SIEM.

**Q: What's the key-rotation story?**
`POST /v1/keys/rotate` mints a new key while retired keys stay in JWKS through a
retention window, so in-flight tokens keep verifying and verifiers need no
coordination. Named keyrings rotate independently (and per-tenant) to keep blast
radius small. Auto-rotation by key age is available.

---

**Q: Do UI logins survive a load balancer / multiple replicas?**
Yes. The session cookie is a stateless signed cookie (HMAC-SHA256) carrying
only the user id; every request re-reads the user's state from the shared
database. Any replica honors a login minted by any other — provided all
replicas share one `BROKER_SESSION_SECRET`. Disabling, demoting, or deleting
a user takes effect on every node at that user's next request.

**Q: Two admins are working at the same time — can they corrupt each other?**
No. Conflicting edits are last-write-wins with *both* writes audited under
their real actors; acting on something another admin just deleted is a clean
404; and guards such as the last-admin check evaluate fresh database state,
so two admins cannot race the broker down to zero admins.

**Q: We're locked out — IdP down, last admin disabled. Now what?**
From a shell on the broker host: `python -m app.admin promote you@example.com`
(via `docker exec` / `kubectl exec`). Idempotent — it creates, reactivates,
restores, or promotes as needed — and audited as `admin-cli`. Works even if
`BROKER_ADMIN_API_KEY` was never configured.

## For leadership / procurement

**Q: What does Cipherlatch actually buy us?**
It replaces long-lived agent API keys with short-lived, signed, owner-attributed
tokens, and keeps downstream secrets out of agents entirely. That turns "an agent
leaked its key" from an incident into a non-event, and gives a provable audit trail
of which human is behind every agent action.

**Q: Does it replace our IdP (Okta/Entra/etc.)?**
No — it uses your IdP for human login and adds the agent-identity layer your IdP
was never built for.

**Q: Are we locked in?**
No. Self-hosted, AGPL-licensed, backend-agnostic (your PostgreSQL, your Vault/KMS,
your IdP), no phone-home. A commercial license exists if you ever need
closed-source embedding.

**Q: Is the standard it's built on stable?**
The foundations (OAuth, OIDC, SCIM, SPIFFE) are mature. The agent-specific guidance
(NIST NCCoE/CAISI/COSAiS, IETF WIMSE) is new and moving; Cipherlatch tracks it
deliberately and is built to slot into the forthcoming reference architectures
rather than diverge.

---

## The short version

> Cipherlatch gives each AI agent a real, human-owned identity that mints short-lived
> signed tokens, brokers or proxies downstream secrets so agents never hold them,
> and audits every action with actor and IP. Its strongest security properties —
> FIPS, non-exportable keys, no plaintext key on the host, transport security,
> authoritative off-boarding — are **turned on by how you deploy it**, and your
> deployment's choices should be recorded in Admin Guide Appendix A.
