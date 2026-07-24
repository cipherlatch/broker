# Cipherlatch — Technical Marketing Brief

**Give your AI agents a real identity — and take back control of what they can do.**

---

## The problem

Every team shipping AI agents has quietly recreated the worst identity practices
of the last decade. Agents authenticate with long-lived API keys pasted into
config files and env vars. Those keys carry broad, standing privilege. Nobody can
say which *human* is behind an agent's action. When an agent is compromised, there
is no clean revocation and no audit trail that names an actor. Agents are now
first-class actors in production systems — and they have worse identity hygiene
than the interns.

The emerging standards bodies agree this is the gap. NIST's NCCoE concept paper
(Feb 2026) treats a bare OAuth `client_id` as a *registration artifact with no
attestation binding*; the CAISI initiative names identification, authorization,
auditing, and non-repudiation of agents as the open problem. The direction is
settled: **compose existing standards** into agent identity rather than invent new
ones.

Cipherlatch is that composition, shipping today.

---

## What Cipherlatch is

A **Broker for Agentic Access Management**: a lightweight, self-hostable service
that makes every AI agent a first-class principal **owned by a human**, granted
explicit scopes, and able to mint **short-lived, signed, audience-bound tokens**
that any downstream service verifies offline with nothing but a JWKS URL.

Then it goes further than a token minter:

- **Broker credentials** so an agent can reach downstream systems it should never
  hold the secret for.
- **Enforce access** at a built-in gateway that injects the real credential
  server-side and constrains what the agent can call.
- **Issue no secret at all** when agents bootstrap from workload identity (SPIFFE,
  Kubernetes, CI).
- **Audit everything** with actor and IP — every issuance, denial, login, and
  lifecycle change.

---

## Why it's different

| Most approaches | Cipherlatch |
|---|---|
| Long-lived API keys in config | 5-minute signed tokens, minted on demand |
| Agent identity = anonymous key | Agent owned by a named human; owner claim in every token |
| Secret lives in the agent | Gateway injects it server-side; agent never holds it |
| Revocation = rotate everything, hope | Per-token revoke, per-agent mass-revoke, SCIM off-board |
| "Trust the network" | Zero-Trust: Cipherlatch is the PDP; the gateway is the PEP |
| Roll-your-own | Every mechanism is a named RFC / NIST application |
| Stolen token = full access | DPoP proof-of-possession — useless without the key |
| Opaque | Full audit trail, Prometheus metrics, SIEM mirror |

**Standards-first, not standards-shaped.** OAuth 2.1, RFC 8707 (resource
indicators), RFC 8693 (token exchange), RFC 9449 (DPoP), RFC 7009/7662
(revoke/introspect), RFC 7523 (private_key_jwt), SCIM 2.0, SPIFFE/OIDC federation
— each is an *implemented* application, with gaps tracked as roadmap, not papered
over. Cipherlatch is designed to serve as the **authorization server for MCP** under the
MCP authorization spec (rev 2025-11-25).

---

## What you can build with it

- **MCP authorization server** — audience-bind tokens per MCP server so a token
  for one server can't be replayed against another (exactly what the MCP spec
  mandates).
- **Agent → internal API broker** — let an agent call an internal service or SaaS
  through a policy-constrained gateway without ever seeing the upstream
  credential.
- **Just-in-time SSH for agents** — agents mint minutes-long, scoped OpenSSH
  certificates; target hosts hold no standing agent key.
- **Secretless CI/Kubernetes agents** — workloads authenticate with their platform
  JWT; no broker secret is ever issued.
- **Regulated / FIPS environments** — sign inside an HSM, wrap credential keys in
  Vault Transit, and boot-fail if the crypto provider isn't FIPS-validated.

---

## Security posture at a glance

- **Cryptography:** ES256 signatures (FIPS 186-5), AES-256-GCM credentials at rest
  (SP 800-38D), HMAC-SHA256 sessions, SHA-256 digests. All FIPS-approved
  primitives.
- **Key custody:** pluggable keystore — file, Vault, cloud KMS (key never leaves),
  or PKCS#11 HSM (signs inside the module).
- **Zero standing plaintext:** downstream secrets stored write-only; KEK can live
  in Vault Transit and never touch the app host.
- **Least privilege by construction:** scopes, per-route method/path policy,
  per-agent rate + daily quota, optional external OPA/Cedar evaluation
  (fail-closed).
- **Non-repudiation:** append-only audit trail with actor and IP, mirrored to your
  SIEM.
- **Supply chain:** dependency scanning + SAST + secret detection gate CI; a
  CycloneDX SBOM ships with every deploy.

> Several of these are **deployment properties** — a FIPS 140-3 claim, "key never
> exportable," or "no plaintext key on the host" depend on choosing the
> HSM/KMS/Vault backends. Cipherlatch makes them *achievable and enforceable* (e.g.
> `BROKER_FIPS_MODE=true` refuses to boot on a non-validated provider); it doesn't
> grant them by default. The [Admin Guide](admin-guide.md) spells out each case.

---

## Deploys where you already are

One stateless FastAPI service plus a database and a signing key. Run it as a
single container, as N replicas behind a load balancer, or on Kubernetes via the
Helm chart. Rolling multi-replica upgrades are safe (advisory-locked self-applying
migrations). Bring any OIDC IdP for human login. Drive the whole thing from your
configuration-management tooling via an idempotent, declarative-convergence API.

---

## Licensing

**AGPL-3.0** — self-host, modify, and redistribute freely. A **commercial license
and paid support** are available for closed-source embedding or running a modified
hosted service without publishing changes. See [COMMERCIAL.md](../../COMMERCIAL.md).

---

## Buyer / evaluator FAQ

**Is this a competitor to Okta / Auth0 / Entra?**
No — it's complementary. Those manage *human* identity and are your IdP. Cipherlatch
manages *agent* (non-person) identity and delegates human login to your existing
IdP over OIDC. Cipherlatch is the missing layer for the actors your IdP wasn't built for.

**Do downstream services have to integrate an SDK?**
No. They verify a standard JWT against a JWKS URL — any OAuth/JWT library, any
language. For the gateway pattern, they need no change at all; Cipherlatch speaks to them
with their existing credential.

**What happens when an agent is compromised?**
Revoke its outstanding tokens instantly, rotate its secret (which also clears any
lockout), or off-board the owning human via SCIM to suspend every agent they own.
With DPoP on, a token stolen without the key was never usable anyway.

**Can we prove who did what?**
Yes. Every action is audited with actor and IP, and the owner claim ties each
agent to a named human. The audit trail is append-only and can be mirrored to your
SIEM with tunable PII masking.

**Is it locked to a vendor cloud?**
No. It's self-hosted, AGPL, and backend-agnostic (your PostgreSQL, your Vault/KMS,
your IdP). No phone-home.

**How mature are the agent-identity standards it targets?**
The person-identity standards it builds on (OAuth, OIDC, SCIM, SPIFFE) are mature
and widely deployed. The *agent-specific* guidance (NIST NCCoE/CAISI/COSAiS, IETF
WIMSE) is new and moving — Cipherlatch tracks it explicitly and is positioned to slot
into the forthcoming reference architectures rather than diverge from them.
