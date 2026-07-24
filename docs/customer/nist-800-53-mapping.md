# Cipherlatch — NIST SP 800-53 Rev 5 Control Mapping

**Scope.** This document maps Cipherlatch's capabilities to the subset of NIST SP 800-53
Rev 5 controls it *supports* — i.e. where the tool provides, or materially
contributes to, a control's implementation. It is a **design alignment aid for
control authors and assessors**, not a certification or an ATO. Cipherlatch is one
component in a system; most controls are satisfied jointly by Cipherlatch, your
surrounding infrastructure, and your organizational controls.

**How to read the "Responsibility" column:**

- **Cipherlatch** — the tool implements the technical mechanism directly.
- **Shared** — Cipherlatch provides the mechanism; full satisfaction also requires
  organizational policy, procedure, or another system component.
- **Deployment** — whether the control is met depends on *how you deploy* Cipherlatch
  (which keystore/KEK/IdP/edge you wire in). These are called out explicitly — do
  not assume them from the app alone.

**Relationship to 800-63.** Cipherlatch applies SP 800-63 (rev 4) *human* digital-
identity principles to agents as non-person entities (NPE). Where 800-53 IA
controls reference authenticator strength, throttling, and federation, the
underlying design follows 800-63B/63C. See ARCHITECTURE.md § NIST alignment.

---

## Access Control (AC)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **AC-2 Account Management** | Full lifecycle for two account types: human users (OIDC, manual or JIT provisioning) and agents (register/modify/rotate/disable/delete). SCIM 2.0 push for create/update/deactivate/delete; deactivating a user suspends all their agents, deleting revokes them. Last-admin guard prevents removing the final admin. All lifecycle events audited. | Shared (with your IdP) |
| **AC-3 Access Enforcement** | Configurable RBAC (roles = permission sets, own-scoped vs `:all`); agents constrained to granted scopes; the enforcing gateway is a policy enforcement point that constrains method/path per route. | Cipherlatch |
| **AC-4 Information Flow Enforcement** | Gateway routes bind an agent to a specific upstream and allowlist of methods/paths; the agent cannot escape the route. Optional external OPA/Cedar per-request evaluation (fail-closed). | Cipherlatch (partial) |
| **AC-6 Least Privilege** | Narrow scopes; per-agent resource (audience) allowlist; per-route method/path policy; per-agent rate limit and daily quota; own-scoped roles so users touch only their own agents. | Cipherlatch |
| **AC-7 Unsuccessful Logon Attempts** | Token-endpoint lockout (800-63B-style): consecutive failures lock a `client_id` for a configurable window; rotation clears it. | Cipherlatch |
| **AC-12 Session Termination** | Short token TTL (default 300s, ceiling 900s); per-token revocation (RFC 7009); per-agent mass token revocation; human session max-age. | Cipherlatch |
| **AC-17 / AC-18 Remote Access** | Tokens are audience-bound (RFC 8707) and can be key-bound (DPoP) so remote use is constrained; transport confidentiality is the edge's job. | Deployment (TLS at proxy/ingress) |

---

## Audit & Accountability (AU)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **AU-2 Event Logging** | Every issuance, denial, login, token exchange, gateway transaction, and lifecycle change is an audit event. | Cipherlatch |
| **AU-3 Content of Audit Records** | Records carry actor, client IP, timestamp, event type, and outcome. The `owner` claim ties every agent action to a named human (non-repudiation). | Cipherlatch |
| **AU-6 Audit Review / Analysis / Reporting** | `GET /v1/audit` (admin/auditor role); audit stream mirrored to stdout in JSON for SIEM ingestion. | Shared (with your SIEM) |
| **AU-9 Protection of Audit Information** | The database audit trail is always complete; log-mirror PII masking (`hash`/`redact`) applies only to the SIEM mirror, never thinning the DB record. | Shared (DB access controls are yours) |
| **AU-12 Audit Record Generation** | Generation is built into every privileged code path, not opt-in. | Cipherlatch |

> **[Deployment]** Long-term audit retention, tamper-evident WORM storage, and
> time synchronization (AU-8) are provided by your logging/SIEM stack, not Cipherlatch.

---

## Identification & Authentication (IA)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **IA-2 Identification & Authentication (Users)** | Human admins authenticate via OIDC to your IdP; a separate machine admin key exists for automation/break-glass. | Deployment (your IdP satisfies MFA/AAL) |
| **IA-4 Identifier Management** | Each agent has a unique `client_id` bound to an owning human; identifiers are managed through lifecycle and never reused silently. | Cipherlatch |
| **IA-5 Authenticator Management** | Agent secrets are 256-bit random, stored only as SHA-256 digests, rotatable, and revocable — following SP 800-63B. Failed-attempt throttling implemented. | Cipherlatch |
| **IA-5(2) PKI-Based Authentication** | `private_key_jwt` (RFC 7523) — signed client assertion, no shared secret; Cipherlatch holds only the public key. | Cipherlatch |
| **IA-8 Identification & Authentication (Non-Org Users)** | SPIFFE/OIDC workload federation: agents bootstrap from a platform-issued JWT (K8s SA, SPIFFE SVID, CI job token) against an issuer allowlist — no Cipherlatch secret issued. | Shared (with your workload-identity platform) |
| **IA-9 Service Identification & Authentication** | **The core control.** Agents/services are authenticated as first-class principals with signed, short-lived, audience-bound tokens verifiable offline (JWKS). DPoP (RFC 9449) adds proof-of-possession. | Cipherlatch |
| **IA-12 Identity Proofing** | Partial/inherited: agent trust derives from the owning human (proofed by your IdP) or from workload attestation (federation). Cipherlatch does not itself proof identity. | Deployment |

---

## System & Communications Protection (SC)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **SC-8 Transmission Confidentiality & Integrity** | Tokens are signed (integrity in transit); confidentiality of the channel is TLS at the edge. | Deployment (reverse proxy/ingress) |
| **SC-12 Cryptographic Key Establishment & Management** | Pluggable keystore (file/Vault/cloud KMS/PKCS#11 HSM); key rotation with JWKS retention window; independent per-tenant keyrings to isolate rotation blast radius. | Shared / Deployment (custody = backend choice) |
| **SC-13 Cryptographic Protection** | FIPS-approved primitives throughout: ES256 (FIPS 186-5), AES-256-GCM (SP 800-38D), HMAC-SHA256, SHA-256. `BROKER_FIPS_MODE=true` refuses to boot unless OpenSSL is in FIPS mode. | Cipherlatch (FIPS *validation* is Deployment) |
| **SC-17 PKI Certificates** | `ssh-ca` dynamic provider mints short-lived scoped OpenSSH certificates at exchange time; hosts trust the CA and hold no standing agent key. | Cipherlatch |
| **SC-23 Session Authenticity** | Signed JWTs with `jti` (replay scoping), issuer/subject/audience binding; DPoP key-binding defeats stolen-token replay. | Cipherlatch |
| **SC-28 Protection of Information at Rest** | Downstream credentials stored write-only, encrypted with AES-256-GCM; the credential-encryption KEK can live in Vault Transit (`vault-transit` backend) and never touch the app host. | Shared / Deployment (KEK location) |

---

## Configuration Management (CM)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **CM-2 / CM-3 Baseline & Change Control** | Declarative, idempotent IaC API (`PUT …/by-name/…`, `POST /v1/apply` with `dry_run`); drive Cipherlatch from your config-management tooling so its config is version-controlled and reviewable. | Shared |
| **CM-6 Configuration Settings** | All settings are explicit `BROKER_*` env vars with documented secure defaults (e.g. `DB_AUTO_CREATE=false` in prod, gateway policy fail-closed). | Shared |
| **CM-7 Least Functionality** | Minimal dependency surface; the `ssh-ca` provider adds zero new dependencies; UI is dependency-free server-rendered. | Cipherlatch |

---

## Supply Chain & System Integrity (SR / SA / SI)

| Control | What Cipherlatch provides | Responsibility |
|---|---|---|
| **SR-3 / SR-4 Supply Chain Controls & Provenance** | CI emits a CycloneDX SBOM per deploy; secret-detection blocks credential leakage into the artifact. | Cipherlatch |
| **SA-11 / SA-15 Developer Testing & Secure Process** | Dependency vulnerability scanning (blocking on known CVEs), SAST, full test suite gate on every change. | Cipherlatch |
| **SI-7 Software, Firmware & Information Integrity** | SBOM + scanned dependency posture support downstream integrity verification. | Shared |

---

## Controls Cipherlatch does **not** claim

Be explicit with assessors about the boundary. Cipherlatch does *not* by itself satisfy:

- **AU-8 (time stamps / time sync)**, **AU-11 (retention)** — your logging stack.
- **IA-2 MFA/AAL enforcement** — your IdP.
- **SC-7 (boundary protection)**, **AC-17 transport** — your reverse
  proxy/ingress/network.
- **CP (contingency), IR (incident response), PE (physical), PS (personnel), RA
  (risk assessment)** families — organizational, outside the tool's scope.
- **Formal FIPS 140-3 validation** — Cipherlatch uses FIPS-approved algorithms and can
  enforce FIPS-mode boot, but the *validated module* (HSM / FIPS OpenSSL) and the
  CMVP certificate are deployment artifacts.

---

## Deployment-dependent control summary

| Control | Met only if you deploy… |
|---|---|
| SC-8 / AC-17 (transport) | TLS terminated at a proxy/ingress you control |
| SC-13 (FIPS validation) | on a FIPS-validated OpenSSL and/or PKCS#11 HSM, with `BROKER_FIPS_MODE=true` |
| SC-12 (key non-exportability) | with the `pkcs11` HSM or a cloud-KMS keystore (Cipherlatch Enterprise; not `file`) |
| SC-28 (no plaintext KEK on host) | with the `vault-transit` credential backend |
| IA-2 (MFA / AAL2+) | with an IdP that enforces it |
| AU-9 / AU-11 (audit protection & retention) | shipping the audit mirror to WORM/SIEM storage |
| AC-2 (authoritative lifecycle) | with SCIM wired from your IdP |

> **Bottom line for assessors:** Cipherlatch directly implements the agent-facing IA, AC,
> and AU technical controls (IA-4/5/9, AC-2/3/6/7/12, AU-2/3/12) and the
> cryptographic mechanisms (SC-13/17/23/28). Whether the *strong-assurance*
> variants — FIPS validation, non-exportable keys, transport confidentiality,
> authoritative account provisioning — are satisfied is a function of the
> deployment choices in the table above, each of which Cipherlatch is built to support.
