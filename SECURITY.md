# Security Policy

Cipherlatch is an identity and access broker — it exists to hold and enforce other
systems' trust, so its own security posture is documented here plainly.

## Reporting a vulnerability

Email **security@cipherlatch.com** with a description, reproduction steps, and
impact. You will get an acknowledgment within 72 hours. Please do not open a
public issue for an unpatched vulnerability; coordinated disclosure is
appreciated and credited.

## Supported versions

The `main` branch is the supported release line. Fixes land on `main` and
deploy from there; there are no long-lived maintenance branches at this
stage of the project.

## What the broker protects, and how

| Asset | Protection |
|---|---|
| Token signing keys | Pluggable keystore: on-disk PEM (0600), Vault, JKS, PKCS#11 HSM, or AWS/GCP/Azure KMS — with the HSM/KMS backends the private key never enters broker memory. `kid`-based rotation with retention. |
| Downstream credentials | AES-256-GCM at rest (or Vault transit envelope encryption — KEK never on the host); write-only after creation; per-agent grants; served only via RFC 8693 exchange or injected server-side by the gateway. |
| Agent secrets | 256-bit random, stored as SHA-256 digests only; per-agent lockout (NIST 800-63B); stronger options: private_key_jwt (RFC 7523), DPoP (RFC 9449), or fully secretless SPIFFE/OIDC workload federation. |
| Sessions | Signed cookies (HMAC-SHA256), SameSite=lax + Origin checks (CSRF), OIDC login with PKCE. UI responses carry CSP (`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, and `Referrer-Policy`. |
| Token verification | Every JWT is decoded against a pinned algorithm allowlist (broker tokens ES256; external tokens the asymmetric set only — never `none` or an HMAC alg). DPoP proofs are single-use (per-`jti` replay rejection); a DPoP-bound token can't be presented at the gateway or exchanged without a fresh matching proof. |
| Tenant isolation | Every data path filters by the actor's single tenant; cross-tenant reads 404. Signing keyrings and gateway routes are tenant-scoped. |
| Audit | Append-only event log for every issuance, denial, and lifecycle change; mirrored to structured logs for SIEM shipping. |

## Supply chain

CI runs on every relevant change (see `.github/workflows/ci.yml`):

- **`dependency-scan`** — `pip-audit` over the resolved production
  dependency set (OSV/PyPI advisories). **Blocking**: a known CVE in a
  production dependency fails the pipeline and therefore blocks deploys.
- **`sast`** — `bandit` over `app/` failing on medium+ severity findings.
- **`secrets`** — `gitleaks` over the full git history.
- **`sbom`** — CycloneDX SBOM generated with `syft` and kept as a pipeline
  artifact for each deploy, so any later advisory can be matched against
  exactly what shipped.

Enterprise keystore backends and their SDKs ship in the separate
cipherlatch-enterprise package and are scanned in that repo.

**Image signing** is deliberately not claimed yet: the deployment model
builds the image on the deploy host (docker compose), so there is no
registry push to sign. When images are published to a registry, cosign
signing + verification lands in the same pipeline; treat any Cipherlatch image you
did not build yourself as untrusted until then.

## Hardening a deployment

- Put the broker behind TLS (reverse proxy or ingress); set `BROKER_ISSUER`
  to the public https URL.
- Set a high-entropy `BROKER_SESSION_SECRET` and `BROKER_CREDENTIAL_KEY`
  (the credential KEK is HKDF-derived, not password-hashed, so the key must
  carry its own entropy — the broker logs a warning at boot if it looks
  weak). In multi-replica deployments every replica must share the same
  `BROKER_SESSION_SECRET`, or logins will not survive the load balancer.
- Behind a reverse proxy, set `BROKER_TRUST_PROXY_HOPS` to the number of
  proxies you control that append to `X-Forwarded-For` (default 1). The
  broker reads the client IP as the Nth-from-right entry, so a client can't
  forge its source IP (for audit or rate limiting) by prepending values.
  Set `BROKER_TRUST_PROXY_IP=false` if the broker is reachable directly.
- Treat `BROKER_ADMIN_API_KEY` as a root credential: alert on the
  `admin_key.used` audit event (every use is recorded, reads included) and
  rotate without downtime via the comma-list form — add the new key,
  redeploy, move callers, remove the old. Or run without it entirely: leave
  it empty and the header path is disabled; recovery is then
  `python -m app.admin promote <email>` from a shell on the broker host,
  audited as `admin-cli`.
- Prefer Vault/KMS keystores and the vault-transit credential backend in
  anything beyond a single-node lab.
- Keep `/metrics` inside the network boundary (it is unauthenticated by
  design and exposes event counts).
- Rate limiting (`BROKER_RATE_LIMIT_PER_MINUTE`) and per-route gateway
  rate/quota limits are per-replica; add edge limits at the proxy for
  cluster-precise control.
- FIPS: all primitives are FIPS-approved (ES256, AES-256-GCM, HMAC-SHA256,
  SHA-256), but FIPS 140-3 *compliance* requires running them in a
  CMVP-validated module (FIPS-mode crypto library and/or PKCS#11 HSM) — a
  deployment property. Set `BROKER_FIPS_MODE=true` to enforce it: the
  broker refuses to start unless OpenSSL reports FIPS mode, and `/readyz`
  gates on it. See ARCHITECTURE.md § "FIPS deployment profile" for the full
  recipe.
