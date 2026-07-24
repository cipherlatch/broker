# Cipherlatch Documentation

Customer-facing documentation for the **Broker for Agentic Access Management** —
a self-hostable service that gives AI agents a real, human-owned identity.

## Guides

| Doc | Audience | Purpose |
|---|---|---|
| [Administrator Guide](admin-guide.md) | Platform / SRE / security admins | Deploy, configure, and operate Cipherlatch. |
| [User Guide](user-guide.md) | Agent owners | Register agents, mint tokens, reach downstream systems safely. |

## Positioning

| Doc | Audience | Purpose |
|---|---|---|
| [Technical Marketing Brief](technical-marketing.md) | Evaluators / buyers / technical decision-makers | Problem, positioning, differentiators, use cases, buyer FAQ. |

## Compliance & operations

| Doc | Audience | Purpose |
|---|---|---|
| [NIST 800-53 Mapping](nist-800-53-mapping.md) | Assessors / control authors | The subset of SP 800-53 Rev 5 controls Cipherlatch supports, with deployment-dependency notes. |
| [Operations FAQ](operations-faq.md) | Everyone | The questions teams ask when adopting and running Cipherlatch, answered. |

## Deeper references

- `README.md` — feature summary and quick start.
- `ARCHITECTURE.md` — how it works: full architecture and standards alignment.
- `ROADMAP.md` — what's next.
- `DECISIONS.md` — why it's built this way, plus build history.
- `SECURITY.md` — security policy and hardening guide.
- `COMMERCIAL.md` — licensing and paid support.

---

### A recurring theme: deployment dependence

Several of Cipherlatch's strongest security properties are **deployment** properties, not
code properties — FIPS validation, non-exportable signing keys, no plaintext key
material on the host, transport security, and authoritative off-boarding all depend
on which backends and edge you wire in. Every guide flags these
**[Deployment-dependent]**, and the
[Admin Guide Appendix A](admin-guide.md#appendix-a--deployment-dependent-decisions-collected)
collects them in one table. Record your deployment's choices there.
