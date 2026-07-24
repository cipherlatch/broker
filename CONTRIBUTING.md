# Contributing to Cipherlatch

Thanks for your interest in improving Cipherlatch. This guide covers how to get
set up, what we expect in a change, and the one legal step contributions require.

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                       # the suite should be green before you start
uvicorn app.main:app --reload
```

See [README.md](README.md) for a fuller local walkthrough and
[ARCHITECTURE.md](ARCHITECTURE.md) for the architecture.

## Submitting a change

- **Keep pull requests small and focused** — one concern per PR is far easier to
  review than a sweeping change.
- **Add or update tests.** Cipherlatch is security infrastructure; behavior
  changes need coverage. `pytest` must pass, and the security gates
  (`pip-audit`, `bandit -r app -ll`, `gitleaks`) run in CI.
- **Match the surrounding style** — the codebase is plain, dependency-light
  Python; follow the conventions already in the file you're editing.
- **Describe the "why."** Explain the problem the change solves, not just the
  diff.

## Reporting security issues

**Do not open a public issue for a vulnerability.** Follow the private
disclosure process in [SECURITY.md](SECURITY.md) — email
`security@cipherlatch.com`.

## Contributor License Agreement (required)

Cipherlatch is dual-licensed (AGPL-3.0 plus a commercial license — see
[COMMERCIAL.md](COMMERCIAL.md)). To keep that possible, every contributor must
agree to the [Contributor License Agreement](CLA.md) before their change can be
merged. It's a lightweight sign-off; you retain copyright to your work and grant
the project the rights it needs to license the whole under both terms.

## A note on this repository

This repo is the public home of the AGPL core. Development happens against an
internal pipeline as well, so accepted changes may land as squashed or
maintainer-authored commits rather than a direct fast-forward of your branch —
your contribution and authorship are preserved in the merge.
