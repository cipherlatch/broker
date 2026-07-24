"""Dynamic credential providers: mint short-lived downstream material at
RFC 8693 exchange time instead of returning a stored static secret.

A provider-backed credential stores a *seed* (e.g. an SSH CA private key)
in the usual encrypted `secret_encrypted` column, plus a `provider` name and
`provider_config`. On exchange the provider mints scoped, short-lived
material for the requesting agent. Cipherlatch brokers the credential; it never
proxies the downstream protocol.

Providers are leaf modules registered by `kind`, imported lazily — the same
pattern as keystore and credential-encryption backends. Per-provider SDK
extras (none for ssh-ca) go in requirements-providers.txt, never the base
image.
"""

from dataclasses import dataclass
from typing import Protocol


class ProviderError(Exception):
    """Configuration or issuance failure. Message is safe to surface to the
    caller as an OAuth error_description."""


@dataclass
class Issued:
    secret: str          # material handed to the agent (cert, password, bundle)
    token_type: str      # RFC 8693 issued_token_type URN describing `secret`
    expires_in: int      # provider-chosen TTL, seconds (short)
    detail: dict         # non-sensitive fields for the audit record


@dataclass
class IssueContext:
    """Everything a provider needs, resolved and validated by the exchange
    path before the provider is called."""
    seed: str            # decrypted credential seed
    config: dict         # provider_config
    agent_id: str
    agent_name: str
    owner_email: str
    jti: str             # subject token's jti — ties issued material to the exchange
    params: dict         # request-supplied params (e.g. {"public_key": ...})


class CredentialProvider(Protocol):
    kind: str

    def validate_config(self, config: dict, seed: str) -> None:
        """Raise ProviderError if provider_config or the seed is unusable.
        Called at credential create/update so misconfig fails fast, not at
        exchange time."""

    def injectable_as_header(self) -> bool:
        """True if issued material can be injected as an HTTP header by the
        gateway. ssh-ca material cannot, so it can never bind a route."""

    def issue(self, ctx: IssueContext) -> Issued:
        ...


# Custom issued-token-type URNs for material that has no IANA-registered type.
TOKEN_TYPE_SSH_CERT = "urn:cipherlatch:params:oauth:token-type:ssh-certificate"


def get_provider(kind: str) -> CredentialProvider:
    if kind == "ssh-ca":
        from .ssh_ca import SshCaProvider

        return SshCaProvider()
    raise ProviderError(f"Unknown credential provider '{kind}' (expected: ssh-ca)")


VALID_PROVIDERS = ("ssh-ca",)
