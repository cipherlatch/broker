"""ssh-ca provider: sign short-lived OpenSSH user certificates.

The credential *seed* is an OpenSSH CA private key (Ed25519 or ECDSA). On
exchange, the agent submits its own public key; Cipherlatch signs a certificate
scoped to configured principals with a short TTL and returns it. The agent's
private key never transits, and Cipherlatch never touches the SSH connection — the
agent connects directly with its key + the cert, and target hosts trust the
CA via TrustedUserCAKeys.

Zero extra dependencies: cryptography's SSHCertificateBuilder does the work.

provider_config:
  principals:   list of principal templates (default ["agent-{name}"]);
                {name}/{id}/{owner} are substituted from the agent.
  ttl:          certificate lifetime in seconds (default 300, max 3600).
  extensions:   OpenSSH cert extensions to grant (default [] — no PTY, no
                port forwarding; automation doesn't need them).
  source_address: optional comma-separated CIDR allowlist (critical option).

The delegation chain rides in the cert key_id:
  cipherlatch:agent:<id>:owner:<email>:jti:<jti>
so sshd auth logs answer "which agent, for whom, from which token" on hosts
Cipherlatch never sees. SSH certs are not introspectable, so revocation is the
short TTL (and token_gen halts new issuance); documented, not hidden.
"""

import time

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_public_key,
    ssh,
)
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificateBuilder,
    SSHCertificateType,
)

from .base import TOKEN_TYPE_SSH_CERT, IssueContext, Issued, ProviderError

_MAX_TTL = 3600
_DEFAULT_TTL = 300
# Extensions we permit config to request; anything else is refused so a
# typo can't silently grant port forwarding.
_ALLOWED_EXTENSIONS = {
    "permit-pty", "permit-X11-forwarding", "permit-agent-forwarding",
    "permit-port-forwarding", "permit-user-rc",
}


def public_openssh(seed: str) -> str:
    """Derive the CA *public* key (OpenSSH one-liner) from the stored private
    seed — what hosts put in TrustedUserCAKeys. The private half never leaves
    the server; this is the only read the write-only posture permits."""
    key = ssh.load_ssh_private_key(seed.encode(), password=None)
    return key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


class SshCaProvider:
    kind = "ssh-ca"

    def injectable_as_header(self) -> bool:
        return False  # an SSH cert is not an HTTP header — can't bind a route

    def _load_ca(self, seed: str):
        try:
            return ssh.load_ssh_private_key(seed.encode(), password=None)
        except Exception as exc:
            raise ProviderError(f"ssh-ca seed is not a valid OpenSSH private key: {exc}")

    def validate_config(self, config: dict, seed: str) -> None:
        self._load_ca(seed)  # seed must be a usable CA key
        ttl = config.get("ttl", _DEFAULT_TTL)
        if not isinstance(ttl, int) or not (1 <= ttl <= _MAX_TTL):
            raise ProviderError(f"ttl must be an integer 1..{_MAX_TTL} seconds")
        principals = config.get("principals", ["agent-{name}"])
        if not isinstance(principals, list) or not principals:
            raise ProviderError("principals must be a non-empty list")
        if not all(isinstance(p, str) and p for p in principals):
            raise ProviderError("principals must be non-empty strings")
        bad = set(config.get("extensions", [])) - _ALLOWED_EXTENSIONS
        if bad:
            raise ProviderError(f"unsupported extensions: {sorted(bad)}")

    def issue(self, ctx: IssueContext) -> Issued:
        ca_key = self._load_ca(ctx.seed)

        raw_pub = (ctx.params.get("public_key") or "").strip()
        if not raw_pub:
            raise ProviderError(
                "ssh-ca exchange requires a 'public_key' parameter (the agent's "
                "OpenSSH public key)"
            )
        try:
            user_pub = load_ssh_public_key(raw_pub.encode())
        except Exception as exc:
            raise ProviderError(f"public_key is not a valid OpenSSH public key: {exc}")

        ttl = int(ctx.config.get("ttl", _DEFAULT_TTL))
        subs = {"name": ctx.agent_name, "id": ctx.agent_id, "owner": ctx.owner_email}
        try:
            principals = [p.format(**subs).encode() for p in
                          ctx.config.get("principals", ["agent-{name}"])]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"principal template error: {exc}")

        now = int(time.time())
        key_id = f"cipherlatch:agent:{ctx.agent_id}:owner:{ctx.owner_email}:jti:{ctx.jti}"
        builder = (
            SSHCertificateBuilder()
            .public_key(user_pub)
            .serial(now)  # monotonic-ish; not a security property
            .type(SSHCertificateType.USER)
            .key_id(key_id.encode())
            .valid_principals(principals)
            .valid_after(now - 30)   # small backdate for clock skew
            .valid_before(now + ttl)
        )
        for ext in ctx.config.get("extensions", []):
            builder = builder.add_extension(ext.encode(), b"")
        src = (ctx.config.get("source_address") or "").strip()
        if src:
            builder = builder.add_critical_option(b"source-address", src.encode())

        cert = builder.sign(ca_key)
        cert_line = cert.public_bytes().decode()

        return Issued(
            secret=cert_line,
            token_type=TOKEN_TYPE_SSH_CERT,
            expires_in=ttl,
            detail={
                "provider": "ssh-ca",
                "principals": [p.decode() for p in principals],
                "key_id": key_id,
                "ttl": ttl,
            },
        )

    # Convenience for tests / operators: the CA public key to install as a
    # TrustedUserCAKeys entry on target hosts.
    @staticmethod
    def ca_public_key(seed: str) -> str:
        from cryptography.hazmat.primitives.serialization import PublicFormat

        ca = ssh.load_ssh_private_key(seed.encode(), password=None)
        return ca.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
