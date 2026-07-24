"""Top-3: token revocation, private_key_jwt public key, DPoP binding support.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("auth_public_jwk", sa.JSON(), nullable=True))
    op.add_column("agents", sa.Column("token_gen", sa.Integer(), nullable=False, server_default="0"))

    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_revoked_tokens_agent_id", "revoked_tokens", ["agent_id"])
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("revoked_tokens")
    op.drop_column("agents", "token_gen")
    op.drop_column("agents", "auth_public_jwk")
