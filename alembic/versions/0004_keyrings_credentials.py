"""Phase 2.5: agent keyrings + downstream credentials with per-agent grants.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents", sa.Column("keyring", sa.String(64), nullable=False, server_default="default")
    )

    op.create_table(
        "credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_exchanged_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_credentials_tenant_name"),
    )
    op.create_index("ix_credentials_tenant_id", "credentials", ["tenant_id"])
    op.create_index("ix_credentials_owner_id", "credentials", ["owner_id"])

    op.create_table(
        "credential_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "credential_id",
            sa.String(36),
            sa.ForeignKey("credentials.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("credential_id", "agent_id", name="uq_credential_grants_pair"),
    )
    op.create_index("ix_credential_grants_credential_id", "credential_grants", ["credential_id"])
    op.create_index("ix_credential_grants_agent_id", "credential_grants", ["agent_id"])


def downgrade() -> None:
    op.drop_table("credential_grants")
    op.drop_table("credentials")
    op.drop_column("agents", "keyring")
