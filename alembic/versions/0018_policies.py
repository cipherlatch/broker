"""Native contextual policies: first-class policy objects + attachments.

Revision ID: 0018
Revises: 0017
"""

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_policies_tenant_name"),
    )
    op.create_index("ix_policies_tenant_id", "policies", ["tenant_id"])
    op.create_index("ix_policies_owner_id", "policies", ["owner_id"])
    op.create_table(
        "policy_attachments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "policy_id", sa.String(36),
            sa.ForeignKey("policies.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "target_type", "target_id",
                            name="uq_policy_attachments_target"),
    )
    op.create_index("ix_policy_attachments_policy_id", "policy_attachments", ["policy_id"])
    op.create_index("ix_policy_attachments_target_id", "policy_attachments", ["target_id"])


def downgrade() -> None:
    op.drop_table("policy_attachments")
    op.drop_table("policies")
