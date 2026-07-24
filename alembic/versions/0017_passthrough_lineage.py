"""Ephemeral-credential passthrough: per-route config + witnessed-credential
lineage table.

Revision ID: 0017
Revises: 0016
"""

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "gateway_routes",
        sa.Column("passthrough_config", sa.JSON(), nullable=True),
    )
    op.create_table(
        "witnessed_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "route_id",
            sa.String(36),
            sa.ForeignKey("gateway_routes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.String(36), nullable=False),
        sa.Column("token_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_sha256", name="uq_witnessed_credentials_token"),
    )
    op.create_index("ix_witnessed_credentials_route_id", "witnessed_credentials", ["route_id"])
    op.create_index("ix_witnessed_credentials_agent_id", "witnessed_credentials", ["agent_id"])
    op.create_index("ix_witnessed_credentials_token_sha256", "witnessed_credentials", ["token_sha256"])
    op.create_index("ix_witnessed_credentials_expires_at", "witnessed_credentials", ["expires_at"])


def downgrade() -> None:
    op.drop_table("witnessed_credentials")
    op.drop_column("gateway_routes", "passthrough_config")
