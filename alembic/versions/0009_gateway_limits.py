"""Gateway policy: per-route per-agent rate limit + daily quota.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "gateway_routes",
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "gateway_routes",
        sa.Column("daily_quota", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("gateway_routes", "daily_quota")
    op.drop_column("gateway_routes", "rate_limit_per_minute")
