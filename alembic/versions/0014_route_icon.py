"""Gateway route: display icon (emoji or auto-detected favicon data URI).

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "gateway_routes",
        sa.Column("icon", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("gateway_routes", "icon")
