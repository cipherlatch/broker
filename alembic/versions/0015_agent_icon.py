"""Agent: display icon (emoji or a fetched image data URI).

Revision ID: 0015
Revises: 0014
"""

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("icon", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("agents", "icon")
