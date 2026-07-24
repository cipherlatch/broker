"""Credential: display icon (emoji or an uploaded/fetched image data URI).

Revision ID: 0016
Revises: 0015
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column("icon", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("credentials", "icon")
