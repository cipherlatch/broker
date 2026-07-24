"""Graveyard: tombstones for archived agents/users (delete = archive).

Revision ID: 0019
Revises: 0018
"""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graveyard",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("original_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("original_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_graveyard_tenant_id", "graveyard", ["tenant_id"])
    op.create_index("ix_graveyard_original_id", "graveyard", ["original_id"])


def downgrade() -> None:
    op.drop_table("graveyard")
