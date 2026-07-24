"""Workload identity federation: per-agent (issuer, subject) binding.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("federated_issuer", sa.String(255), nullable=True))
    op.add_column("agents", sa.Column("federated_subject", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "federated_subject")
    op.drop_column("agents", "federated_issuer")
