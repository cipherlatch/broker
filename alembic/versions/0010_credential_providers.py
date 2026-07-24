"""Dynamic credential providers: per-credential provider + provider_config.

Revision ID: 0010
Revises: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("provider", sa.String(32), nullable=True))
    op.add_column("credentials", sa.Column("provider_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("credentials", "provider_config")
    op.drop_column("credentials", "provider")
