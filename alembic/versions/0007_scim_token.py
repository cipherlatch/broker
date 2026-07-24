"""SCIM 2.0 provisioning: per-tenant SCIM bearer-token digest.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("scim_token_digest", sa.String(64), nullable=True))
    op.create_index("ix_tenants_scim_token_digest", "tenants", ["scim_token_digest"])


def downgrade() -> None:
    op.drop_index("ix_tenants_scim_token_digest", table_name="tenants")
    op.drop_column("tenants", "scim_token_digest")
