"""Service keys: scoped machine credentials for the control plane.

A service key is a machine principal that carries a Role (any role, built-in
or custom) and authenticates to the control plane via the X-Api-Key header
with that role's permissions — the least-privilege alternative to sharing the
platform X-Admin-Key. Tenant-scoped; never platform admin.

Revision ID: 0021
Revises: 0020
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("role_id", sa.String(36), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        # SHA-256 hex of the presented key; only the hash is ever stored.
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_service_keys_tenant_name"),
        sa.UniqueConstraint("key_hash", name="uq_service_keys_key_hash"),
    )
    op.create_index("ix_service_keys_tenant_id", "service_keys", ["tenant_id"])
    op.create_index("ix_service_keys_key_hash", "service_keys", ["key_hash"])
    op.create_index("ix_service_keys_role_id", "service_keys", ["role_id"])


def downgrade() -> None:
    op.drop_table("service_keys")
