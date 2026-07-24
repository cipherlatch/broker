"""Phase 2: OIDC identity binding, roles, agent lockout/resources, audit actor+ip.

Plain column adds only (no batch/table-recreate), so the migration behaves
identically on Postgres and SQLite. The (tenant_id, sub) uniqueness is
enforced via a unique index.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("principals", sa.Column("sub", sa.String(255), nullable=True))
    op.add_column(
        "principals", sa.Column("role", sa.String(16), nullable=False, server_default="user")
    )
    op.add_column(
        "principals", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true())
    )
    op.add_column("principals", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "principals", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index("ix_principals_sub", "principals", ["sub"])
    op.create_index(
        "uq_principals_tenant_sub", "principals", ["tenant_id", "sub"], unique=True
    )

    op.add_column(
        "agents", sa.Column("allowed_resources", sa.JSON(), nullable=False, server_default="[]")
    )
    op.add_column(
        "agents", sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("agents", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE agents SET updated_at = created_at WHERE updated_at IS NULL")

    op.add_column(
        "audit_events", sa.Column("actor", sa.String(255), nullable=False, server_default="")
    )
    op.add_column("audit_events", sa.Column("ip", sa.String(64), nullable=False, server_default=""))
    op.create_index("ix_audit_events_actor", "audit_events", ["actor"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_actor", "audit_events")
    op.drop_column("audit_events", "ip")
    op.drop_column("audit_events", "actor")

    op.drop_column("agents", "updated_at")
    op.drop_column("agents", "locked_until")
    op.drop_column("agents", "failed_attempts")
    op.drop_column("agents", "allowed_resources")

    op.drop_index("uq_principals_tenant_sub", "principals")
    op.drop_index("ix_principals_sub", "principals")
    op.drop_column("principals", "last_login_at")
    op.drop_column("principals", "deleted_at")
    op.drop_column("principals", "active")
    op.drop_column("principals", "role")
    op.drop_column("principals", "sub")
