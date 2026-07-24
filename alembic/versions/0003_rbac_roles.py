"""Phase 2.1: configurable RBAC — roles table, principals.role_id.

Backfills built-in roles per tenant and maps the old role strings:
admin -> broker-admin, user -> agent-manager. Plain ALTERs only (no
batch/table-recreate) so Postgres and SQLite behave identically; the
role_id foreign key is therefore enforced at the application layer on
databases migrated from Phase 2 (fresh installs get it from create_all
semantics on Postgres via this same path — acceptable for a lookup table
whose rows are never deleted while referenced, which crud enforces).

Revision ID: 0003
Revises: 0002
"""

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

BUILTINS = {
    "broker-admin": ("Full control of the broker", ["*"]),
    "agent-manager": (
        "Manages their own agents",
        ["agents:create", "agents:read", "agents:update", "agents:rotate", "agents:revoke", "audit:read"],
    ),
    "auditor": (
        "Read-only visibility across agents, users, and the audit log",
        ["agents:read:all", "users:read", "roles:read", "audit:read:all"],
    ),
}


def upgrade() -> None:
    roles = op.create_table(
        "roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_roles_tenant_name"),
    )
    op.create_index("ix_roles_tenant_id", "roles", ["tenant_id"])

    conn = op.get_bind()
    now = datetime.now(timezone.utc)
    role_ids: dict[tuple[str, str], str] = {}
    for (tenant_id,) in conn.execute(sa.text("SELECT id FROM tenants")):
        for name, (desc, perms) in BUILTINS.items():
            rid = str(uuid.uuid4())
            role_ids[(tenant_id, name)] = rid
            conn.execute(
                roles.insert().values(
                    id=rid, tenant_id=tenant_id, name=name, description=desc,
                    permissions=perms, builtin=True, created_at=now,
                )
            )

    op.add_column("principals", sa.Column("role_id", sa.String(36), nullable=True))
    op.create_index("ix_principals_role_id", "principals", ["role_id"])

    for pid, tenant_id, old_role in conn.execute(
        sa.text("SELECT id, tenant_id, role FROM principals")
    ):
        target = "broker-admin" if old_role == "admin" else "agent-manager"
        conn.execute(
            sa.text("UPDATE principals SET role_id = :rid WHERE id = :pid"),
            {"rid": role_ids[(tenant_id, target)], "pid": pid},
        )

    op.drop_column("principals", "role")


def downgrade() -> None:
    op.add_column(
        "principals", sa.Column("role", sa.String(16), nullable=False, server_default="user")
    )
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE principals SET role = 'admin' WHERE role_id IN "
            "(SELECT id FROM roles WHERE name = 'broker-admin')"
        )
    )
    op.drop_index("ix_principals_role_id", "principals")
    op.drop_column("principals", "role_id")
    op.drop_table("roles")
