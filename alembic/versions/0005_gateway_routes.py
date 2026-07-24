"""Phase 3: enforcing gateway — routes + per-agent route grants.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gateway_routes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("upstream_base", sa.String(1024), nullable=False),
        sa.Column("credential_id", sa.String(36), sa.ForeignKey("credentials.id"), nullable=False),
        sa.Column("inject_mode", sa.String(16), nullable=False, server_default="bearer"),
        sa.Column("inject_header", sa.String(64), nullable=False, server_default="Authorization"),
        sa.Column("allowed_methods", sa.JSON(), nullable=False),
        sa.Column("allowed_path_prefixes", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "slug", name="uq_gateway_routes_tenant_slug"),
    )
    op.create_index("ix_gateway_routes_tenant_id", "gateway_routes", ["tenant_id"])
    op.create_index("ix_gateway_routes_owner_id", "gateway_routes", ["owner_id"])
    op.create_index("ix_gateway_routes_credential_id", "gateway_routes", ["credential_id"])

    op.create_table(
        "route_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "route_id",
            sa.String(36),
            sa.ForeignKey("gateway_routes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("route_id", "agent_id", name="uq_route_grants_pair"),
    )
    op.create_index("ix_route_grants_route_id", "route_grants", ["route_id"])
    op.create_index("ix_route_grants_agent_id", "route_grants", ["agent_id"])


def downgrade() -> None:
    op.drop_table("route_grants")
    op.drop_table("gateway_routes")
