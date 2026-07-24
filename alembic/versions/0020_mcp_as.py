"""MCP authorization server: CIMD clients, registered resources,
authorization codes (PKCE), and consent grants.

Revision ID: 0020
Revises: 0019
"""

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mcp_clients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("client_id_url", sa.String(1024), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, server_default=""),
        sa.Column("metadata_doc", sa.JSON(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_mcp_clients_client_id_url", "mcp_clients",
                    ["client_id_url"], unique=True)

    op.create_table(
        "mcp_resources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("resource_uri", sa.String(1024), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_scopes", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "resource_uri", name="uq_mcp_resources_tenant_uri"),
    )
    op.create_index("ix_mcp_resources_tenant_id", "mcp_resources", ["tenant_id"])

    op.create_table(
        "authorization_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code_sha256", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("principal_id", sa.String(36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("client_id_url", sa.String(1024), nullable=False),
        sa.Column("redirect_uri", sa.String(1024), nullable=False),
        sa.Column("resource", sa.String(1024), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("issued_jti", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_authorization_codes_code_sha256", "authorization_codes",
                    ["code_sha256"], unique=True)
    op.create_index("ix_authorization_codes_tenant_id", "authorization_codes", ["tenant_id"])
    op.create_index("ix_authorization_codes_principal_id", "authorization_codes",
                    ["principal_id"])
    op.create_index("ix_authorization_codes_expires_at", "authorization_codes",
                    ["expires_at"])

    op.create_table(
        "consent_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("principal_id", sa.String(36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("client_id_url", sa.String(1024), nullable=False),
        sa.Column("resource", sa.String(1024), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("principal_id", "client_id_url", "resource",
                            name="uq_consent_grants_triple"),
    )
    op.create_index("ix_consent_grants_tenant_id", "consent_grants", ["tenant_id"])
    op.create_index("ix_consent_grants_principal_id", "consent_grants", ["principal_id"])


def downgrade() -> None:
    op.drop_table("consent_grants")
    op.drop_table("authorization_codes")
    op.drop_table("mcp_resources")
    op.drop_table("mcp_clients")
