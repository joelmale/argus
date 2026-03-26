"""add pfsense module tables

Revision ID: 20260325_0030
Revises: 20260325_0029
Create Date: 2026-03-25 13:05:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260325_0030"
down_revision = "20260325_0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pfsense_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("base_url", sa.String(255), nullable=False, server_default="http://192.168.1.1"),
        sa.Column("flavor", sa.String(16), nullable=False, server_default="opnsense"),
        sa.Column("api_key", sa.String(256), nullable=True),
        sa.Column("api_secret", sa.String(256), nullable=True),
        sa.Column("fauxapi_token", sa.String(512), nullable=True),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("fetch_dhcp_leases", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("fetch_arp_table", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("fetch_interfaces", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=False, server_default="idle"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_lease_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "pfsense_sync_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("lease_count", sa.Integer(), nullable=True),
        sa.Column("arp_count", sa.Integer(), nullable=True),
        sa.Column("interface_count", sa.Integer(), nullable=True),
        sa.Column("leases_payload", JSONB(), nullable=True),
        sa.Column("arp_payload", JSONB(), nullable=True),
        sa.Column("interfaces_payload", JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("pfsense_sync_runs")
    op.drop_table("pfsense_configs")
