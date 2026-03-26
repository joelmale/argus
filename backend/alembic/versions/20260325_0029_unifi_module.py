"""add unifi module tables

Revision ID: 20260325_0029
Revises: 20260325_0028
Create Date: 2026-03-25 13:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260325_0029"
down_revision = "20260325_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "unifi_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("controller_url", sa.String(255), nullable=False, server_default="https://192.168.1.1"),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("password", sa.String(256), nullable=True),
        sa.Column("site_id", sa.String(64), nullable=False, server_default="default"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("fetch_clients", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("fetch_devices", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=False, server_default="idle"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_client_count", sa.Integer(), nullable=True),
        sa.Column("last_device_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "unifi_sync_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("client_count", sa.Integer(), nullable=True),
        sa.Column("device_count", sa.Integer(), nullable=True),
        sa.Column("clients_payload", JSONB(), nullable=True),
        sa.Column("devices_payload", JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("unifi_sync_runs")
    op.drop_table("unifi_configs")
