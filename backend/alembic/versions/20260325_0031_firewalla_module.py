"""add firewalla module tables

Revision ID: 20260325_0031
Revises: 20260325_0030
Create Date: 2026-03-25 13:10:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260325_0031"
down_revision = "20260325_0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "firewalla_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("base_url", sa.String(255), nullable=False, server_default="http://firewalla.lan"),
        sa.Column("api_token", sa.String(512), nullable=True),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("fetch_devices", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("fetch_alarms", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(32), nullable=False, server_default="idle"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_device_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "firewalla_sync_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("device_count", sa.Integer(), nullable=True),
        sa.Column("alarm_count", sa.Integer(), nullable=True),
        sa.Column("devices_payload", JSONB(), nullable=True),
        sa.Column("alarms_payload", JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("firewalla_sync_runs")
    op.drop_table("firewalla_configs")
