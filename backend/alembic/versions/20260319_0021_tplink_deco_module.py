"""add tplink deco module config and sync runs

Revision ID: 20260319_0021
Revises: 20260319_0020
Create Date: 2026-03-19 12:20:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260319_0021"
down_revision = "20260319_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tplink_deco_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("base_url", sa.String(length=255), nullable=False, server_default="http://tplinkdeco.net"),
        sa.Column("owner_username", sa.String(length=128), nullable=True),
        sa.Column("owner_password", sa.String(length=256), nullable=True),
        sa.Column("fetch_connected_clients", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("fetch_portal_logs", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=False, server_default="idle"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_client_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_table(
        "tplink_deco_sync_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("client_count", sa.Integer(), nullable=True),
        sa.Column("clients_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("logs_excerpt", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("tplink_deco_sync_runs")
    op.drop_table("tplink_deco_configs")
