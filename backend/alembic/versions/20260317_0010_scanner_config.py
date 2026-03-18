"""add scanner config

Revision ID: 202603170010
Revises: 202603170009
Create Date: 2026-03-17 00:10:00
"""

from alembic import op
import sqlalchemy as sa


revision = "202603170010"
down_revision = "202603170009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scanner_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("default_targets", sa.Text(), nullable=True),
        sa.Column("auto_detect_targets", sa.Boolean(), nullable=False),
        sa.Column("default_profile", sa.String(length=32), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("concurrent_hosts", sa.Integer(), nullable=False),
        sa.Column("last_scheduled_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("scanner_configs")
