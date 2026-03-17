"""add backup policies

Revision ID: 202603170009
Revises: 202603170008
Create Date: 2026-03-17 13:45:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "202603170009"
down_revision = "202603170008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "config_backup_policies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("tag_filter", sa.String(length=64), nullable=False),
        sa.Column("retention_count", sa.Integer(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("config_backup_policies")
