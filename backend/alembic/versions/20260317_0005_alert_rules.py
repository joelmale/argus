"""add alert rules

Revision ID: 202603170005
Revises: 202603170004
Create Date: 2026-03-17 15:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "202603170005"
down_revision = "202603170004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("notify_email", sa.Boolean(), nullable=False),
        sa.Column("notify_webhook", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_type"),
    )


def downgrade() -> None:
    op.drop_table("alert_rules")
