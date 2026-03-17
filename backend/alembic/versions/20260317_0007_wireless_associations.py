"""add wireless associations

Revision ID: 202603170007
Revises: 202603170006
Create Date: 2026-03-17 11:15:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "202603170007"
down_revision = "202603170006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wireless_associations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("access_point_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("client_mac", sa.String(length=17), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("ssid", sa.String(length=128), nullable=True),
        sa.Column("band", sa.String(length=32), nullable=True),
        sa.Column("signal_dbm", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["access_point_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["client_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("wireless_associations")
