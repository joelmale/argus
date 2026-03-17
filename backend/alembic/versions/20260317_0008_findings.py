"""add findings

Revision ID: 202603170008
Revises: 202603170007
Create Date: 2026-03-17 13:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "202603170008"
down_revision = "202603170007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("port_id", sa.Integer(), nullable=True),
        sa.Column("source_tool", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("cve", sa.String(length=64), nullable=True),
        sa.Column("service", sa.String(length=64), nullable=True),
        sa.Column("port_number", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=8), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["port_id"], ["ports.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("findings")
