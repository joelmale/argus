"""add asset ai analysis

Revision ID: 202603180011
Revises: 202603170010
Create Date: 2026-03-18 00:11:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "202603180011"
down_revision = "202603170010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_ai_analyses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_class", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("vendor", sa.String(length=256), nullable=True),
        sa.Column("model", sa.String(length=256), nullable=True),
        sa.Column("os_guess", sa.String(length=256), nullable=True),
        sa.Column("device_role", sa.String(length=256), nullable=True),
        sa.Column("open_services_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("security_findings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("investigation_notes", sa.Text(), nullable=True),
        sa.Column("suggested_tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ai_backend", sa.String(length=32), nullable=False),
        sa.Column("model_used", sa.String(length=128), nullable=True),
        sa.Column("agent_steps", sa.Integer(), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id"),
    )


def downgrade() -> None:
    op.drop_table("asset_ai_analyses")
