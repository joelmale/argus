"""add fingerprinting evidence and probe run tables

Revision ID: 20260318_0013
Revises: 20260318_0012
Create Date: 2026-03-18 20:25:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260318_0013"
down_revision = "20260318_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_evidence_asset_id", "asset_evidence", ["asset_id"], unique=False)
    op.create_index("ix_asset_evidence_category", "asset_evidence", ["category"], unique=False)

    op.create_table(
        "probe_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("probe_type", sa.String(length=32), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("summary", sa.String(length=512), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("raw_excerpt", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_probe_runs_asset_id", "probe_runs", ["asset_id"], unique=False)
    op.create_index("ix_probe_runs_probe_type", "probe_runs", ["probe_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_probe_runs_probe_type", table_name="probe_runs")
    op.drop_index("ix_probe_runs_asset_id", table_name="probe_runs")
    op.drop_table("probe_runs")

    op.drop_index("ix_asset_evidence_category", table_name="asset_evidence")
    op.drop_index("ix_asset_evidence_asset_id", table_name="asset_evidence")
    op.drop_table("asset_evidence")
