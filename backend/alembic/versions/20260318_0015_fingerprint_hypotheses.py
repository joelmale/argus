"""add fingerprint hypotheses and scanner ai controls

Revision ID: 20260318_0015
Revises: 20260318_0014
Create Date: 2026-03-18 21:18:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260318_0015"
down_revision = "20260318_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fingerprint_hypotheses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("device_type", sa.String(length=64), nullable=True),
        sa.Column("vendor", sa.String(length=256), nullable=True),
        sa.Column("model", sa.String(length=256), nullable=True),
        sa.Column("os_guess", sa.String(length=256), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("supporting_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("model_used", sa.String(length=128), nullable=True),
        sa.Column("raw_response", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("scanner_configs", sa.Column("fingerprint_ai_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scanner_configs", sa.Column("fingerprint_ai_model", sa.String(length=128), nullable=True))
    op.add_column("scanner_configs", sa.Column("fingerprint_ai_min_confidence", sa.Float(), nullable=False, server_default="0.75"))
    op.add_column("scanner_configs", sa.Column("fingerprint_ai_prompt_suffix", sa.Text(), nullable=True))
    op.alter_column("scanner_configs", "fingerprint_ai_enabled", server_default=None)
    op.alter_column("scanner_configs", "fingerprint_ai_min_confidence", server_default=None)


def downgrade() -> None:
    op.drop_column("scanner_configs", "fingerprint_ai_prompt_suffix")
    op.drop_column("scanner_configs", "fingerprint_ai_min_confidence")
    op.drop_column("scanner_configs", "fingerprint_ai_model")
    op.drop_column("scanner_configs", "fingerprint_ai_enabled")
    op.drop_table("fingerprint_hypotheses")
