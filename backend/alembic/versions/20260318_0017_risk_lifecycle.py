"""add risk lifecycle records

Revision ID: 20260318_0017
Revises: 20260318_0016
Create Date: 2026-03-18 21:49:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260318_0017"
down_revision = "20260318_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "lifecycle_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=True),
        sa.Column("support_status", sa.String(length=32), nullable=False),
        sa.Column("eol_date", sa.String(length=32), nullable=True),
        sa.Column("reference", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("lifecycle_records")
