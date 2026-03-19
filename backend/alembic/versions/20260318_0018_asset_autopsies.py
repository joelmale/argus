"""add asset autopsy traces

Revision ID: 20260318_0018
Revises: 20260318_0017
Create Date: 2026-03-18 23:55:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260318_0018"
down_revision = "20260318_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_autopsies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("trace", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id"),
    )


def downgrade() -> None:
    op.drop_table("asset_autopsies")
