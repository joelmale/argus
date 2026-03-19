"""add internet lookup cache and controls

Revision ID: 20260318_0016
Revises: 20260318_0015
Create Date: 2026-03-18 21:34:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260318_0016"
down_revision = "20260318_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "internet_lookup_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("query", sa.String(length=512), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("scanner_configs", sa.Column("internet_lookup_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scanner_configs", sa.Column("internet_lookup_allowed_domains", sa.Text(), nullable=True))
    op.add_column("scanner_configs", sa.Column("internet_lookup_budget", sa.Integer(), nullable=False, server_default="3"))
    op.add_column("scanner_configs", sa.Column("internet_lookup_timeout_seconds", sa.Integer(), nullable=False, server_default="5"))
    op.alter_column("scanner_configs", "internet_lookup_enabled", server_default=None)
    op.alter_column("scanner_configs", "internet_lookup_budget", server_default=None)
    op.alter_column("scanner_configs", "internet_lookup_timeout_seconds", server_default=None)


def downgrade() -> None:
    op.drop_column("scanner_configs", "internet_lookup_timeout_seconds")
    op.drop_column("scanner_configs", "internet_lookup_budget")
    op.drop_column("scanner_configs", "internet_lookup_allowed_domains")
    op.drop_column("scanner_configs", "internet_lookup_enabled")
    op.drop_table("internet_lookup_results")
