"""add topology default segment prefix setting

Revision ID: 20260326_0034
Revises: 20260326_0033
Create Date: 2026-03-26 12:45:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260326_0034"
down_revision = "20260326_0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_configs",
        sa.Column("topology_default_segment_prefix_v4", sa.Integer(), nullable=False, server_default="24"),
    )
    op.alter_column("scanner_configs", "topology_default_segment_prefix_v4", server_default=None)


def downgrade() -> None:
    op.drop_column("scanner_configs", "topology_default_segment_prefix_v4")
