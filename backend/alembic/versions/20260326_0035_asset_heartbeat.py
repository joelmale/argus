"""add asset heartbeat tracking

Revision ID: 20260326_0035
Revises: 20260326_0034
Create Date: 2026-03-26 14:20:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260326_0035"
down_revision = "20260326_0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("heartbeat_missed_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "assets",
        sa.Column("heartbeat_last_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.alter_column("assets", "heartbeat_missed_count", server_default=None)


def downgrade() -> None:
    op.drop_column("assets", "heartbeat_last_checked_at")
    op.drop_column("assets", "heartbeat_missed_count")
