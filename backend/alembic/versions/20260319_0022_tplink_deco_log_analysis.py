"""add tplink deco log analysis field

Revision ID: 20260319_0022
Revises: 20260319_0021
Create Date: 2026-03-19 21:25:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260319_0022"
down_revision = "20260319_0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tplink_deco_sync_runs",
        sa.Column("log_analysis", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tplink_deco_sync_runs", "log_analysis")
