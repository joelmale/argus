"""add dedicated scheduled scan toggle

Revision ID: 20260325_0028
Revises: 20260324_0027
Create Date: 2026-03-25 12:20:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260325_0028"
down_revision = "20260324_0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scanner_configs",
        sa.Column("scheduled_scans_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute("UPDATE scanner_configs SET scheduled_scans_enabled = enabled")
    op.alter_column("scanner_configs", "scheduled_scans_enabled", server_default=None)


def downgrade() -> None:
    op.drop_column("scanner_configs", "scheduled_scans_enabled")
