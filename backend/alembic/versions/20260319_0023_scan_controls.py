"""add scan control fields

Revision ID: 20260319_0023
Revises: 20260319_0022
Create Date: 2026-03-19 23:45:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260319_0023"
down_revision = "20260319_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("control_action", sa.String(length=16), nullable=True))
    op.add_column("scan_jobs", sa.Column("control_mode", sa.String(length=32), nullable=True))
    op.add_column("scan_jobs", sa.Column("resume_after", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_jobs", "resume_after")
    op.drop_column("scan_jobs", "control_mode")
    op.drop_column("scan_jobs", "control_action")
