"""add scan queue position

Revision ID: 20260320_0024
Revises: 20260319_0023
Create Date: 2026-03-20 00:15:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260320_0024"
down_revision = "20260319_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("queue_position", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_jobs", "queue_position")
