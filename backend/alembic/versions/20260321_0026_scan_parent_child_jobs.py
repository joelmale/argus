"""add parent child scan jobs

Revision ID: 20260321_0026
Revises: 20260321_0025
Create Date: 2026-03-21 11:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260321_0026"
down_revision = "20260321_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("parent_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("scan_jobs", sa.Column("chunk_index", sa.Integer(), nullable=True))
    op.add_column("scan_jobs", sa.Column("chunk_count", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_scan_jobs_parent_id_scan_jobs",
        "scan_jobs",
        "scan_jobs",
        ["parent_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_scan_jobs_parent_id_scan_jobs", "scan_jobs", type_="foreignkey")
    op.drop_column("scan_jobs", "chunk_count")
    op.drop_column("scan_jobs", "chunk_index")
    op.drop_column("scan_jobs", "parent_id")
