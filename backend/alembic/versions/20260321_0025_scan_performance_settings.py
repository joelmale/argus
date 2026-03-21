"""add scanner performance settings

Revision ID: 20260321_0025
Revises: 20260320_0024
Create Date: 2026-03-21 09:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260321_0025"
down_revision = "20260320_0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scanner_configs", sa.Column("host_chunk_size", sa.Integer(), nullable=False, server_default="64"))
    op.add_column("scanner_configs", sa.Column("top_ports_count", sa.Integer(), nullable=False, server_default="1000"))
    op.add_column("scanner_configs", sa.Column("deep_probe_timeout_seconds", sa.Integer(), nullable=False, server_default="6"))
    op.add_column("scanner_configs", sa.Column("ai_after_scan_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))


def downgrade() -> None:
    op.drop_column("scanner_configs", "ai_after_scan_enabled")
    op.drop_column("scanner_configs", "deep_probe_timeout_seconds")
    op.drop_column("scanner_configs", "top_ports_count")
    op.drop_column("scanner_configs", "host_chunk_size")
