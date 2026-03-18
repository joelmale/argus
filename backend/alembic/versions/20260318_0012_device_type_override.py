"""add device type override and source

Revision ID: 20260318_0012
Revises: 20260318_0011
Create Date: 2026-03-18 14:05:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260318_0012"
down_revision = "202603180011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("device_type_override", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("device_type_source", sa.String(length=16), nullable=False, server_default="unknown"))
    op.execute(
        """
        UPDATE assets
        SET device_type_source = CASE
            WHEN device_type IS NULL OR device_type = 'unknown' THEN 'unknown'
            ELSE 'legacy'
        END
        """
    )
    op.alter_column("assets", "device_type_source", server_default=None)


def downgrade() -> None:
    op.drop_column("assets", "device_type_source")
    op.drop_column("assets", "device_type_override")
