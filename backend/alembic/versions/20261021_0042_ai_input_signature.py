"""asset_ai_analyses.input_signature: skip re-investigating unchanged hosts

Revision ID: 20261021_0042
Revises: 20261020_0041
Create Date: 2026-10-21 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20261021_0042"
down_revision = "20261020_0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_ai_analyses", sa.Column("input_signature", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("asset_ai_analyses", "input_signature")
