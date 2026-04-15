"""add topology latency and ttl evidence fields

Revision ID: 20260415_0037
Revises: 20260414_0036
Create Date: 2026-04-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260415_0037"
down_revision = "20260414_0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("avg_latency_ms", sa.Float(), nullable=True))
    op.add_column("assets", sa.Column("ttl_distance", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "ttl_distance")
    op.drop_column("assets", "avg_latency_ms")
