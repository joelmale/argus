"""add suppressed flag to topology_links

Revision ID: 20260415_0038
Revises: 20260415_0037
Create Date: 2026-04-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260415_0038"
down_revision = "20260415_0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "topology_links",
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index(
        "ix_topology_links_suppressed",
        "topology_links",
        ["suppressed"],
        postgresql_where=sa.text("suppressed = false"),
    )


def downgrade() -> None:
    op.drop_index("ix_topology_links_suppressed", table_name="topology_links")
    op.drop_column("topology_links", "suppressed")
