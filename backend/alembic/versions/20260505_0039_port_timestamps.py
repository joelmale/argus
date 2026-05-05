"""add first_seen and last_seen to ports

Revision ID: 20260505_0039
Revises: 20260415_0038
Create Date: 2026-05-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260505_0039"
down_revision = "20260415_0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ports",
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.add_column(
        "ports",
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    op.drop_column("ports", "last_seen")
    op.drop_column("ports", "first_seen")
