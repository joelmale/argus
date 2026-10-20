"""finding lifecycle: occurrences, acknowledgement, resolution time

Revision ID: 20261020_0041
Revises: 20261020_0040
Create Date: 2026-10-20 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20261020_0041"
down_revision = "20261020_0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("occurrences", sa.Integer(), nullable=False, server_default=sa.text("1")))
    op.add_column("findings", sa.Column("ack_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("ack_note", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("acked_by", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_findings_source_external", "findings", ["source_tool", "external_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_source_external", table_name="findings")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "acked_by")
    op.drop_column("findings", "ack_note")
    op.drop_column("findings", "ack_until")
    op.drop_column("findings", "occurrences")
