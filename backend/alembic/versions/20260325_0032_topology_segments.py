"""add typed topology metadata and network segments

Revision ID: 20260325_0032
Revises: 20260325_0031
Create Date: 2026-03-25 21:30:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "20260325_0032"
down_revision = "20260325_0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_segments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("gateway_asset_id", UUID(as_uuid=True), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="heuristic_ipv4_24"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("metadata", JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["gateway_asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cidr"),
    )

    op.add_column("topology_links", sa.Column("relationship_type", sa.String(length=64), nullable=False, server_default="neighbor_l2"))
    op.add_column("topology_links", sa.Column("observed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("topology_links", sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"))
    op.add_column("topology_links", sa.Column("source", sa.String(length=64), nullable=False, server_default="inference"))
    op.add_column("topology_links", sa.Column("evidence", JSONB(), nullable=True))
    op.add_column("topology_links", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")))
    op.add_column("topology_links", sa.Column("segment_id", sa.Integer(), nullable=True))
    op.add_column("topology_links", sa.Column("local_interface", sa.String(length=128), nullable=True))
    op.add_column("topology_links", sa.Column("remote_interface", sa.String(length=128), nullable=True))
    op.add_column("topology_links", sa.Column("ssid", sa.String(length=128), nullable=True))
    op.create_foreign_key("fk_topology_links_segment_id", "topology_links", "network_segments", ["segment_id"], ["id"], ondelete="SET NULL")

    op.drop_constraint("uq_topology_link", "topology_links", type_="unique")
    op.create_unique_constraint("uq_topology_link", "topology_links", ["source_id", "target_id", "relationship_type"])


def downgrade() -> None:
    op.drop_constraint("uq_topology_link", "topology_links", type_="unique")
    op.create_unique_constraint("uq_topology_link", "topology_links", ["source_id", "target_id"])

    op.drop_constraint("fk_topology_links_segment_id", "topology_links", type_="foreignkey")
    op.drop_column("topology_links", "ssid")
    op.drop_column("topology_links", "remote_interface")
    op.drop_column("topology_links", "local_interface")
    op.drop_column("topology_links", "segment_id")
    op.drop_column("topology_links", "last_seen")
    op.drop_column("topology_links", "evidence")
    op.drop_column("topology_links", "source")
    op.drop_column("topology_links", "confidence")
    op.drop_column("topology_links", "observed")
    op.drop_column("topology_links", "relationship_type")

    op.drop_table("network_segments")
