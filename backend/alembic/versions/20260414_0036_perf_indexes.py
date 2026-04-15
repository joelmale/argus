"""add performance indexes for inventory and scan access paths

Revision ID: 20260414_0036
Revises: 20260326_0035
Create Date: 2026-04-14 00:00:00.000000
"""

from alembic import op

revision = "20260414_0036"
down_revision = "20260326_0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pg_trgm for ILIKE-accelerated asset search.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # Asset column indexes (B-tree for equality/range, trgm GIN for ILIKE search)
    op.create_index("ix_assets_status", "assets", ["status"])
    op.create_index("ix_assets_last_seen", "assets", ["last_seen"])
    with op.get_context().autocommit_block():
        op.create_index(
            "ix_assets_hostname_trgm",
            "assets",
            ["hostname"],
            postgresql_concurrently=True,
            postgresql_using="gin",
            postgresql_ops={"hostname": "gin_trgm_ops"},
        )
        op.create_index(
            "ix_assets_vendor_trgm",
            "assets",
            ["vendor"],
            postgresql_concurrently=True,
            postgresql_using="gin",
            postgresql_ops={"vendor": "gin_trgm_ops"},
        )
        op.create_index(
            "ix_assets_ip_address_trgm",
            "assets",
            ["ip_address"],
            postgresql_concurrently=True,
            postgresql_using="gin",
            postgresql_ops={"ip_address": "gin_trgm_ops"},
        )

    # asset_tags
    op.create_index("ix_asset_tags_asset_id", "asset_tags", ["asset_id"])
    op.create_index("ix_asset_tags_tag", "asset_tags", ["tag"])

    # asset_history
    op.create_index("ix_asset_history_asset_id", "asset_history", ["asset_id"])

    # scan_jobs composite index for queue and history queries
    op.create_index(
        "ix_scan_jobs_queue",
        "scan_jobs",
        ["parent_id", "status", "queue_position", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_queue", "scan_jobs")
    op.drop_index("ix_asset_history_asset_id", "asset_history")
    op.drop_index("ix_asset_tags_tag", "asset_tags")
    op.drop_index("ix_asset_tags_asset_id", "asset_tags")
    with op.get_context().autocommit_block():
        op.drop_index("ix_assets_ip_address_trgm", "assets", postgresql_concurrently=True)
        op.drop_index("ix_assets_vendor_trgm", "assets", postgresql_concurrently=True)
        op.drop_index("ix_assets_hostname_trgm", "assets", postgresql_concurrently=True)
    op.drop_index("ix_assets_last_seen", "assets")
    op.drop_index("ix_assets_status", "assets")
