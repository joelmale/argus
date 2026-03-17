from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.backups import apply_backup_retention, generate_backup_diff, generate_restore_assist, get_backup_policy, update_backup_policy
from app.db.models import Asset, ConfigBackupSnapshot, ConfigBackupTarget
from app.db.session import AsyncSessionLocal


@pytest.mark.asyncio
async def test_backup_policy_and_retention_flow():
    asset_id = uuid4()
    async with AsyncSessionLocal() as db:
        policy = await update_backup_policy(
            db,
            enabled=True,
            interval_minutes=120,
            tag_filter="infra",
            retention_count=2,
        )
        assert policy.enabled is True
        loaded = await get_backup_policy(db)
        assert loaded.retention_count == 2

        asset = Asset(
            id=asset_id,
            ip_address=f"192.168.210.{asset_id.int % 200 + 20}",
            hostname=f"backup-{asset_id.hex[:6]}",
            status="online",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(asset)
        await db.flush()
        target = ConfigBackupTarget(asset_id=asset.id, driver="openwrt", username="root", password_env_var="ARGUS_TEST", enabled=True)
        db.add(target)
        await db.flush()
        for idx in range(3):
            db.add(
                ConfigBackupSnapshot(
                    asset_id=asset.id,
                    target_id=target.id,
                    status="done",
                    driver="openwrt",
                    content=f"config line {idx}\n",
                    captured_at=datetime.now(timezone.utc),
                )
            )
        await db.commit()

        deleted = await apply_backup_retention(db, asset.id, keep_latest=2)
        assert deleted == 1

        snapshots = (
            await db.execute(
                select(ConfigBackupSnapshot)
                .where(ConfigBackupSnapshot.asset_id == asset.id)
                .order_by(ConfigBackupSnapshot.id.asc())
            )
        ).scalars().all()
        diff = await generate_backup_diff(db, asset.id, snapshots[-1].id, snapshots[0].id)
        assist = await generate_restore_assist(db, asset.id, snapshots[-1].id)
        await db.delete(asset)
        await db.commit()

    assert "snapshot-" in diff
    assert assist["commands"]
