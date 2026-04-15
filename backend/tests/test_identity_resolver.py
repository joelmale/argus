from __future__ import annotations

from sqlalchemy import func, select

import pytest

from app.db.models import Asset, AssetHistory
from app.db.session import AsyncSessionLocal
from app.services.identity import AssetIdentityResolver


@pytest.mark.asyncio
async def test_identity_resolver_ignores_randomized_mac_without_ip():
    async with AsyncSessionLocal() as db:
        resolver = AssetIdentityResolver(db, source="test")
        asset = await resolver.resolve_asset(mac="02:11:22:33:44:55", create_if_missing=True)

        assert asset is None
        asset_count = await db.scalar(select(func.count()).select_from(Asset))
        assert asset_count == 0


@pytest.mark.asyncio
async def test_identity_resolver_rehomes_existing_asset_by_stable_mac():
    async with AsyncSessionLocal() as db:
        existing = Asset(
            ip_address="192.168.1.20",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="desktop",
            status="online",
        )
        db.add(existing)
        await db.commit()
        await db.refresh(existing)

        resolver = AssetIdentityResolver(db, source="test")
        resolved = await resolver.resolve_asset(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.21",
            hostname="desktop",
            lookup_order=("mac", "ip"),
        )
        await db.commit()

        assert resolved is not None
        assert resolved.id == existing.id
        assert resolved.ip_address == "192.168.1.21"

        history = await db.execute(select(AssetHistory).where(AssetHistory.asset_id == existing.id))
        entries = history.scalars().all()
        assert any(entry.change_type.startswith("identity_") for entry in entries)
