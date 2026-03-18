from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

from app.db.models import Asset
from app.db.session import AsyncSessionLocal
from app.db.upsert import upsert_scan_result
from app.scanner.models import AIAnalysis, DeviceClass, DiscoveredHost, HostScanResult, OSFingerprint


@pytest.mark.asyncio
async def test_upsert_ignores_weak_os_and_ai_classification():
    ip = f"10.254.{uuid.uuid4().int % 200}.20"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            result = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="ping"),
                os_fingerprint=OSFingerprint(os_name="Sanyo PLC-XU88 digital projector", os_accuracy=92),
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.IOT_DEVICE,
                    confidence=0.55,
                    vendor="Sanyo",
                    os_guess="Sanyo PLC-XU88 digital projector",
                    investigation_notes="Weak heuristic guess",
                ),
            )

            asset, change_type = await upsert_scan_result(db, result)
            await db.commit()

            assert change_type == "discovered"
            assert asset.os_name is None
            assert asset.device_type is None
            assert asset.vendor is None

            persisted = (await db.execute(select(Asset).where(Asset.ip_address == ip))).scalar_one()
            assert persisted.os_name is None
            assert persisted.device_type is None
            assert persisted.vendor is None
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()
