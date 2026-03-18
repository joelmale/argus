from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

from app.db.models import Asset, AssetAIAnalysis
from app.db.session import AsyncSessionLocal
from app.db.upsert import upsert_scan_result
from app.scanner.models import AIAnalysis, DeviceClass, DiscoveredHost, HostScanResult, PortResult


@pytest.mark.asyncio
async def test_upsert_persists_asset_ai_analysis():
    ip = f"10.253.{uuid.uuid4().int % 200}.30"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            result = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="arp", mac_address="AA:BB:CC:DD:EE:FF"),
                ports=[PortResult(port=443, protocol="tcp", state="open", service="https")],
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.ROUTER,
                    confidence=0.93,
                    vendor="TP-Link",
                    model="Deco XE75",
                    os_guess="Embedded Linux",
                    device_role="mesh access point",
                    open_services_summary=["HTTPS admin UI"],
                    investigation_notes="HTTPS surface and vendor signals match a TP-Link Deco node.",
                    suggested_tags=["wifi", "infrastructure"],
                    ai_backend="ollama",
                    model_used="qwen2.5:7b",
                    agent_steps=4,
                ),
            )

            asset, _ = await upsert_scan_result(db, result)
            await db.commit()

            analysis = (
                await db.execute(select(AssetAIAnalysis).where(AssetAIAnalysis.asset_id == asset.id))
            ).scalar_one()

            assert analysis.device_class == "router"
            assert analysis.vendor == "TP-Link"
            assert analysis.model == "Deco XE75"
            assert analysis.ai_backend == "ollama"
            assert analysis.open_services_summary == ["HTTPS admin UI"]
            assert analysis.suggested_tags == ["wifi", "infrastructure"]
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()
