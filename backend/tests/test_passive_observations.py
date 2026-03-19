from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

from app.db.models import Asset, AssetEvidence, PassiveObservation
from app.db.session import AsyncSessionLocal
from app.db.upsert import upsert_scan_result
from app.fingerprinting.passive import record_passive_observation
from app.scanner.models import DiscoveredHost, HostScanResult, PortResult


@pytest.mark.asyncio
async def test_passive_observation_persists_and_survives_snapshot_refresh():
    ip = f"10.254.{uuid.uuid4().int % 200}.60"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            asset, _ = await upsert_scan_result(
                db,
                HostScanResult(
                    host=DiscoveredHost(ip_address=ip, discovery_method="arp", mac_address="aa:bb:cc:dd:ee:01"),
                    ports=[PortResult(port=80, service="http", state="open")],
                ),
            )
            await record_passive_observation(
                db,
                asset=asset,
                source="dhcp_log",
                event_type="lease",
                summary=f"Observed DHCP lease for {ip}",
                details={"ip": ip, "hostname": "lab-client", "mac": "aa:bb:cc:dd:ee:01"},
            )
            await db.commit()

            asset, _ = await upsert_scan_result(
                db,
                HostScanResult(
                    host=DiscoveredHost(ip_address=ip, discovery_method="syn", mac_address="aa:bb:cc:dd:ee:01"),
                    ports=[PortResult(port=443, service="https", state="open")],
                ),
            )
            await db.commit()

            observations = (await db.execute(select(PassiveObservation).where(PassiveObservation.asset_id == asset.id))).scalars().all()
            evidence = (await db.execute(select(AssetEvidence).where(AssetEvidence.asset_id == asset.id))).scalars().all()

            assert len(observations) == 1
            assert observations[0].source == "dhcp_log"
            assert any(row.source == "dhcp_log" and row.key == "observed_hostname" and row.value == "lab-client" for row in evidence)
            assert any(row.source == "dhcp_log" and row.key == "passive_lease" for row in evidence)
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()
