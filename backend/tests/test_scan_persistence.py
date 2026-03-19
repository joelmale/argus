from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

from app.db.models import Asset, AssetEvidence, ProbeRun
from app.db.session import AsyncSessionLocal
from app.db.upsert import upsert_scan_result
from app.scanner.models import AIAnalysis, DeviceClass, DiscoveredHost, HostScanResult, OSFingerprint, PortResult


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
            assert asset.device_type_source == "unknown"
            assert asset.vendor is None

            persisted = (await db.execute(select(Asset).where(Asset.ip_address == ip))).scalar_one()
            assert persisted.os_name is None
            assert persisted.device_type is None
            assert persisted.device_type_source == "unknown"
            assert persisted.vendor is None
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()


@pytest.mark.asyncio
async def test_upsert_uses_rule_based_classification_when_ai_is_weak():
    ip = f"10.254.{uuid.uuid4().int % 200}.30"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            result = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="syn"),
                ports=[
                    PortResult(port=80, service="http", state="open"),
                    PortResult(port=443, service="https", state="open"),
                    PortResult(port=161, service="snmp", state="open"),
                    PortResult(port=22, service="ssh", state="open"),
                ],
                mac_vendor="TP-Link",
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.UNKNOWN,
                    confidence=0.2,
                    investigation_notes="No confident AI conclusion",
                ),
            )

            asset, _ = await upsert_scan_result(db, result)
            await db.commit()

            assert asset.device_type == "access_point"
            assert asset.device_type_source == "rule"
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()


@pytest.mark.asyncio
async def test_manual_device_type_override_survives_scan_updates():
    ip = f"10.254.{uuid.uuid4().int % 200}.40"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            first = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="syn"),
                ports=[PortResult(port=9100, service="jetdirect", state="open")],
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.PRINTER,
                    confidence=0.95,
                    investigation_notes="JetDirect service",
                ),
            )
            asset, _ = await upsert_scan_result(db, first)
            asset.device_type_override = "server"
            await db.commit()

            second = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="syn"),
                ports=[PortResult(port=9100, service="jetdirect", state="open")],
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.PRINTER,
                    confidence=0.99,
                    investigation_notes="Still a printer",
                ),
            )
            updated, _ = await upsert_scan_result(db, second)
            await db.commit()

            assert updated.device_type == "printer"
            assert updated.device_type_override == "server"
            assert updated.effective_device_type == "server"
            assert updated.effective_device_type_source == "manual"
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()


@pytest.mark.asyncio
async def test_upsert_persists_fingerprinting_evidence_and_probe_snapshot():
    ip = f"10.254.{uuid.uuid4().int % 200}.50"

    async with AsyncSessionLocal() as db:
        try:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()

            result = HostScanResult(
                host=DiscoveredHost(ip_address=ip, discovery_method="arp", ttl=64, mac_address="AA:BB:CC:DD:EE:FF"),
                mac_vendor="Ubiquiti Networks",
                reverse_hostname="ap-lab.local",
                ports=[
                    PortResult(port=80, service="http", state="open"),
                    PortResult(port=443, service="https", state="open"),
                    PortResult(port=161, service="snmp", state="open"),
                ],
                ai_analysis=AIAnalysis(
                    device_class=DeviceClass.ACCESS_POINT,
                    confidence=0.91,
                    vendor="Ubiquiti",
                    investigation_notes="Strong AP evidence",
                ),
                probes=[
                    {
                        "probe_type": "http",
                        "target_port": 80,
                        "success": True,
                        "duration_ms": 25.0,
                        "data": {"server": "nginx", "title": "UniFi Network"},
                        "raw": "HTTP/1.1 200 OK",
                    },
                    {
                        "probe_type": "snmp",
                        "target_port": 161,
                        "success": True,
                        "duration_ms": 18.0,
                        "data": {"sys_descr": "UAP-AC-LR", "sys_name": "ap-lab"},
                    },
                ],
            )

            asset, _ = await upsert_scan_result(db, result)
            await db.commit()

            evidence_rows = (
                await db.execute(select(AssetEvidence).where(AssetEvidence.asset_id == asset.id))
            ).scalars().all()
            probe_rows = (
                await db.execute(select(ProbeRun).where(ProbeRun.asset_id == asset.id))
            ).scalars().all()

            assert asset.device_type == "access_point"
            assert asset.device_type_source == "ai"
            assert any(row.category == "device_type" and row.value == "access_point" for row in evidence_rows)
            assert any(row.category == "vendor" and "Ubiquiti" in row.value for row in evidence_rows)
            assert any(row.probe_type == "http" and row.success for row in probe_rows)
            assert any(row.probe_type == "snmp" and row.summary == "UAP-AC-LR" for row in probe_rows)
        finally:
            await db.execute(delete(Asset).where(Asset.ip_address == ip))
            await db.commit()
