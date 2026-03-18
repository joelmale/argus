from __future__ import annotations

import uuid

import pytest

from app.db.models import Asset, ScanJob, ScannerConfig
from app.db.session import AsyncSessionLocal
from app.scanner.config import (
    AUTO_TARGET_SENTINEL,
    clear_inventory,
    has_meaningful_scan_evidence,
    resolve_scan_targets,
    should_enqueue_scheduled_scan,
)
from app.scanner.models import DiscoveredHost, HostScanResult, PortResult


@pytest.mark.asyncio
async def test_clear_inventory_removes_assets_and_optional_scan_history():
    async with AsyncSessionLocal() as db:
        asset = Asset(ip_address=f"10.255.{uuid.uuid4().int % 200}.10", status="online")
        scan = ScanJob(targets="10.255.0.0/24", scan_type="balanced", triggered_by="manual")
        db.add_all([asset, scan])
        await db.commit()

        result = await clear_inventory(db, include_scan_history=True)
        await db.commit()

        assert result["assets_deleted"] >= 1
        assert result["scans_deleted"] >= 1
        assert await db.get(Asset, asset.id) is None
        assert await db.get(ScanJob, scan.id) is None


def test_resolve_scan_targets_uses_auto_sentinel_when_enabled():
    config = ScannerConfig(auto_detect_targets=True, default_targets=None, default_profile="balanced", interval_minutes=60, concurrent_hosts=10)

    assert resolve_scan_targets(config, None) == AUTO_TARGET_SENTINEL
    assert resolve_scan_targets(config, "192.168.96.0/20") == "192.168.96.0/20"


def test_should_enqueue_scheduled_scan_respects_enablement():
    enabled = ScannerConfig(enabled=True, auto_detect_targets=True, default_profile="balanced", interval_minutes=60, concurrent_hosts=10)
    disabled = ScannerConfig(enabled=False, auto_detect_targets=True, default_profile="balanced", interval_minutes=60, concurrent_hosts=10)

    assert should_enqueue_scheduled_scan(enabled) is True
    assert should_enqueue_scheduled_scan(disabled) is False


def test_has_meaningful_scan_evidence_rejects_empty_ping_noise():
    weak = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.55", discovery_method="ping"))
    strong = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.56", discovery_method="ping"),
        ports=[PortResult(port=443, protocol="tcp", state="open", service="https")],
    )

    assert has_meaningful_scan_evidence(weak) is False
    assert has_meaningful_scan_evidence(strong) is True


def test_has_meaningful_scan_evidence_rejects_os_fingerprint_only_noise():
    weak = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.57", discovery_method="ping"),
        os_fingerprint={"os_name": "Sanyo PLC-XU88 digital projector", "os_accuracy": 92},
    )

    assert has_meaningful_scan_evidence(weak) is False
