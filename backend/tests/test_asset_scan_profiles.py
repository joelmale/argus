from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.routes import assets as assets_routes
from app.db.models import Asset
from app.scanner.models import ScanProfile


class _FakeDb:
    def __init__(self):
        self.added = []
        self.committed = False
        self.refreshed = False

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        self.committed = True

    async def refresh(self, _item):
        self.refreshed = True


async def _completed(value):
    return value


@pytest.mark.asyncio
async def test_asset_port_scan_queues_deep_enrichment(monkeypatch):
    asset = Asset(id=uuid4(), ip_address="192.168.100.5", status="online")
    db = _FakeDb()

    monkeypatch.setattr(assets_routes, "_load_asset", lambda db, asset_id: _completed(asset))
    monkeypatch.setattr(assets_routes, "_next_queue_position", lambda db: _completed(1))
    monkeypatch.setattr(assets_routes, "_has_active_scan", lambda db: _completed(False))

    queued = []
    monkeypatch.setattr(assets_routes.run_scan_job, "delay", lambda job_id: queued.append(job_id))

    response = await assets_routes.run_asset_port_scan(asset.id, db, object())

    assert response["status"] == "started"
    assert len(db.added) == 1
    assert db.added[0].scan_type == ScanProfile.DEEP_ENRICHMENT.value
    assert "deep port scan" in db.added[0].result_summary["message"]
    assert queued


@pytest.mark.asyncio
async def test_asset_ai_refresh_uses_deep_enrichment(monkeypatch):
    asset = Asset(id=uuid4(), ip_address="192.168.100.5", status="online", vendor="Synology")
    db = _FakeDb()
    profiles: list[ScanProfile] = []

    monkeypatch.setattr(assets_routes, "_load_asset", lambda db, asset_id: _completed(asset))
    monkeypatch.setattr(assets_routes, "read_effective_scanner_config", lambda db: _completed((None, SimpleNamespace())))

    async def fake_scan_host(host, profile):
        profiles.append(profile)
        return [], SimpleNamespace()

    async def fake_investigate_host(**kwargs):
        profiles.append(kwargs["profile"])
        return SimpleNamespace(
            host=SimpleNamespace(ip_address=asset.ip_address, mac_address=None),
            ports=[],
            os_fingerprint=SimpleNamespace(os_name=None),
            mac_vendor=asset.vendor,
            reverse_hostname=None,
            ai_analysis=None,
            probes=[],
            open_ports=[],
        )

    monkeypatch.setattr(assets_routes.portscan, "scan_host", fake_scan_host)
    monkeypatch.setattr(assets_routes, "_investigate_host", fake_investigate_host)
    monkeypatch.setattr(assets_routes, "_serialize_asset", lambda loaded_asset: {"id": str(loaded_asset.id)})
    monkeypatch.setattr(assets_routes, "get_analyst", lambda runtime_config: None)

    async def fake_upsert_scan_result(db, result):
        return asset, "updated"

    import sys
    monkeypatch.setitem(
        sys.modules,
        "app.db.upsert",
        SimpleNamespace(upsert_scan_result=fake_upsert_scan_result),
    )

    await assets_routes.run_asset_ai_refresh(asset.id, db, object())

    assert profiles == [ScanProfile.DEEP_ENRICHMENT, ScanProfile.DEEP_ENRICHMENT]
