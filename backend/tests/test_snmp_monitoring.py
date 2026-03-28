from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from app.db.models import Asset, ProbeRun
from app.db.session import AsyncSessionLocal
from app.scanner.models import ProbeResult
from app.scanner.snmp import SnmpPoller


@pytest.mark.asyncio
async def test_snmp_poller_collects_interface_counters_and_resource_summary(monkeypatch):
    poller = SnmpPoller(community="public", version="2c", timeout=5)

    async def fake_walk(_host: str, oid: str):
        rows = {
            "1.3.6.1.2.1.2.2.1.2": [("1.3.6.1.2.1.2.2.1.2.7", "uplink0")],
            "1.3.6.1.2.1.2.2.1.3": [("1.3.6.1.2.1.2.2.1.3.7", "6")],
            "1.3.6.1.2.1.2.2.1.5": [("1.3.6.1.2.1.2.2.1.5.7", "1000000000")],
            "1.3.6.1.2.1.31.1.1.1.15": [("1.3.6.1.2.1.31.1.1.1.15.7", "1000")],
            "1.3.6.1.2.1.2.2.1.6": [("1.3.6.1.2.1.2.2.1.6.7", "AABBCCDDEEFF")],
            "1.3.6.1.2.1.2.2.1.7": [("1.3.6.1.2.1.2.2.1.7.7", "1")],
            "1.3.6.1.2.1.2.2.1.8": [("1.3.6.1.2.1.2.2.1.8.7", "1")],
            "1.3.6.1.2.1.2.2.1.10": [("1.3.6.1.2.1.2.2.1.10.7", "1000")],
            "1.3.6.1.2.1.2.2.1.14": [("1.3.6.1.2.1.2.2.1.14.7", "2")],
            "1.3.6.1.2.1.2.2.1.16": [("1.3.6.1.2.1.2.2.1.16.7", "2000")],
            "1.3.6.1.2.1.2.2.1.20": [("1.3.6.1.2.1.2.2.1.20.7", "3")],
            "1.3.6.1.2.1.31.1.1.1.6": [("1.3.6.1.2.1.31.1.1.1.6.7", "123456789")],
            "1.3.6.1.2.1.31.1.1.1.10": [("1.3.6.1.2.1.31.1.1.1.10.7", "987654321")],
            "1.3.6.1.2.1.17.7.1.4.5.1.1": [("1.3.6.1.2.1.17.7.1.4.5.1.1.7", "20")],
            "1.3.6.1.2.1.25.3.3.1.2": [
                ("1.3.6.1.2.1.25.3.3.1.2.1", "15"),
                ("1.3.6.1.2.1.25.3.3.1.2.2", "35"),
            ],
            "1.3.6.1.2.1.25.2.3.1.3": [("1.3.6.1.2.1.25.2.3.1.3.1", "Physical memory")],
            "1.3.6.1.2.1.25.2.3.1.4": [("1.3.6.1.2.1.25.2.3.1.4.1", "1024")],
            "1.3.6.1.2.1.25.2.3.1.5": [("1.3.6.1.2.1.25.2.3.1.5.1", "1000")],
            "1.3.6.1.2.1.25.2.3.1.6": [("1.3.6.1.2.1.25.2.3.1.6.1", "500")],
        }
        return rows.get(oid, [])

    monkeypatch.setattr(poller, "_walk", fake_walk)

    interfaces = await poller.get_interfaces("192.0.2.10")
    resource_summary = await poller.get_resource_summary("192.0.2.10")

    assert interfaces == [
        {
            "if_index": 7,
            "name": "uplink0",
            "type": 6,
            "speed": 1000000000,
            "high_speed_mbps": 1000,
            "mac": "AA:BB:CC:DD:EE:FF",
            "admin_status": 1,
            "oper_status": 1,
            "in_octets": 1000,
            "in_errors": 2,
            "out_octets": 2000,
            "out_errors": 3,
            "hc_in_octets": 123456789,
            "hc_out_octets": 987654321,
            "vlan_id": 20,
            "in_octets_total": 123456789,
            "out_octets_total": 987654321,
        }
    ]
    assert resource_summary == {
        "cpu_loads": [15, 35],
        "cpu_core_count": 2,
        "cpu_average_load": 25.0,
        "memory_label": "Physical memory",
        "memory_total_bytes": 1024000,
        "memory_used_bytes": 512000,
        "memory_utilization": 0.5,
    }


@pytest.mark.asyncio
async def test_asset_snmp_refresh_route_appends_probe_runs_and_flips_asset_online(api_client, admin_user, monkeypatch):
    ip_address = f"10.252.{uuid4().int % 200}.40"
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        await db.execute(delete(Asset).where(Asset.ip_address == ip_address))
        await db.commit()

        asset = Asset(
            ip_address=ip_address,
            hostname="edge-router",
            vendor="Test Vendor",
            status="offline",
            first_seen=now,
            last_seen=now,
            heartbeat_last_checked_at=now,
        )
        db.add(asset)
        await db.flush()
        db.add(
            ProbeRun(
                asset_id=asset.id,
                probe_type="http",
                target_port=443,
                success=True,
                duration_ms=11.0,
                summary="web ui",
                details={"title": "Device UI"},
                raw_excerpt="HTTP/1.1 200 OK",
                observed_at=now,
            )
        )
        asset_uuid = asset.id
        asset_id = str(asset.id)
        await db.commit()

    async def fake_read_effective_scanner_config(_db):
        return object(), SimpleNamespace(
            snmp_enabled=True,
            snmp_version="2c",
            snmp_community="public",
            snmp_timeout=7,
            snmp_v3_username="",
            snmp_v3_auth_key="",
            snmp_v3_priv_key="",
            snmp_v3_auth_protocol="sha",
            snmp_v3_priv_protocol="aes",
        )

    async def fake_snmp_probe(
        ip: str,
        community: str = "public",
        port: int = 161,
        version: str = "2c",
        timeout_seconds: float = 5.0,
        **_kwargs,
    ):
        assert ip == ip_address
        assert community == "public"
        assert version == "2c"
        assert timeout_seconds == 7
        return ProbeResult(
            probe_type="snmp",
            target_port=port,
            success=True,
            duration_ms=12.5,
            data={
                "sys_descr": "Test RouterOS",
                "sys_name": "edge-router",
                "sys_object_id": "1.3.6.1.4.1.9999.1",
                "interfaces": [{"if_index": 7, "name": "uplink0", "vlan_id": 20}],
                "neighbors": [{"protocol": "lldp", "remote_name": "core-switch"}],
                "arp_table": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "if_index": 7}],
                "resource_summary": {"cpu_average_load": 21.0},
            },
            raw="sysDescr: Test RouterOS",
        )

    calls: list[tuple[str, dict]] = []

    async def fake_infer_topology_links_from_snmp(_db, asset, probe_data):
        calls.append((str(asset.id), probe_data))
        return 0

    monkeypatch.setattr("app.api.routes.assets.read_effective_scanner_config", fake_read_effective_scanner_config)
    monkeypatch.setattr("app.scanner.probes.snmp.probe", fake_snmp_probe)
    monkeypatch.setattr("app.scanner.topology.infer_topology_links_from_snmp", fake_infer_topology_links_from_snmp)

    response = await api_client.post(
        f"/api/v1/assets/{asset_id}/snmp-refresh",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "online"
    assert body["probe_runs"][0]["probe_type"] == "snmp"
    assert body["probe_runs"][0]["summary"] == "Test RouterOS"
    assert any(row["probe_type"] == "http" for row in body["probe_runs"])
    assert calls and calls[0][0] == asset_id
    assert calls[0][1]["sys_name"] == "edge-router"

    async with AsyncSessionLocal() as db:
        persisted = (
            await db.execute(
                select(ProbeRun).where(ProbeRun.asset_id == asset_uuid)
            )
        ).scalars().all()

        assert len(persisted) == 2
        assert {row.probe_type for row in persisted} == {"http", "snmp"}
