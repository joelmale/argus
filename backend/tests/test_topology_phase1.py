from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.routes import topology as topology_routes
from app.db.models import Asset, NetworkSegment, Port, TopologyLink
from app.modules import tplink_deco
from app.modules import unifi as unifi_module
from app.modules.tplink_deco import DecoClientRecord
from app.modules.unifi import UnifiClientRecord
from app.topology.segments import ensure_segment_for_asset, infer_ipv4_segment_cidr, pick_gateway_candidates, score_gateway_candidate


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeDb:
    def __init__(self, results):
        self._results = list(results)
        self.added = []

    async def execute(self, _stmt):
        return _ScalarResult(self._results.pop(0))

    def add(self, item):
        self.added.append(item)


def _asset(ip: str, *, device_type: str | None = None, hostname: str | None = None, ports: list[int] | None = None):
    asset = Asset(
        id=uuid4(),
        ip_address=ip,
        hostname=hostname,
        device_type=device_type,
        status="online",
    )
    asset.ports = [
        Port(asset_id=asset.id, port_number=port, protocol="tcp", state="open")
        for port in (ports or [])
    ]
    return asset


def test_infer_ipv4_segment_cidr_respects_configured_prefix():
    assert infer_ipv4_segment_cidr("192.168.100.17") == "192.168.100.0/24"
    assert infer_ipv4_segment_cidr("192.168.100.17", 23) == "192.168.100.0/23"
    assert infer_ipv4_segment_cidr("10.1.2.3") == "10.1.2.0/24"
    assert infer_ipv4_segment_cidr("8.8.8.8") is None
    assert infer_ipv4_segment_cidr("not-an-ip") is None


def test_gateway_scoring_prefers_router_like_assets():
    gateway = _asset("192.168.100.1", device_type="router", hostname="gateway", ports=[53, 67, 80, 443])
    server = _asset("192.168.100.10", device_type="server", hostname="proxmox", ports=[22, 8006])

    winners = pick_gateway_candidates([gateway, server])

    assert score_gateway_candidate(gateway) > score_gateway_candidate(server)
    assert winners["192.168.100.0/24"].id == gateway.id


@pytest.mark.asyncio
async def test_ensure_segment_for_asset_creates_segment_once():
    asset = _asset("192.168.100.25", device_type="server")
    db = _FakeDb([[]])

    segment = await ensure_segment_for_asset(db, asset, prefix_v4=23)

    assert segment is not None
    assert segment.cidr == "192.168.100.0/23"
    assert any(isinstance(item, NetworkSegment) for item in db.added)


@pytest.mark.asyncio
async def test_topology_graph_exposes_segments_gateway_roles_and_edge_metadata():
    gateway = _asset("192.168.100.1", device_type="router", hostname="gateway", ports=[53, 67, 80, 443])
    endpoint = _asset("192.168.100.50", device_type="workstation", hostname="desktop", ports=[22])
    segment = NetworkSegment(id=1, cidr="192.168.100.0/24", label="192.168.100.0/24", source="heuristic_ipv4_24", confidence=0.55)
    link = TopologyLink(
        id=1,
        source_id=gateway.id,
        target_id=endpoint.id,
        link_type="wifi",
        relationship_type="wireless_ap_for",
        observed=True,
        confidence=0.98,
        source="snmp",
        segment_id=segment.id,
        ssid="Argus",
        vlan_id=None,
    )
    db = _FakeDb([[gateway, endpoint], [segment], [link]])

    async def fake_read_effective_scanner_config(_db):
        return SimpleNamespace(), SimpleNamespace(topology_default_segment_prefix_v4=24)

    topology_routes.read_effective_scanner_config = fake_read_effective_scanner_config
    payload = await topology_routes.get_topology_graph(db, SimpleNamespace())

    assert payload["segments"][0]["cidr"] == "192.168.100.0/24"
    assert any(node["data"]["is_gateway"] for node in payload["nodes"])
    assert payload["edges"][0]["data"]["relationship_type"] == "wireless_ap_for"
    assert payload["edges"][0]["data"]["observed"] is True
    assert payload["edges"][0]["data"]["confidence"] == pytest.approx(0.98)


@pytest.mark.asyncio
async def test_unifi_client_ap_mac_creates_observed_topology_link(monkeypatch):
    access_point = _asset("192.168.100.2", device_type="access_point", hostname="ap-living-room")
    access_point.mac_address = "AA:AA:AA:AA:AA:AA"
    client_asset = _asset("192.168.100.40", device_type="iot_device", hostname="phone")
    client_asset.mac_address = "BB:BB:BB:BB:BB:BB"
    segment = SimpleNamespace(id=7)
    captured = {}

    async def fake_resolve_asset(db, *, mac, ip, hostname):
        assert mac == access_point.mac_address
        assert ip is None
        assert hostname is None
        return access_point

    async def fake_ensure_segment_for_asset(db, asset, source=None):
        assert asset is access_point
        assert source == "unifi"
        return segment

    async def fake_upsert_topology_link(db, source_id, target_id, link_type, metadata):
        captured.update(
            {
                "source_id": source_id,
                "target_id": target_id,
                "link_type": link_type,
                "metadata": metadata,
            }
        )
        return 1

    monkeypatch.setattr(unifi_module, "_resolve_asset", fake_resolve_asset)
    monkeypatch.setattr(unifi_module, "ensure_segment_for_asset", fake_ensure_segment_for_asset)
    monkeypatch.setattr(unifi_module, "_upsert_topology_link", fake_upsert_topology_link)

    count = await unifi_module._upsert_unifi_client_topology_link(
        SimpleNamespace(),
        client_asset,
        UnifiClientRecord(
            mac=client_asset.mac_address,
            ip=client_asset.ip_address,
            hostname=client_asset.hostname,
            ap_mac=access_point.mac_address,
            ssid="Argus",
            is_wired=False,
            raw={},
        ),
    )

    assert count == 1
    assert captured["source_id"] == access_point.id
    assert captured["target_id"] == client_asset.id
    assert captured["link_type"] == "wifi"
    assert captured["metadata"]["relationship_type"] == "wireless_ap_for"
    assert captured["metadata"]["observed"] is True
    assert captured["metadata"]["segment_id"] == segment.id


@pytest.mark.asyncio
async def test_tplink_client_ap_name_creates_observed_topology_link(monkeypatch):
    access_point = _asset("192.168.100.3", device_type="access_point", hostname="Deco Office")
    client_asset = _asset("192.168.100.41", device_type="iot_device", hostname="tablet")
    client_asset.mac_address = "CC:CC:CC:CC:CC:CC"
    segment = SimpleNamespace(id=8)
    captured = {}

    async def fake_ensure_segment_for_asset(db, asset, source=None):
        assert asset is access_point
        assert source == "tplink_deco"
        return segment

    async def fake_upsert_topology_link(db, source_id, target_id, link_type, metadata):
        captured.update(
            {
                "source_id": source_id,
                "target_id": target_id,
                "link_type": link_type,
                "metadata": metadata,
            }
        )
        return 1

    monkeypatch.setattr(tplink_deco, "ensure_segment_for_asset", fake_ensure_segment_for_asset)
    monkeypatch.setattr(tplink_deco, "_upsert_topology_link", fake_upsert_topology_link)

    count = await tplink_deco._upsert_deco_client_topology_link(
        SimpleNamespace(),
        client_asset,
        DecoClientRecord(
            mac=client_asset.mac_address,
            ip=client_asset.ip_address,
            hostname=client_asset.hostname,
            nickname=None,
            device_model=None,
            connection_type="wireless",
            access_point_name="Deco Office",
            raw={},
        ),
        {"deco office": access_point},
    )

    assert count == 1
    assert captured["source_id"] == access_point.id
    assert captured["target_id"] == client_asset.id
    assert captured["link_type"] == "wifi"
    assert captured["metadata"]["relationship_type"] == "wireless_ap_for"
    assert captured["metadata"]["observed"] is True
    assert captured["metadata"]["segment_id"] == segment.id
