from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.routes import topology as topology_routes
from app.db.models import Asset, NetworkSegment, Port, TopologyLink
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
