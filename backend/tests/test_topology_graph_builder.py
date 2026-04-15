from __future__ import annotations

from uuid import uuid4

import pytest

from app.db.models import Asset, AssetTag, NetworkSegment, Port, TopologyLink
from app.topology.graph_builder import build_topology_graph
from app.topology.segments import infer_topology_role


def _asset(
    ip: str,
    *,
    device_type: str | None = None,
    hostname: str | None = None,
    ports: list[int] | None = None,
    tags: list[str] | None = None,
    avg_latency_ms: float | None = None,
    ttl_distance: int | None = None,
):
    asset = Asset(
        id=uuid4(),
        ip_address=ip,
        hostname=hostname,
        device_type=device_type,
        status="online",
        avg_latency_ms=avg_latency_ms,
        ttl_distance=ttl_distance,
    )
    asset.ports = [
        Port(asset_id=asset.id, port_number=port, protocol="tcp", state="open")
        for port in (ports or [])
    ]
    asset.tags = [AssetTag(asset_id=asset.id, tag=tag) for tag in (tags or [])]
    return asset


def test_graph_builder_assigns_layout_hints_and_infers_gateway_edges():
    gateway = _asset("192.168.100.1", device_type="router", hostname="gateway", ports=[53, 67, 80, 443])
    endpoint = _asset("192.168.100.20", device_type="workstation", hostname="desktop", ports=[22])
    nas = _asset("192.168.100.30", device_type="nas", hostname="nas-1", ports=[22, 443])
    segment = NetworkSegment(id=1, cidr="192.168.100.0/24", label="Main LAN", source="heuristic_ipv4_24", confidence=0.55)

    graph = build_topology_graph([gateway, endpoint, nas], [segment], [])

    nodes = {node["data"]["id"]: node["data"] for node in graph["nodes"]}
    edges = [edge["data"] for edge in graph["edges"]]

    assert nodes[str(gateway.id)]["layout_tier"] == "gateway"
    assert nodes[str(endpoint.id)]["layout_tier"] == "endpoint"
    assert nodes[str(gateway.id)]["is_gateway"] is True
    assert any(edge["relationship_type"] == "gateway_for" and edge["observed"] is False for edge in edges)
    assert all(edge["segment_id"] == 1 for edge in edges)


def test_graph_builder_preserves_observed_links_without_duplicate_inferred_edges():
    gateway = _asset("192.168.100.1", device_type="router", hostname="gateway", ports=[53, 67, 80, 443])
    ap = _asset("192.168.100.2", device_type="access_point", hostname="ap-living-room", ports=[80, 443])
    phone = _asset("192.168.100.40", device_type="iot_device", hostname="phone")
    segment = NetworkSegment(id=1, cidr="192.168.100.0/24", label="Main LAN", source="heuristic_ipv4_24", confidence=0.55)
    observed_link = TopologyLink(
        id=1,
        source_id=ap.id,
        target_id=phone.id,
        link_type="wifi",
        relationship_type="wireless_ap_for",
        observed=True,
        confidence=0.98,
        source="snmp",
        segment_id=1,
        ssid="Argus",
        vlan_id=None,
        evidence={"source": "snmp"},
    )

    graph = build_topology_graph([gateway, ap, phone], [segment], [observed_link])
    edge_pairs = {(edge["data"]["source"], edge["data"]["target"], edge["data"]["relationship_type"]) for edge in graph["edges"]}

    assert (str(ap.id), str(phone.id), "wireless_ap_for") in edge_pairs
    assert (str(gateway.id), str(phone.id), "gateway_for") not in edge_pairs


def test_graph_builder_infers_wireless_parent_before_gateway_fallback():
    gateway = _asset("192.168.100.1", device_type="router", hostname="gateway", ports=[53, 67, 80, 443])
    ap = _asset("192.168.100.2", device_type="unknown", hostname="ap-living-room", tags=["access-point"])
    phone = _asset("192.168.100.40", device_type="iot_device", hostname="phone", tags=["wifi"])
    segment = NetworkSegment(id=1, cidr="192.168.100.0/24", label="Main LAN", source="heuristic_ipv4_24", confidence=0.55)

    graph = build_topology_graph([gateway, ap, phone], [segment], [])
    edge_pairs = {(edge["data"]["source"], edge["data"]["target"], edge["data"]["relationship_type"]) for edge in graph["edges"]}
    wireless_edge = next(
        edge["data"]
        for edge in graph["edges"]
        if edge["data"]["source"] == str(ap.id) and edge["data"]["target"] == str(phone.id)
    )

    assert (str(ap.id), str(phone.id), "inferred_wireless") in edge_pairs
    assert (str(gateway.id), str(phone.id), "gateway_for") not in edge_pairs
    assert wireless_edge["observed"] is False
    assert wireless_edge["source_kind"] == "heuristic_same_segment_wifi_ap"


def test_graph_builder_serializes_latency_tier_hint_and_ttl_distance():
    endpoint = _asset("192.168.100.20", device_type="workstation", avg_latency_ms=1.2, ttl_distance=0)
    segment = NetworkSegment(id=1, cidr="192.168.100.0/24", label="Main LAN", source="heuristic_ipv4_24", confidence=0.55)

    graph = build_topology_graph([endpoint], [segment], [])
    node = graph["nodes"][0]["data"]

    assert node["avg_latency_ms"] == pytest.approx(1.2)
    assert node["ttl_distance"] == 0
    assert node["tier_hint"] == "tier_1_local"


def test_tagged_infrastructure_roles_have_full_confidence():
    switch = _asset("192.168.100.10", device_type="unknown", tags=["switch"])
    ap = _asset("192.168.100.11", device_type="unknown", tags=["access-point"])

    assert infer_topology_role(switch) == ("switch", 1.0)
    assert infer_topology_role(ap) == ("access_point", 1.0)
