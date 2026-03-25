from __future__ import annotations

from collections import defaultdict

from app.db.models import Asset, NetworkSegment, TopologyLink
from app.topology.segments import infer_ipv4_segment_cidr, infer_topology_role, pick_gateway_candidates


def build_topology_graph(
    assets: list[Asset],
    segments: list[NetworkSegment],
    links: list[TopologyLink],
) -> dict:
    gateway_candidates = pick_gateway_candidates(assets)
    gateway_ids = {str(asset.id) for asset in gateway_candidates.values()}
    segment_by_cidr = {segment.cidr: segment for segment in segments}
    segment_assets: dict[str, list[Asset]] = defaultdict(list)

    for asset in assets:
        cidr = infer_ipv4_segment_cidr(asset.ip_address)
        if cidr:
            segment_assets[cidr].append(asset)

    nodes = [
        {"data": _serialize_node(asset, segment_by_cidr, gateway_ids)}
        for asset in assets
    ]

    persisted_edges = [
        {"data": _serialize_link(link)}
        for link in links
    ]
    inferred_edges = _build_inferred_gateway_edges(segment_assets, segment_by_cidr, persisted_edges, gateway_candidates)

    serialized_segments = [
        _serialize_segment(segment, gateway_candidates.get(segment.cidr))
        for segment in segments
    ]

    return {"nodes": nodes, "edges": persisted_edges + inferred_edges, "segments": serialized_segments}


def _serialize_node(asset: Asset, segment_by_cidr: dict[str, NetworkSegment], gateway_ids: set[str]) -> dict:
    segment_cidr = infer_ipv4_segment_cidr(asset.ip_address)
    segment = segment_by_cidr.get(segment_cidr or "")
    topology_role, topology_confidence = infer_topology_role(asset, gateway_ids)
    layout_tier = _layout_tier_for_role(topology_role)
    return {
        "id": str(asset.id),
        "label": asset.hostname or asset.ip_address,
        "ip": asset.ip_address,
        "vendor": asset.vendor,
        "os": asset.os_name,
        "status": asset.status,
        "device_type": asset.effective_device_type,
        "segment_cidr": segment_cidr,
        "segment_id": segment.id if segment else None,
        "topology_role": topology_role,
        "topology_confidence": topology_confidence,
        "is_gateway": str(asset.id) in gateway_ids,
        "layout_tier": layout_tier,
        "is_infrastructure": layout_tier in {"gateway", "distribution"},
    }


def _serialize_link(link: TopologyLink) -> dict:
    return {
        "id": f"e{link.id}",
        "source": str(link.source_id),
        "target": str(link.target_id),
        "link_type": link.link_type,
        "relationship_type": link.relationship_type,
        "observed": link.observed,
        "confidence": link.confidence,
        "source_kind": link.source,
        "segment_id": link.segment_id,
        "local_interface": link.local_interface,
        "remote_interface": link.remote_interface,
        "ssid": link.ssid,
        "vlan_id": link.vlan_id,
        "layout_tier": _edge_layout_tier(link.relationship_type),
        "evidence": link.evidence or link.link_metadata,
    }


def _serialize_segment(segment: NetworkSegment, gateway_asset: Asset | None) -> dict:
    return {
        "id": segment.id,
        "cidr": segment.cidr,
        "label": segment.label,
        "vlan_id": segment.vlan_id,
        "gateway_asset_id": str(segment.gateway_asset_id) if segment.gateway_asset_id else str(gateway_asset.id) if gateway_asset else None,
        "confidence": segment.confidence,
        "source": segment.source,
    }


def _build_inferred_gateway_edges(
    segment_assets: dict[str, list[Asset]],
    segment_by_cidr: dict[str, NetworkSegment],
    persisted_edges: list[dict],
    gateway_candidates: dict[str, Asset],
) -> list[dict]:
    linked_pairs = {
        (edge["data"]["source"], edge["data"]["target"])
        for edge in persisted_edges
    }
    observed_attachment_ids = {
        edge["data"]["source"]
        for edge in persisted_edges
        if edge["data"].get("observed")
    } | {
        edge["data"]["target"]
        for edge in persisted_edges
        if edge["data"].get("observed")
    }
    inferred_edges = []

    for cidr, assets in segment_assets.items():
        gateway = gateway_candidates.get(cidr)
        segment = segment_by_cidr.get(cidr)
        if gateway is None:
            continue

        for asset in assets:
            if asset.id == gateway.id:
                continue
            pair = (str(gateway.id), str(asset.id))
            reverse_pair = (str(asset.id), str(gateway.id))
            if pair in linked_pairs or reverse_pair in linked_pairs or str(asset.id) in observed_attachment_ids:
                continue
            inferred_edges.append(
                {
                    "data": {
                        "id": f"inferred-gateway-{gateway.id}-{asset.id}",
                        "source": str(gateway.id),
                        "target": str(asset.id),
                        "link_type": "inferred",
                        "relationship_type": "gateway_for",
                        "observed": False,
                        "confidence": 0.46,
                        "source_kind": "heuristic_gateway_segment",
                        "segment_id": segment.id if segment else None,
                        "local_interface": None,
                        "remote_interface": None,
                        "ssid": None,
                        "vlan_id": segment.vlan_id if segment else None,
                        "layout_tier": "gateway",
                        "evidence": {
                            "source": "heuristic_gateway_segment",
                            "segment": cidr,
                            "reason": "gateway candidate selected for segment with no stronger observed parent link",
                        },
                    }
                }
            )
    return inferred_edges


def _layout_tier_for_role(role: str) -> str:
    if role == "gateway":
        return "gateway"
    if role in {"gateway_candidate", "switch", "access_point", "infrastructure"}:
        return "distribution"
    return "endpoint"


def _edge_layout_tier(relationship_type: str | None) -> str:
    if relationship_type in {"gateway_for", "uplink"}:
        return "gateway"
    if relationship_type in {"neighbor_l2", "wireless_ap_for"}:
        return "distribution"
    return "endpoint"
