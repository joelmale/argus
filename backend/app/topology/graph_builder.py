from __future__ import annotations

from collections import defaultdict

from app.db.models import Asset, NetworkSegment, TopologyLink
from app.topology.segments import infer_ipv4_segment_cidr, infer_topology_role, pick_gateway_candidates


def build_topology_graph(
    assets: list[Asset],
    segments: list[NetworkSegment],
    links: list[TopologyLink],
    *,
    prefix_v4: int = 24,
) -> dict:
    gateway_candidates = pick_gateway_candidates(assets, prefix_v4)
    gateway_ids = {str(asset.id) for asset in gateway_candidates.values()}
    segment_by_cidr = {segment.cidr: segment for segment in segments}
    segment_assets: dict[str, list[Asset]] = defaultdict(list)

    for asset in assets:
        cidr = infer_ipv4_segment_cidr(asset.ip_address, prefix_v4)
        if cidr:
            segment_assets[cidr].append(asset)

    nodes = [
        {"data": _serialize_node(asset, segment_by_cidr, gateway_ids, prefix_v4)}
        for asset in assets
    ]

    persisted_edges = [
        {"data": _serialize_link(link)}
        for link in links
        if not link.suppressed
    ]
    inferred_edges = _build_inferred_gateway_edges(segment_assets, segment_by_cidr, persisted_edges, gateway_candidates)

    serialized_segments = [
        _serialize_segment(segment, gateway_candidates.get(segment.cidr))
        for segment in segments
    ]

    return {"nodes": nodes, "edges": persisted_edges + inferred_edges, "segments": serialized_segments}


def _serialize_node(asset: Asset, segment_by_cidr: dict[str, NetworkSegment], gateway_ids: set[str], prefix_v4: int) -> dict:
    segment_cidr = infer_ipv4_segment_cidr(asset.ip_address, prefix_v4)
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
        "tier_hint": _tier_hint_for_asset(asset),
        "avg_latency_ms": asset.avg_latency_ms,
        "ttl_distance": asset.ttl_distance,
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
    parented_asset_ids = {
        edge["data"]["target"]
        for edge in persisted_edges
        if _edge_is_parent_evidence(edge["data"])
    }
    inferred_edges = []

    for cidr, assets in segment_assets.items():
        gateway = gateway_candidates.get(cidr)
        segment = segment_by_cidr.get(cidr)
        segment_id = segment.id if segment else None
        vlan_id = segment.vlan_id if segment else None
        access_points = [
            asset
            for asset in assets
            if infer_topology_role(asset, {str(gateway.id)} if gateway else set())[0] == "access_point"
        ]

        for asset in assets:
            if str(asset.id) in parented_asset_ids:
                continue
            if gateway is not None and asset.id == gateway.id:
                continue
            if _is_wifi_asset(asset):
                access_point = _choose_access_point_parent(asset, access_points)
                if access_point is not None:
                    pair = (str(access_point.id), str(asset.id))
                    reverse_pair = (str(asset.id), str(access_point.id))
                    if pair not in linked_pairs and reverse_pair not in linked_pairs:
                        inferred_edges.append(
                            {
                                "data": {
                                    "id": f"inferred-wireless-{access_point.id}-{asset.id}",
                                    "source": str(access_point.id),
                                    "target": str(asset.id),
                                    "link_type": "inferred",
                                    "relationship_type": "inferred_wireless",
                                    "observed": False,
                                    "confidence": 0.58,
                                    "source_kind": "heuristic_same_segment_wifi_ap",
                                    "segment_id": segment_id,
                                    "local_interface": None,
                                    "remote_interface": None,
                                    "ssid": None,
                                    "vlan_id": vlan_id,
                                    "layout_tier": "distribution",
                                    "evidence": {
                                        "source": "heuristic_same_segment_wifi_ap",
                                        "segment": cidr,
                                        "reason": "wifi-tagged asset without observed parent; selected same-segment access point",
                                    },
                                }
                            }
                        )
                        linked_pairs.add(pair)
                        parented_asset_ids.add(str(asset.id))
                        continue

            if gateway is None:
                continue
            pair = (str(gateway.id), str(asset.id))
            reverse_pair = (str(asset.id), str(gateway.id))
            if pair in linked_pairs or reverse_pair in linked_pairs:
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
                        "segment_id": segment_id,
                        "local_interface": None,
                        "remote_interface": None,
                        "ssid": None,
                        "vlan_id": vlan_id,
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


def _tier_hint_for_asset(asset: Asset) -> str | None:
    if asset.avg_latency_ms is None:
        return None
    if asset.avg_latency_ms < 2:
        return "tier_1_local"
    if asset.avg_latency_ms < 10:
        return "tier_2_near"
    return "tier_3_remote"


def _edge_layout_tier(relationship_type: str | None) -> str:
    if relationship_type in {"gateway_for", "uplink"}:
        return "gateway"
    if relationship_type in {"neighbor_l2", "wireless_ap_for", "inferred_wireless", "switch_port_for"}:
        return "distribution"
    return "endpoint"


def _edge_is_parent_evidence(edge: dict) -> bool:
    if edge.get("relationship_type") == "gateway_for":
        return False
    return bool(edge.get("observed")) or float(edge.get("confidence") or 0) >= 0.7


def _asset_tag_names(asset: Asset) -> set[str]:
    return {tag.tag.lower() for tag in getattr(asset, "tags", []) if getattr(tag, "tag", None)}


def _is_wifi_asset(asset: Asset) -> bool:
    tags = _asset_tag_names(asset)
    return "wifi" in tags or "wireless" in tags


def build_topology_summary(
    assets: list[Asset],
    segments: list[NetworkSegment],
    links: list[TopologyLink],
    *,
    prefix_v4: int = 24,
) -> dict:
    """Lightweight graph summary — counts only, no node/edge serialization."""
    active_links = [link for link in links if not link.suppressed]
    observed = sum(1 for link in active_links if link.observed)
    return {
        "node_count": len(assets),
        "edge_count": len(active_links),
        "observed_edge_count": observed,
        "inferred_edge_count": len(active_links) - observed,
        "segment_count": len(segments),
    }


def build_neighborhood_graph(
    focal_asset_id: str,
    assets: list[Asset],
    segments: list[NetworkSegment],
    links: list[TopologyLink],
    *,
    prefix_v4: int = 24,
) -> dict:
    """Return the focal node plus its immediate parents and children."""
    active_links = [link for link in links if not link.suppressed]
    neighbor_ids: set[str] = {focal_asset_id}
    neighborhood_edges: list[TopologyLink] = []
    for link in active_links:
        src, tgt = str(link.source_id), str(link.target_id)
        if src == focal_asset_id or tgt == focal_asset_id:
            neighborhood_edges.append(link)
            neighbor_ids.add(src)
            neighbor_ids.add(tgt)

    neighbor_assets = [asset for asset in assets if str(asset.id) in neighbor_ids]
    gateway_candidates = pick_gateway_candidates(neighbor_assets, prefix_v4)
    gateway_ids = {str(asset.id) for asset in gateway_candidates.values()}
    segment_by_cidr = {segment.cidr: segment for segment in segments}

    nodes = [
        {"data": _serialize_node(asset, segment_by_cidr, gateway_ids, prefix_v4)}
        for asset in neighbor_assets
    ]
    edges = [{"data": _serialize_link(link)} for link in neighborhood_edges]
    visible_segment_ids = {
        node["data"].get("segment_id") for node in nodes if node["data"].get("segment_id") is not None
    }
    visible_segments = [
        _serialize_segment(segment, gateway_candidates.get(segment.cidr))
        for segment in segments
        if segment.id in visible_segment_ids
    ]
    return {"nodes": nodes, "edges": edges, "segments": visible_segments}


def build_segment_graph(
    segment_id: int,
    assets: list[Asset],
    segments: list[NetworkSegment],
    links: list[TopologyLink],
    *,
    prefix_v4: int = 24,
) -> dict:
    """Return nodes, edges, and segment info for a single network segment."""
    active_links = [link for link in links if not link.suppressed]
    segment = next((s for s in segments if s.id == segment_id), None)
    if segment is None:
        return {"nodes": [], "edges": [], "segments": []}

    segment_assets = [
        asset for asset in assets
        if infer_ipv4_segment_cidr(asset.ip_address, prefix_v4) == segment.cidr
    ]
    segment_asset_ids = {str(asset.id) for asset in segment_assets}
    segment_links = [
        link for link in active_links
        if str(link.source_id) in segment_asset_ids and str(link.target_id) in segment_asset_ids
    ]

    gateway_candidates = pick_gateway_candidates(segment_assets, prefix_v4)
    gateway_ids = {str(asset.id) for asset in gateway_candidates.values()}
    segment_by_cidr = {segment.cidr: segment}

    nodes = [
        {"data": _serialize_node(asset, segment_by_cidr, gateway_ids, prefix_v4)}
        for asset in segment_assets
    ]
    edges = [{"data": _serialize_link(link)} for link in segment_links]
    serialized_segments = [_serialize_segment(segment, gateway_candidates.get(segment.cidr))]
    return {"nodes": nodes, "edges": edges, "segments": serialized_segments}


def _choose_access_point_parent(asset: Asset, access_points: list[Asset]) -> Asset | None:
    candidates = [access_point for access_point in access_points if access_point.id != asset.id]
    if not candidates:
        return None
    tagged = [access_point for access_point in candidates if {"access-point", "access_point"} & _asset_tag_names(access_point)]
    if tagged:
        return tagged[0]
    return candidates[0]
