from __future__ import annotations

from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, NetworkSegment


def normalize_topology_prefix_v4(prefix_v4: int | None) -> int:
    if prefix_v4 is None:
        return 24
    return max(8, min(30, int(prefix_v4)))


def infer_ipv4_segment_cidr(ip_value: str | None, prefix_v4: int = 24) -> str | None:
    if not ip_value:
        return None
    try:
        candidate = ip_address(ip_value)
    except ValueError:
        return None
    if candidate.version != 4 or not candidate.is_private:
        return None
    network = ip_network(f"{candidate}/{normalize_topology_prefix_v4(prefix_v4)}", strict=False)
    return str(network)


def infer_topology_role(asset: Asset, gateway_ids: set[str] | None = None) -> tuple[str, float]:
    effective_type = (asset.effective_device_type or "unknown").lower()
    hostname = (asset.hostname or "").lower()
    tags = _asset_tag_names(asset)
    gateway_ids = gateway_ids or set()

    if str(asset.id) in gateway_ids:
        return "gateway", 0.9
    if "switch" in tags:
        return "switch", 1.0
    if "access-point" in tags or "access_point" in tags:
        return "access_point", 1.0
    if effective_type in {"router", "firewall"}:
        return "gateway_candidate", 0.8
    if effective_type == "switch":
        return "switch", 0.85
    if effective_type == "access_point":
        return "access_point", 0.85
    if "gateway" in hostname or "router" in hostname:
        return "gateway_candidate", 0.7
    if effective_type in {"server", "nas"}:
        return "infrastructure", 0.55
    return "endpoint", 0.6


def score_gateway_candidate(asset: Asset) -> float:
    score = 0.0
    effective_type = (asset.effective_device_type or "unknown").lower()
    hostname = (asset.hostname or "").lower()
    vendor = (asset.vendor or "").lower()
    tags = _asset_tag_names(asset)
    open_ports = {port.port_number for port in asset.ports if port.state == "open"}

    if effective_type in {"router", "firewall"}:
        score += 0.7
    elif effective_type == "access_point":
        score += 0.2
    elif effective_type == "switch":
        score += 0.16

    if "switch" in tags:
        score += 0.18
    if "access-point" in tags or "access_point" in tags:
        score += 0.14

    if any(token in vendor for token in ("ubiquiti", "unifi", "tp-link", "tplink")):
        if tags & {"access-point", "access_point", "switch", "unifi", "tplink", "tp-link"}:
            score += 0.12

    if 53 in open_ports:
        score += 0.08
    if 67 in open_ports or 68 in open_ports:
        score += 0.12
    if 80 in open_ports or 443 in open_ports:
        score += 0.05
    if 22 in open_ports:
        score += 0.03

    for token, bonus in (
        ("gateway", 0.2),
        ("router", 0.18),
        ("firewall", 0.18),
        ("opnsense", 0.2),
        ("pfsense", 0.2),
        ("deco", 0.12),
    ):
        if token in hostname:
            score += bonus

    return min(score, 1.0)


def _asset_tag_names(asset: Asset) -> set[str]:
    return {tag.tag.lower() for tag in getattr(asset, "tags", []) if getattr(tag, "tag", None)}


def pick_gateway_candidates(assets: list[Asset], prefix_v4: int = 24) -> dict[str, Asset]:
    grouped: dict[str, list[Asset]] = {}
    for asset in assets:
        cidr = infer_ipv4_segment_cidr(asset.ip_address, prefix_v4)
        if cidr is None:
            continue
        grouped.setdefault(cidr, []).append(asset)

    winners: dict[str, Asset] = {}
    for cidr, members in grouped.items():
        ranked = sorted(members, key=score_gateway_candidate, reverse=True)
        if ranked and score_gateway_candidate(ranked[0]) >= 0.55:
            winners[cidr] = ranked[0]
    return winners


async def ensure_segment_for_asset(
    db: AsyncSession,
    asset: Asset,
    *,
    prefix_v4: int = 24,
    source: str | None = None,
) -> NetworkSegment | None:
    normalized_prefix = normalize_topology_prefix_v4(prefix_v4)
    cidr = infer_ipv4_segment_cidr(asset.ip_address, normalized_prefix)
    if cidr is None:
        return None

    result = await db.execute(select(NetworkSegment).where(NetworkSegment.cidr == cidr))
    segment = result.scalar_one_or_none() if result is not None else None
    if segment is not None:
        return segment

    segment = NetworkSegment(
        cidr=cidr,
        label=cidr,
        source=source or f"heuristic_ipv4_{normalized_prefix}",
        confidence=0.55,
        segment_metadata={"inferred_from": "asset_ipv4_private_address", "prefix_v4": normalized_prefix},
    )
    db.add(segment)
    return segment
