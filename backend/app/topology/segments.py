from __future__ import annotations

from ipaddress import ip_address, ip_network

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, NetworkSegment


def infer_ipv4_segment_cidr(ip_value: str | None) -> str | None:
    if not ip_value:
        return None
    try:
        candidate = ip_address(ip_value)
    except ValueError:
        return None
    if candidate.version != 4 or not candidate.is_private:
        return None
    network = ip_network(f"{candidate}/24", strict=False)
    return str(network)


def infer_topology_role(asset: Asset, gateway_ids: set[str] | None = None) -> tuple[str, float]:
    effective_type = (asset.effective_device_type or "unknown").lower()
    hostname = (asset.hostname or "").lower()
    gateway_ids = gateway_ids or set()

    if str(asset.id) in gateway_ids:
        return "gateway", 0.9
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
    open_ports = {port.port_number for port in asset.ports if port.state == "open"}

    if effective_type in {"router", "firewall"}:
        score += 0.7
    elif effective_type == "access_point":
        score += 0.2

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


def pick_gateway_candidates(assets: list[Asset]) -> dict[str, Asset]:
    grouped: dict[str, list[Asset]] = {}
    for asset in assets:
        cidr = infer_ipv4_segment_cidr(asset.ip_address)
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
    source: str = "heuristic_ipv4_24",
) -> NetworkSegment | None:
    cidr = infer_ipv4_segment_cidr(asset.ip_address)
    if cidr is None:
        return None

    result = await db.execute(select(NetworkSegment).where(NetworkSegment.cidr == cidr))
    segment = result.scalar_one_or_none() if result is not None else None
    if segment is not None:
        return segment

    segment = NetworkSegment(
        cidr=cidr,
        label=cidr,
        source=source,
        confidence=0.55,
        segment_metadata={"inferred_from": "asset_ipv4_private_address"},
    )
    db.add(segment)
    return segment
