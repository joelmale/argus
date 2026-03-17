from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, TopologyLink


async def infer_topology_links_from_snmp(
    db: AsyncSession,
    source_asset: Asset,
    snmp_data: dict,
) -> int:
    arp_entries = snmp_data.get("arp_table") or []
    interfaces = snmp_data.get("interfaces") or []
    if not arp_entries:
        return 0

    interface_map = {item.get("if_index"): item for item in interfaces if item.get("if_index") is not None}
    created = 0

    for entry in arp_entries:
        ip_address = entry.get("ip")
        mac_address = entry.get("mac")
        if not ip_address and not mac_address:
            continue

        conditions = []
        if ip_address:
            conditions.append(Asset.ip_address == ip_address)
        if mac_address:
            conditions.append(Asset.mac_address == mac_address)
        if not conditions:
            continue

        stmt = select(Asset).where(or_(*conditions))
        target_asset = (await db.execute(stmt)).scalar_one_or_none()
        if target_asset is None or target_asset.id == source_asset.id:
            continue

        existing = await db.execute(
            select(TopologyLink).where(
                and_(
                    TopologyLink.source_id == source_asset.id,
                    TopologyLink.target_id == target_asset.id,
                    TopologyLink.link_type == "snmp_arp",
                )
            )
        )
        link = existing.scalar_one_or_none()

        interface = interface_map.get(entry.get("if_index"), {})
        metadata = {
            "source": "snmp_arp",
            "interface": interface.get("name"),
            "if_index": entry.get("if_index"),
            "target_mac": mac_address,
        }
        vlan_id = interface.get("vlan_id")

        if link is None:
            db.add(
                TopologyLink(
                    source_id=source_asset.id,
                    target_id=target_asset.id,
                    link_type="snmp_arp",
                    vlan_id=vlan_id,
                    link_metadata=metadata,
                )
            )
            created += 1
        else:
            link.vlan_id = vlan_id
            link.link_metadata = metadata

    return created
