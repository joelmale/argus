from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, TopologyLink, WirelessAssociation
from app.topology.segments import ensure_segment_for_asset


async def infer_topology_links_from_snmp(
    db: AsyncSession,
    source_asset: Asset,
    snmp_data: dict,
) -> int:
    arp_entries = snmp_data.get("arp_table") or []
    bridge_entries = snmp_data.get("bridge_table") or []
    interfaces = snmp_data.get("interfaces") or []
    neighbors = snmp_data.get("neighbors") or []
    wireless_clients = snmp_data.get("wireless_clients") or []
    if not arp_entries and not bridge_entries and not neighbors and not wireless_clients:
        return 0

    interface_map = {item.get("if_index"): item for item in interfaces if item.get("if_index") is not None}
    source_segment = await ensure_segment_for_asset(db, source_asset)
    created = 0
    created += await _process_arp_entries(db, source_asset, arp_entries, interface_map, source_segment.id if source_segment else None)
    created += await _process_bridge_entries(db, source_asset, bridge_entries, interface_map, source_segment.id if source_segment else None)
    created += await _process_neighbor_entries(db, source_asset, neighbors, source_segment.id if source_segment else None)
    created += await _process_wireless_clients(db, source_asset, wireless_clients, source_segment.id if source_segment else None)
    return created


async def _process_arp_entries(
    db: AsyncSession,
    source_asset: Asset,
    arp_entries: list[dict],
    interface_map: dict,
    segment_id: int | None,
) -> int:
    created = 0
    for entry in arp_entries:
        target_asset = await _resolve_asset_by_ip_or_mac(db, entry.get("ip"), entry.get("mac"))
        if target_asset is None or target_asset.id == source_asset.id:
            continue
        interface = interface_map.get(entry.get("if_index"), {})
        metadata = {
            "source": "snmp_arp",
            "interface": interface.get("name"),
            "if_index": entry.get("if_index"),
            "target_mac": entry.get("mac"),
            "relationship_type": "arp_seen_by",
            "observed": False,
            "confidence": 0.35,
            "segment_id": segment_id,
        }
        created += await _upsert_topology_link(
            db,
            source_asset.id,
            target_asset.id,
            "snmp_arp",
            metadata,
            vlan_id=interface.get("vlan_id"),
        )
    return created


async def _process_bridge_entries(
    db: AsyncSession,
    source_asset: Asset,
    bridge_entries: list[dict],
    interface_map: dict,
    segment_id: int | None,
) -> int:
    created = 0
    for entry in bridge_entries:
        target_mac = entry.get("mac")
        if not target_mac:
            continue
        target_asset = await _resolve_asset_by_ip_or_mac(db, None, target_mac)
        if target_asset is None or target_asset.id == source_asset.id:
            continue
        interface = interface_map.get(entry.get("if_index"), {})
        metadata = {
            "source": "snmp_bridge",
            "interface": interface.get("name"),
            "if_index": entry.get("if_index"),
            "bridge_port": entry.get("bridge_port"),
            "target_mac": target_mac,
            "relationship_type": "switch_port_for",
            "observed": True,
            "confidence": 0.92,
            "segment_id": segment_id,
        }
        created += await _upsert_topology_link(
            db,
            source_asset.id,
            target_asset.id,
            "ethernet",
            metadata,
            vlan_id=interface.get("vlan_id"),
        )
    return created


async def _process_neighbor_entries(db: AsyncSession, source_asset: Asset, neighbors: list[dict], segment_id: int | None) -> int:
    created = 0
    for neighbor in neighbors:
        target_asset = await _resolve_asset_by_hostname_or_mac(db, neighbor.get("remote_name"), neighbor.get("remote_mac"))
        if target_asset is None or target_asset.id == source_asset.id:
            continue
        link_type = neighbor.get("protocol") or "l2"
        metadata = {
            "source": link_type,
            "local_port": neighbor.get("local_port"),
            "remote_name": neighbor.get("remote_name"),
            "remote_port": neighbor.get("remote_port"),
            "remote_platform": neighbor.get("remote_platform"),
            "relationship_type": "neighbor_l2",
            "observed": True,
            "confidence": 0.95,
            "segment_id": segment_id,
        }
        created += await _upsert_topology_link(db, source_asset.id, target_asset.id, link_type, metadata)
    return created


async def _process_wireless_clients(db: AsyncSession, source_asset: Asset, wireless_clients: list[dict], segment_id: int | None) -> int:
    created = 0
    for client in wireless_clients:
        client_asset = await _resolve_asset_by_ip_or_mac(db, client.get("ip"), client.get("mac"))
        association, association_created = await _upsert_wireless_association(db, source_asset, client, client_asset)
        created += association_created
        if client_asset is None:
            continue
        metadata = {
            "source": association.source,
            "ssid": association.ssid,
            "band": association.band,
            "signal_dbm": association.signal_dbm,
            "relationship_type": "wireless_ap_for",
            "observed": True,
            "confidence": 0.98,
            "segment_id": segment_id,
        }
        created += await _upsert_topology_link(db, source_asset.id, client_asset.id, "wifi", metadata)
    return created


async def _resolve_asset_by_ip_or_mac(db: AsyncSession, ip_address: str | None, mac_address: str | None) -> Asset | None:
    conditions = []
    if ip_address:
        conditions.append(Asset.ip_address == ip_address)
    if mac_address:
        conditions.append(Asset.mac_address == mac_address)
    return await _resolve_asset(db, conditions)


async def _resolve_asset_by_hostname_or_mac(db: AsyncSession, hostname: str | None, mac_address: str | None) -> Asset | None:
    conditions = []
    if mac_address:
        conditions.append(Asset.mac_address == mac_address)
    if hostname:
        conditions.append(Asset.hostname == hostname)
    return await _resolve_asset(db, conditions)


async def _resolve_asset(db: AsyncSession, conditions: list) -> Asset | None:
    if not conditions:
        return None
    return (await db.execute(select(Asset).where(or_(*conditions)))).scalar_one_or_none()


async def _upsert_topology_link(
    db: AsyncSession,
    source_id,
    target_id,
    link_type: str,
    metadata: dict,
    *,
    vlan_id=None,
) -> int:
    relationship_type = metadata.get("relationship_type") or link_type
    observed = bool(metadata.get("observed", False))
    confidence = metadata.get("confidence")
    confidence_value = float(confidence) if confidence is not None else 0.5
    source_value = metadata.get("source") or "inference"
    segment_id = metadata.get("segment_id")
    local_interface = metadata.get("local_port") or metadata.get("interface")
    remote_interface = metadata.get("remote_port")
    ssid = metadata.get("ssid")

    existing = await db.execute(
        select(TopologyLink).where(
            and_(
                TopologyLink.source_id == source_id,
                TopologyLink.target_id == target_id,
                TopologyLink.link_type == link_type,
            )
        )
    )
    link = existing.scalar_one_or_none()
    if link is None:
        db.add(
            TopologyLink(
                source_id=source_id,
                target_id=target_id,
                link_type=link_type,
                relationship_type=relationship_type,
                observed=observed,
                confidence=confidence_value,
                source=source_value,
                evidence=metadata,
                segment_id=segment_id,
                local_interface=local_interface,
                remote_interface=remote_interface,
                ssid=ssid,
                vlan_id=vlan_id,
                link_metadata=metadata,
            )
        )
        return 1
    link.relationship_type = relationship_type or link.relationship_type
    link.observed = observed if "observed" in metadata else bool(link.observed)
    link.confidence = confidence_value if confidence is not None or link.confidence is None else link.confidence
    link.source = source_value or link.source
    link.evidence = metadata
    link.segment_id = segment_id
    link.local_interface = local_interface
    link.remote_interface = remote_interface
    link.ssid = ssid
    link.vlan_id = vlan_id
    link.link_metadata = metadata
    return 0


async def _upsert_wireless_association(
    db: AsyncSession,
    source_asset: Asset,
    client: dict,
    client_asset: Asset | None,
) -> tuple[WirelessAssociation, int]:
    result = await db.execute(
        select(WirelessAssociation).where(
            WirelessAssociation.access_point_asset_id == source_asset.id,
            WirelessAssociation.client_mac == client.get("mac"),
        )
    )
    association = result.scalar_one_or_none()
    if association is None:
        association = WirelessAssociation(
            access_point_asset_id=source_asset.id,
            client_asset_id=client_asset.id if client_asset else None,
            client_mac=client.get("mac"),
            client_ip=client.get("ip"),
            ssid=client.get("ssid"),
            band=client.get("band"),
            signal_dbm=client.get("signal_dbm"),
            source=client.get("source") or "snmp",
        )
        db.add(association)
        return association, 1

    association.client_asset_id = client_asset.id if client_asset else None
    association.client_ip = client.get("ip")
    association.ssid = client.get("ssid")
    association.band = client.get("band")
    association.signal_dbm = client.get("signal_dbm")
    association.source = client.get("source") or association.source
    return association, 0
