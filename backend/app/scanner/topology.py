from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, TopologyLink, WirelessAssociation


async def infer_topology_links_from_snmp(
    db: AsyncSession,
    source_asset: Asset,
    snmp_data: dict,
) -> int:
    arp_entries = snmp_data.get("arp_table") or []
    interfaces = snmp_data.get("interfaces") or []
    neighbors = snmp_data.get("neighbors") or []
    wireless_clients = snmp_data.get("wireless_clients") or []
    if not arp_entries and not neighbors and not wireless_clients:
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

    for neighbor in neighbors:
        remote_name = neighbor.get("remote_name")
        remote_mac = neighbor.get("remote_mac")
        stmt = select(Asset)
        conditions = []
        if remote_mac:
            conditions.append(Asset.mac_address == remote_mac)
        if remote_name:
            conditions.append(Asset.hostname == remote_name)
        if not conditions:
            continue

        target_asset = (await db.execute(stmt.where(or_(*conditions)))).scalar_one_or_none()
        if target_asset is None or target_asset.id == source_asset.id:
            continue

        link_type = neighbor.get("protocol") or "l2"
        existing = await db.execute(
            select(TopologyLink).where(
                TopologyLink.source_id == source_asset.id,
                TopologyLink.target_id == target_asset.id,
                TopologyLink.link_type == link_type,
            )
        )
        link = existing.scalar_one_or_none()
        metadata = {
            "source": link_type,
            "local_port": neighbor.get("local_port"),
            "remote_name": remote_name,
            "remote_port": neighbor.get("remote_port"),
            "remote_platform": neighbor.get("remote_platform"),
        }
        if link is None:
            db.add(
                TopologyLink(
                    source_id=source_asset.id,
                    target_id=target_asset.id,
                    link_type=link_type,
                    link_metadata=metadata,
                )
            )
            created += 1
        else:
            link.link_metadata = metadata

    for client in wireless_clients:
        client_ip = client.get("ip")
        client_mac = client.get("mac")
        conditions = []
        if client_ip:
            conditions.append(Asset.ip_address == client_ip)
        if client_mac:
            conditions.append(Asset.mac_address == client_mac)
        client_asset = None
        if conditions:
            client_asset = (await db.execute(select(Asset).where(or_(*conditions)))).scalar_one_or_none()

        result = await db.execute(
            select(WirelessAssociation).where(
                WirelessAssociation.access_point_asset_id == source_asset.id,
                WirelessAssociation.client_mac == client_mac,
            )
        )
        association = result.scalar_one_or_none()
        if association is None:
            association = WirelessAssociation(
                access_point_asset_id=source_asset.id,
                client_asset_id=client_asset.id if client_asset else None,
                client_mac=client_mac,
                client_ip=client_ip,
                ssid=client.get("ssid"),
                band=client.get("band"),
                signal_dbm=client.get("signal_dbm"),
                source=client.get("source") or "snmp",
            )
            db.add(association)
            created += 1
        else:
            association.client_asset_id = client_asset.id if client_asset else None
            association.client_ip = client_ip
            association.ssid = client.get("ssid")
            association.band = client.get("band")
            association.signal_dbm = client.get("signal_dbm")
            association.source = client.get("source") or association.source

        if client_asset is not None:
            existing = await db.execute(
                select(TopologyLink).where(
                    TopologyLink.source_id == source_asset.id,
                    TopologyLink.target_id == client_asset.id,
                    TopologyLink.link_type == "wifi",
                )
            )
            link = existing.scalar_one_or_none()
            metadata = {
                "source": association.source,
                "ssid": association.ssid,
                "band": association.band,
                "signal_dbm": association.signal_dbm,
            }
            if link is None:
                db.add(
                    TopologyLink(
                        source_id=source_asset.id,
                        target_id=client_asset.id,
                        link_type="wifi",
                        link_metadata=metadata,
                    )
                )
                created += 1
            else:
                link.link_metadata = metadata

    return created
