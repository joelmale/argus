"""
SNMP Probe

SNMP sysDescr (OID 1.3.6.1.2.1.1.1.0) is arguably the single most informative
field for device identification. Real-world examples:

  "Linux proxmox 5.15.30-2-pve #1 SMP PVE 5.15.30-3 Thu Apr 14..."
  "Cisco IOS Software, C2960 Software (C2960-LANLITEK9-M), Version 15.0..."
  "MikroTik RouterOS 7.13.2"
  "Synology DiskStation NAS"
  "HP LaserJet Pro M404dn, ROM 002.2210B"
  "DD-WRT v3.0-r48900 std (c) 2023 NewMedia-NET GmbH"
  "FreeBSD truenas.local 13.1-RELEASE-p6 FreeBSD 13.1-RELEASE-p6..."

Uses pysnmp for SNMP v2c queries with async support.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.scanner.snmp import SnmpPoller
from app.scanner.models import ProbeResult, SnmpProbeData

log = logging.getLogger(__name__)

# Core OIDs we want to query
OIDS = {
    "sys_descr":     "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime":    "1.3.6.1.2.1.1.3.0",
    "sys_contact":   "1.3.6.1.2.1.1.4.0",
    "sys_name":      "1.3.6.1.2.1.1.5.0",
    "sys_location":  "1.3.6.1.2.1.1.6.0",
}


async def probe(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 5.0,
    version: str = "2c",
    v3_username: str | None = None,
    v3_auth_key: str | None = None,
    v3_priv_key: str | None = None,
    v3_auth_protocol: str | None = None,
    v3_priv_protocol: str | None = None,
) -> ProbeResult:
    """Query SNMP MIB-II system group."""
    t0 = time.monotonic()

    try:
        poller = SnmpPoller(
            community=community,
            version=version,
            timeout=int(timeout),
            v3_username=v3_username,
            v3_auth_key=v3_auth_key,
            v3_priv_key=v3_priv_key,
            v3_auth_protocol=v3_auth_protocol,
            v3_priv_protocol=v3_priv_protocol,
        )
        system_info, interfaces, arp_table, neighbors, wireless_clients = await asyncio.wait_for(
            asyncio.gather(
                poller.get_system_info(ip),
                poller.get_interfaces(ip),
                poller.get_arp_table(ip),
                poller.get_neighbors(ip),
                poller.get_wireless_clients(ip),
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return ProbeResult(probe_type="snmp", success=False, error="Timeout")
    except Exception as exc:
        return ProbeResult(probe_type="snmp", success=False, error=str(exc)[:200])

    data = SnmpProbeData(
        sys_descr=system_info.get("sys_descr"),
        sys_name=system_info.get("sys_name"),
        sys_location=system_info.get("sys_location"),
        sys_contact=system_info.get("sys_contact"),
        sys_object_id=system_info.get("sys_object_id"),
        interfaces=interfaces,
        arp_table=arp_table,
        neighbors=neighbors,
        wireless_clients=wireless_clients,
    )

    if not data.sys_descr and not data.sys_name:
        return ProbeResult(
            probe_type="snmp", success=False,
            duration_ms=round((time.monotonic() - t0) * 1000, 1),
            error="No SNMP response (device may not support SNMP or community string is wrong)",
        )

    raw = (
        f"sysDescr: {data.sys_descr or 'n/a'}\n"
        f"sysName: {data.sys_name or 'n/a'}\n"
        f"sysLocation: {data.sys_location or 'n/a'}\n"
        f"sysContact: {data.sys_contact or 'n/a'}\n"
        f"sysObjectID: {data.sys_object_id or 'n/a'}\n"
        f"Interfaces: {len(data.interfaces)}\n"
        f"ARP entries: {len(data.arp_table)}\n"
        f"Neighbors: {len(data.neighbors)}\n"
        f"Wireless clients: {len(data.wireless_clients)}"
    )

    return ProbeResult(
        probe_type="snmp",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )
