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


async def probe(ip: str, community: str = "public", port: int = 161, timeout: float = 5.0) -> ProbeResult:
    """Query SNMP MIB-II system group."""
    t0 = time.monotonic()

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _snmp_get_sync, ip, community, port),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return ProbeResult(probe_type="snmp", success=False, error="Timeout")
    except ImportError:
        return ProbeResult(probe_type="snmp", success=False, error="pysnmp not installed")
    except Exception as exc:
        return ProbeResult(probe_type="snmp", success=False, error=str(exc)[:200])

    if data is None or (not data.sys_descr and not data.sys_name):
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
        f"sysObjectID: {data.sys_object_id or 'n/a'}"
    )

    return ProbeResult(
        probe_type="snmp",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )


def _snmp_get_sync(ip: str, community: str, port: int) -> SnmpProbeData | None:
    """Synchronous pysnmp GET for system MIB variables."""
    try:
        from pysnmp.hlapi import (
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, getCmd,
        )

        engine = SnmpEngine()
        transport = UdpTransportTarget((ip, port), timeout=3, retries=1)
        auth = CommunityData(community, mpModel=1)  # mpModel=1 → SNMPv2c

        # Build GET request for all system OIDs at once
        objects = [ObjectType(ObjectIdentity(oid)) for oid in OIDS.values()]
        error_indication, error_status, error_index, var_binds = next(
            getCmd(engine, auth, transport, ContextData(), *objects)
        )

        if error_indication or error_status:
            return None

        result = SnmpProbeData()
        oid_names = list(OIDS.keys())
        for i, var_bind in enumerate(var_binds):
            value = str(var_bind[1])
            if i < len(oid_names):
                key = oid_names[i]
                if key == "sys_descr":     result.sys_descr     = value
                elif key == "sys_name":    result.sys_name      = value
                elif key == "sys_location":result.sys_location  = value
                elif key == "sys_contact": result.sys_contact   = value
                elif key == "sys_object_id": result.sys_object_id = value

        return result

    except Exception as exc:
        log.debug("SNMP sync error: %s", exc)
        return None
