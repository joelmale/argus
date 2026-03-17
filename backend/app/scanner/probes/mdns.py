"""
mDNS / Bonjour Probe

mDNS (Multicast DNS, RFC 6762) runs on 224.0.0.251:5353 and is used by:
- Apple devices (AirDrop, AirPlay, iTunes sharing)
- IoT devices (Chromecast, smart speakers, cameras)
- Network printers (IPP, AirPrint)
- Linux desktops (Avahi)
- Home automation hubs

A device's mDNS announcements often reveal exact model names.
For example, a Chromecast announces "_googlecast._tcp" with properties
including its model name and friendly name.

This probe uses the zeroconf library to query and listen for service
announcements from a specific IP address.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.scanner.models import MdnsProbeData, ProbeResult

log = logging.getLogger(__name__)

# Service types to query — each one maps to a class of devices
QUERY_SERVICES = [
    "_http._tcp.local.",            # Web UIs
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",             # Samba / NAS
    "_afpovertcp._tcp.local.",      # AFP (Apple/Mac NAS)
    "_nfs._tcp.local.",             # NFS shares
    "_ipp._tcp.local.",             # AirPrint printers
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_googlecast._tcp.local.",      # Chromecast / Google devices
    "_airplay._tcp.local.",         # Apple AirPlay
    "_appletv-v2._tcp.local.",      # Apple TV
    "_raop._tcp.local.",            # AirPlay audio
    "_homekit._tcp.local.",         # HomeKit accessories
    "_hap._tcp.local.",             # HomeKit Accessory Protocol
    "_workstation._tcp.local.",     # Avahi workstation
    "_device-info._tcp.local.",     # Apple device info
    "_sleep-proxy._udp.local.",     # Apple Sleep Proxy
    "_nut._tcp.local.",             # UPS monitoring
    "_mqtt._tcp.local.",            # MQTT broker
    "_esphomelib._tcp.local.",      # ESPHome devices
    "_axis-video._tcp.local.",      # Axis IP cameras
]


async def probe(ip: str, timeout: float = 6.0) -> ProbeResult:
    """Query mDNS for service announcements from a specific IP."""
    t0 = time.monotonic()

    try:
        data = await asyncio.wait_for(_query_mdns(ip), timeout=timeout)
    except asyncio.TimeoutError:
        data = MdnsProbeData()
    except ImportError:
        return ProbeResult(
            probe_type="mdns", success=False,
            error="zeroconf not installed — pip install zeroconf",
        )
    except Exception as exc:
        return ProbeResult(probe_type="mdns", success=False, error=str(exc)[:200])

    if not data.services:
        return ProbeResult(
            probe_type="mdns", success=False,
            duration_ms=round((time.monotonic() - t0) * 1000, 1),
            error="No mDNS services found for this host",
        )

    raw = "\n".join(
        f"{s.get('type','?')} | {s.get('name','?')} | {s.get('host','?')}:{s.get('port','?')} | {s.get('properties',{})}"
        for s in data.services
    )

    return ProbeResult(
        probe_type="mdns",
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )


async def _query_mdns(target_ip: str) -> MdnsProbeData:
    """Use zeroconf to browse services and filter by IP."""
    from zeroconf.asyncio import AsyncZeroconf

    data = MdnsProbeData()
    found: list[dict] = []

    azc = AsyncZeroconf()
    try:
        # Browse all service types and collect info for our target IP
        for svc_type in QUERY_SERVICES:
            try:
                infos = await azc.async_get_service_info(svc_type, svc_type, timeout=1000)
                # async_get_service_info returns None or ServiceInfo
                if infos is None:
                    continue
                # Filter by target IP
                addresses = infos.parsed_scoped_addresses()
                if target_ip not in addresses:
                    continue
                props = {}
                for k, v in (infos.properties or {}).items():
                    key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                    val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v) if v else ""
                    props[key] = val
                found.append({
                    "type": svc_type.rstrip("."),
                    "name": infos.name,
                    "host": infos.server,
                    "port": infos.port,
                    "properties": props,
                })
            except Exception:
                continue
    finally:
        await azc.async_close()

    data.services = found
    return data
