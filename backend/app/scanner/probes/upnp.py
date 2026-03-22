"""
UPnP / SSDP Device Discovery Probe

UPnP (Universal Plug and Play) is used by most consumer networking gear,
smart TVs, media servers, and IoT devices. The device description XML
often contains exact model information:
  - "NETGEAR Nighthawk R8000"
  - "Synology DiskStation DS920+"
  - "Roku Streaming Stick"
  - "Amazon Echo"

Phase 1: Send M-SEARCH SSDP broadcast to find devices.
Phase 2: Fetch the device description XML from the discovered location header.
Phase 3: Parse manufacturer, model, serial from the XML.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from xml.etree import ElementTree as ET

import httpx

from app.scanner.models import ProbeResult, UpnpProbeData

log = logging.getLogger(__name__)


def _upnp_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context

SSDP_MULTICAST = ("239.255.255.255", 1900)
SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    'HOST: 239.255.255.255:1900\r\n'
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode()

# UPnP XML namespaces
NS = {
    "upnp": "urn:schemas-upnp-org:device-1-0",
    "": "urn:schemas-upnp-org:device-1-0",
}


async def probe(ip: str, port: int = 1900, timeout: float = 6.0) -> ProbeResult:
    """
    Probe a device for UPnP device description.
    First tries direct SSDP query, then falls back to common description URLs.
    """
    t0 = time.monotonic()

    # Strategy 1: SSDP discovery — find the description URL
    try:
        async with asyncio.timeout(timeout):
            location = await _ssdp_discover(ip, timeout=min(timeout / 2, 3.0))

            # Strategy 2: Try common description paths if SSDP didn't respond
            if not location:
                location = await _try_common_paths(ip)

            if not location:
                return ProbeResult(
                    probe_type="upnp", success=False,
                    duration_ms=round((time.monotonic() - t0) * 1000, 1),
                    error="No UPnP device description found",
                )

            # Fetch and parse the description XML
            data = await _fetch_description(location, timeout=4.0)
            if data is None:
                return ProbeResult(
                    probe_type="upnp", success=False,
                    duration_ms=round((time.monotonic() - t0) * 1000, 1),
                    error=f"Failed to parse device description at {location}",
                )
    except TimeoutError:
        return ProbeResult(
            probe_type="upnp", success=False,
            duration_ms=round((time.monotonic() - t0) * 1000, 1),
            error="Timeout",
        )

    raw = (
        f"Location: {location}\n"
        f"Friendly name: {data.friendly_name}\n"
        f"Manufacturer: {data.manufacturer}\n"
        f"Model: {data.model_name} {data.model_number or ''}\n"
        f"Serial: {data.serial_number}\n"
        f"Device type: {data.device_type}"
    )

    return ProbeResult(
        probe_type="upnp",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )


async def _ssdp_discover(target_ip: str, timeout: float) -> str | None:
    """Send SSDP M-SEARCH and wait for a response from target_ip."""
    loop = asyncio.get_event_loop()

    class _SsdpProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.location: str | None = None
            self.event = asyncio.Event()

        def datagram_received(self, data: bytes, addr: tuple):
            if addr[0] != target_ip:
                return
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if line.upper().startswith("LOCATION:"):
                    self.location = line.split(":", 1)[1].strip()
                    self.event.set()
                    break

        def error_received(self, exc):
            # Datagram errors are expected when targets ignore SSDP discovery.
            pass

    proto = _SsdpProtocol()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: proto,
            remote_addr=SSDP_MULTICAST,
            family=socket.AF_INET,
        )
        transport.sendto(SSDP_SEARCH)
        async with asyncio.timeout(timeout):
            await proto.event.wait()
        transport.close()
        return proto.location
    except Exception:
        return None


async def _try_common_paths(ip: str) -> str | None:
    """Try common UPnP device description URL patterns."""
    candidates = [
        f"http://{ip}:49152/desc.xml",
        f"http://{ip}:1400/xml/device_description.xml",   # Sonos
        f"http://{ip}:8200/rootDesc.xml",                  # MiniDLNA
        f"http://{ip}:5000/rootDesc.xml",
        f"http://{ip}:52235/dmr/SamsungMRDesc.xml",        # Samsung TV
    ]
    async with httpx.AsyncClient(timeout=2.0, verify=_upnp_ssl_context()) as client:
        for url in candidates:
            try:
                r = await client.get(url)
                if r.status_code == 200 and "xml" in r.headers.get("content-type", ""):
                    return url
            except Exception:
                continue
    return None


async def _fetch_description(location: str, timeout: float) -> UpnpProbeData | None:
    """Fetch and parse UPnP device description XML."""
    try:
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(timeout=None, verify=_upnp_ssl_context()) as client:
                resp = await client.get(location)
                if resp.status_code != 200:
                    return None
                return _parse_xml(resp.text)
    except Exception:
        return None


def _parse_xml(xml_text: str) -> UpnpProbeData:
    data = UpnpProbeData()
    try:
        root = ET.fromstring(xml_text)
        # Handle namespace-prefixed elements
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        device = root.find(f"{ns}device")
        if device is None:
            device = root

        def _find(tag: str) -> str | None:
            el = device.find(f"{ns}{tag}")
            return el.text.strip() if el is not None and el.text else None

        data.friendly_name   = _find("friendlyName")
        data.manufacturer    = _find("manufacturer")
        data.model_name      = _find("modelName")
        data.model_number    = _find("modelNumber")
        data.serial_number   = _find("serialNumber")
        data.device_type     = _find("deviceType")
        data.udn             = _find("UDN")
        data.presentation_url = _find("presentationURL")
    except ET.ParseError:
        pass
    return data
