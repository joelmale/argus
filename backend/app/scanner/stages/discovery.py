"""
Stage 1 — Host Discovery

Two complementary techniques run in parallel:

1. ARP sweep (scapy)  — fast, layer-2, MAC address revealed, LAN only.
   Like shouting "who has X.X.X.X? tell me!" on the local segment.

2. ICMP ping sweep (nmap -sn) — works across routed segments, no MAC,
   but reveals hosts that ignore ARP (rare but exists in locked-down VMs).

3. Passive ARP listener — long-running background coroutine that captures
   ARP broadcasts in real time, detecting devices the moment they join.

Returns a list of DiscoveredHost objects, deduplicated by IP.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import time
from collections.abc import AsyncIterator
from xml.etree import ElementTree as ET

from app.scanner.models import DiscoveredHost

log = logging.getLogger(__name__)

DISCOVERY_SWEEP_TIMEOUT_SECONDS = 30


async def _await_with_deadline(awaitable, deadline_seconds: float):
    timeout_context = getattr(asyncio, "timeout", None)
    if timeout_context is not None:
        async with timeout_context(deadline_seconds):
            return await awaitable
    return await asyncio.wait_for(awaitable, timeout=deadline_seconds)


# ─── Active ARP + Ping sweep ────────────────────────────────────────────────

async def sweep(targets: str) -> list[DiscoveredHost]:
    """
    Discover live hosts in `targets` (CIDR or space-separated IPs).
    Runs ARP sweep and ping sweep in parallel, merges results.
    """
    log.info("Discovery sweep started: %s", targets)

    arp_task = asyncio.create_task(_arp_sweep(targets))
    ping_task = asyncio.create_task(_ping_sweep(targets))

    arp_results, ping_results = await asyncio.gather(arp_task, ping_task, return_exceptions=True)

    hosts = list(_merge_discovery_results(arp_results, ping_results).values())
    log.info("Discovery complete: %d hosts found", len(hosts))
    return hosts


def _merge_discovery_results(
    arp_results: list[DiscoveredHost] | Exception,
    ping_results: list[DiscoveredHost] | Exception,
) -> dict[str, DiscoveredHost]:
    merged: dict[str, DiscoveredHost] = {}
    for result_set, method in ((arp_results, "arp"), (ping_results, "ping")):
        if isinstance(result_set, Exception):
            log.warning("Discovery method %s failed: %s", method, result_set)
            continue
        for host in result_set:
            _merge_discovered_host(merged, host)
    return merged


def _merge_discovered_host(merged: dict[str, DiscoveredHost], host: DiscoveredHost) -> None:
    current = merged.get(host.ip_address)
    if current is None:
        merged[host.ip_address] = host
        return
    if host.mac_address and not current.mac_address:
        merged[host.ip_address] = host


async def _arp_sweep(targets: str) -> list[DiscoveredHost]:
    """
    Use scapy to send ARP requests. Runs in a thread executor since scapy
    is synchronous and uses raw sockets.

    Requires NET_RAW capability (granted in docker-compose.yml).
    """
    loop = asyncio.get_event_loop()
    return await _await_with_deadline(
        loop.run_in_executor(None, _arp_sweep_sync, targets),
        DISCOVERY_SWEEP_TIMEOUT_SECONDS,
    )


def _arp_sweep_sync(targets: str) -> list[DiscoveredHost]:
    """Synchronous ARP sweep implementation using scapy."""
    results: list[DiscoveredHost] = []
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        import ipaddress

        # Build list of IPs from CIDR or space-separated
        ips: list[str] = []
        for token in targets.replace(",", " ").split():
            try:
                net = ipaddress.ip_network(token, strict=False)
                ips.extend(str(ip) for ip in net.hosts())
            except ValueError:
                ips.append(token.strip())

        # Send ARP requests in batches to avoid timeout issues on large subnets
        BATCH = 256
        for i in range(0, len(ips), BATCH):
            batch = " ".join(ips[i : i + BATCH])
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
            t0 = time.monotonic()
            answered, _ = srp(pkt, timeout=2, verbose=False)
            for _, rcv in answered:
                results.append(DiscoveredHost(
                    ip_address=rcv.psrc,
                    mac_address=rcv.hwsrc.upper().replace(":", ":"),
                    is_up=True,
                    response_time_ms=round((time.monotonic() - t0) * 1000, 2),
                    discovery_method="arp",
                ))
    except Exception as exc:
        log.warning("ARP sweep error: %s", exc)
    return results


async def _ping_sweep(targets: str) -> list[DiscoveredHost]:
    """
    Use nmap's -sn (ping-only) scan. Fast, handles multiple CIDRs,
    works across routed segments. Runs in executor to avoid blocking.
    """
    loop = asyncio.get_event_loop()
    return await _await_with_deadline(
        loop.run_in_executor(None, _ping_sweep_sync, targets),
        DISCOVERY_SWEEP_TIMEOUT_SECONDS,
    )


def _ping_sweep_sync(targets: str) -> list[DiscoveredHost]:
    results: list[DiscoveredHost] = []
    try:
        completed = subprocess.run(
            [
                "nmap",
                "-sn",
                "-T4",
                "--host-timeout",
                f"{DISCOVERY_SWEEP_TIMEOUT_SECONDS}s",
                "-oX",
                "-",
                *targets.replace(",", " ").split(),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        results = _parse_ping_sweep_xml(completed.stdout)
    except Exception as exc:
        log.warning("Ping sweep error: %s", exc)
    return results


def _parse_ping_sweep_xml(xml_output: str) -> list[DiscoveredHost]:
    hosts: list[DiscoveredHost] = []
    root = ET.fromstring(xml_output)
    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ip_address, mac_address = _extract_host_addresses(host_node)

        if not ip_address:
            continue

        ttl = _parse_reason_ttl(status.attrib.get("reason_ttl"))

        hosts.append(
            DiscoveredHost(
                ip_address=ip_address,
                mac_address=mac_address,
                is_up=True,
                discovery_method="ping",
                ttl=ttl,
            )
        )
    return hosts


def _extract_host_addresses(host_node: ET.Element) -> tuple[str | None, str | None]:
    ip_address = None
    mac_address = None
    for address in host_node.findall("address"):
        addr_type = address.attrib.get("addrtype")
        if addr_type == "ipv4":
            ip_address = address.attrib.get("addr")
        elif addr_type == "mac":
            mac_address = address.attrib.get("addr")
    return ip_address, mac_address


def _parse_reason_ttl(reason_ttl: str | None) -> int | None:
    if not reason_ttl:
        return None
    try:
        return int(reason_ttl)
    except ValueError:
        return None


# ─── Passive ARP listener ────────────────────────────────────────────────────

class PassiveArpListener:
    """
    Long-running background listener that captures ARP broadcasts.
    Every time a device sends an ARP request/reply, we record it.

    This gives near-real-time detection of new devices without active scanning —
    like a doorbell that rings the moment anything new shows up.

    Requires: NET_RAW capability, scapy
    """

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self._running = False

    async def listen(self) -> AsyncIterator[DiscoveredHost]:
        """
        Async generator that yields DiscoveredHost whenever an ARP packet is seen.
        Run this in a background task and consume yielded hosts.
        """
        self._running = True
        queue: asyncio.Queue[DiscoveredHost] = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _packet_handler(pkt):
            try:
                from scapy.layers.l2 import ARP
                if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):  # who-has or is-at
                    host = DiscoveredHost(
                        ip_address=pkt[ARP].psrc,
                        mac_address=pkt[ARP].hwsrc.upper(),
                        is_up=True,
                        discovery_method="passive",
                    )
                    loop.call_soon_threadsafe(queue.put_nowait, host)
            except Exception:
                pass

        def _sniff():
            try:
                from scapy.sendrecv import sniff
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=_packet_handler,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except Exception as exc:
                log.error("Passive ARP listener error: %s", exc)

        # Run scapy sniff in a thread so it doesn't block the event loop
        loop.run_in_executor(None, _sniff)

        while self._running:
            try:
                async with asyncio.timeout(1.0):
                    host = await queue.get()
                yield host
            except TimeoutError:
                continue

    def stop(self):
        self._running = False
