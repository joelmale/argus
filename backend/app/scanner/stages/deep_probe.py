"""
Stage 4 — Deep Probe Dispatcher

Orchestrates targeted protocol-specific probes for a single host.
Runs all applicable probes concurrently (asyncio.gather) with individual
timeouts so a slow device doesn't hold up the pipeline.

The probe selection is driven by the fingerprint stage's priority list,
but we also run opportunistic probes for any service clearly visible in
the port scan (e.g. always probe TLS if port 443 is open).
"""
from __future__ import annotations

import asyncio
import logging

from app.scanner.models import DiscoveredHost, PortResult, ProbeResult, ScanProfile

log = logging.getLogger(__name__)

# Per-probe timeout in seconds — network latency + device response time
PROBE_TIMEOUTS = {
    "http":  6.0,
    "tls":   5.0,
    "ssh":   5.0,
    "snmp":  5.0,
    "mdns":  7.0,
    "upnp":  7.0,
    "smb":   8.0,
}


async def run(
    host: DiscoveredHost,
    ports: list[PortResult],
    priority_probes: list[str],
    profile: ScanProfile = ScanProfile.BALANCED,
) -> list[ProbeResult]:
    """
    Run all applicable probes for a host concurrently.
    Returns list of ProbeResult (both successes and failures).
    """
    ip = host.ip_address
    open_port_nums = {p.port: p for p in ports if p.state == "open"}

    # Build the probe task list
    tasks: list[tuple[str, asyncio.Task]] = []

    # Always run DNS
    tasks.append(("dns", asyncio.create_task(_dns_probe(ip))))

    # HTTP probes — one per web port found
    web_ports = {
        80: False, 8080: False, 8000: False, 8008: False, 8888: False,
        443: True, 8443: True, 4443: True,
    }
    for port_num, use_https in web_ports.items():
        if port_num in open_port_nums:
            label = "https" if use_https else "http"
            timeout = PROBE_TIMEOUTS.get("http", 6.0)
            tasks.append((label, asyncio.create_task(
                _with_timeout(
                    _http_probe(ip, port_num, use_https),
                    timeout,
                    probe_type=label, port=port_num,
                )
            )))

    # TLS: run on any HTTPS port even if not in priority list
    for port_num in (443, 8443, 4443):
        if port_num in open_port_nums and "tls" not in [t[0] for t in tasks]:
            tasks.append(("tls", asyncio.create_task(
                _with_timeout(_tls_probe(ip, port_num), PROBE_TIMEOUTS["tls"], "tls", port_num)
            )))

    # SSH
    for port_num in (22, 2222):
        if port_num in open_port_nums:
            tasks.append(("ssh", asyncio.create_task(
                _with_timeout(_ssh_probe(ip, port_num), PROBE_TIMEOUTS["ssh"], "ssh", port_num)
            )))
            break

    # SNMP
    if 161 in open_port_nums or "snmp" in priority_probes:
        tasks.append(("snmp", asyncio.create_task(
            _with_timeout(_snmp_probe(ip), PROBE_TIMEOUTS["snmp"], "snmp", 161)
        )))

    # mDNS — probe if suggested or if 5353 is in port scan
    if "mdns" in priority_probes or 5353 in open_port_nums:
        tasks.append(("mdns", asyncio.create_task(
            _with_timeout(_mdns_probe(ip), PROBE_TIMEOUTS["mdns"], "mdns")
        )))

    # UPnP
    if "upnp" in priority_probes or 1900 in open_port_nums:
        tasks.append(("upnp", asyncio.create_task(
            _with_timeout(_upnp_probe(ip), PROBE_TIMEOUTS["upnp"], "upnp", 1900)
        )))

    # SMB
    for port_num in (445, 139):
        if port_num in open_port_nums:
            tasks.append(("smb", asyncio.create_task(
                _with_timeout(_smb_probe(ip, port_num), PROBE_TIMEOUTS["smb"], "smb", port_num)
            )))
            break

    if not tasks:
        return []

    log.debug("Running %d probes for %s: %s", len(tasks), ip, [t[0] for t in tasks])

    # Run all probes concurrently
    results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)

    probe_results: list[ProbeResult] = []
    for (probe_name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            probe_results.append(ProbeResult(probe_type=probe_name, success=False, error=str(result)))
        elif isinstance(result, ProbeResult):
            probe_results.append(result)

    successes = sum(1 for r in probe_results if r.success)
    log.debug("Probes complete for %s: %d/%d succeeded", ip, successes, len(probe_results))

    return probe_results


# ── Probe wrappers ────────────────────────────────────────────────────────────

async def _with_timeout(coro, timeout: float, probe_type: str, port: int | None = None) -> ProbeResult:
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        return ProbeResult(probe_type=probe_type, target_port=port, success=False, error=f"Timeout after {timeout}s")


async def _dns_probe(ip: str) -> ProbeResult:
    from app.scanner.enrichment.dns_lookup import reverse_lookup
    hostname = await reverse_lookup(ip)
    return ProbeResult(
        probe_type="dns",
        success=hostname is not None,
        data={"hostname": hostname},
        raw=f"PTR: {hostname or 'no record'}",
    )


async def _http_probe(ip: str, port: int, use_https: bool) -> ProbeResult:
    from app.scanner.probes.http import probe
    return await probe(ip, port, use_https)


async def _tls_probe(ip: str, port: int) -> ProbeResult:
    from app.scanner.probes.tls import probe
    return await probe(ip, port)


async def _ssh_probe(ip: str, port: int) -> ProbeResult:
    from app.scanner.probes.ssh import probe
    return await probe(ip, port)


async def _snmp_probe(ip: str) -> ProbeResult:
    from app.scanner.probes.snmp import probe
    return await probe(ip)


async def _mdns_probe(ip: str) -> ProbeResult:
    from app.scanner.probes.mdns import probe
    return await probe(ip)


async def _upnp_probe(ip: str) -> ProbeResult:
    from app.scanner.probes.upnp import probe
    return await probe(ip)


async def _smb_probe(ip: str, port: int) -> ProbeResult:
    from app.scanner.probes.smb import probe
    return await probe(ip, port)
