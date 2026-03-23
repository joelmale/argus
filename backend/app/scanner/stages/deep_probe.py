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
    timeout_seconds: float | None = None,
) -> list[ProbeResult]:
    """
    Run all applicable probes for a host concurrently.
    Returns list of ProbeResult (both successes and failures).
    """
    ip = host.ip_address
    open_port_nums = {p.port: p for p in ports if p.state == "open"}
    effective_timeout = _normalize_probe_timeout(timeout_seconds)
    tasks = _build_probe_tasks(ip, open_port_nums, priority_probes, effective_timeout)

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


def _build_probe_tasks(
    ip: str,
    open_port_nums: dict[int, PortResult],
    priority_probes: list[str],
    effective_timeout: float | None,
) -> list[tuple[str, asyncio.Task]]:
    tasks: list[tuple[str, asyncio.Task]] = [("dns", asyncio.create_task(_dns_probe(ip)))]
    tasks.extend(_build_http_tasks(ip, open_port_nums, effective_timeout))
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "tls")
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "ssh")
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "snmp")
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "mdns")
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "upnp")
    _append_optional_probe(tasks, ip, open_port_nums, priority_probes, effective_timeout, "smb")
    return tasks


def _build_http_tasks(
    ip: str,
    open_port_nums: dict[int, PortResult],
    effective_timeout: float | None,
) -> list[tuple[str, asyncio.Task]]:
    tasks: list[tuple[str, asyncio.Task]] = []
    for port_num, use_https in _web_ports().items():
        if port_num not in open_port_nums:
            continue
        label = "https" if use_https else "http"
        tasks.append(
            (
                label,
                asyncio.create_task(
                    _with_timeout(
                        _http_probe(ip, port_num, use_https),
                        _resolve_probe_timeout("http", effective_timeout),
                        probe_type=label,
                        port=port_num,
                    )
                ),
            )
        )
    return tasks


def _append_optional_probe(
    tasks: list[tuple[str, asyncio.Task]],
    ip: str,
    open_port_nums: dict[int, PortResult],
    priority_probes: list[str],
    effective_timeout: float | None,
    probe_name: str,
) -> None:
    port_num = _select_probe_port(probe_name, open_port_nums, priority_probes, tasks)
    if port_num is None and probe_name not in {"mdns", "snmp", "upnp"}:
        return
    if probe_name in {"mdns", "snmp", "upnp"} and not _should_run_priority_probe(probe_name, open_port_nums, priority_probes):
        return
    tasks.append(
        (
            probe_name,
            asyncio.create_task(
                _with_timeout(
                    _probe_coroutine(probe_name, ip, port_num),
                    _resolve_probe_timeout(probe_name, effective_timeout),
                    probe_name,
                    port_num,
                )
            ),
        )
    )


def _probe_coroutine(probe_name: str, ip: str, port_num: int | None):
    if probe_name == "tls":
        return _tls_probe(ip, _require_port(port_num, probe_name))
    if probe_name == "ssh":
        return _ssh_probe(ip, _require_port(port_num, probe_name))
    if probe_name == "snmp":
        return _snmp_probe(ip)
    if probe_name == "mdns":
        return _mdns_probe(ip)
    if probe_name == "upnp":
        return _upnp_probe(ip)
    if probe_name == "smb":
        return _smb_probe(ip, _require_port(port_num, probe_name))
    raise ValueError(f"Unsupported probe type: {probe_name}")


def _require_port(port_num: int | None, probe_name: str) -> int:
    if port_num is None:
        raise ValueError(f"Probe {probe_name} requires a target port")
    return port_num


def _select_probe_port(
    probe_name: str,
    open_port_nums: dict[int, PortResult],
    priority_probes: list[str],
    tasks: list[tuple[str, asyncio.Task]],
) -> int | None:
    if probe_name == "tls":
        if any(existing_name == "tls" for existing_name, _ in tasks):
            return None
        return _first_matching_port((443, 8443, 4443), open_port_nums)
    if probe_name == "ssh":
        return _first_matching_port((22, 2222), open_port_nums)
    if probe_name == "smb":
        return _first_matching_port((445, 139), open_port_nums)
    if probe_name == "snmp":
        return 161
    if probe_name == "upnp":
        return 1900
    if probe_name == "mdns":
        return None
    return None


def _should_run_priority_probe(
    probe_name: str,
    open_port_nums: dict[int, PortResult],
    priority_probes: list[str],
) -> bool:
    if probe_name == "snmp":
        return 161 in open_port_nums or probe_name in priority_probes
    if probe_name == "mdns":
        return 5353 in open_port_nums or probe_name in priority_probes
    if probe_name == "upnp":
        return 1900 in open_port_nums or probe_name in priority_probes
    return False


def _first_matching_port(candidates: tuple[int, ...], open_port_nums: dict[int, PortResult]) -> int | None:
    for port_num in candidates:
        if port_num in open_port_nums:
            return port_num
    return None


def _web_ports() -> dict[int, bool]:
    return {
        80: False,
        8080: False,
        8000: False,
        8008: False,
        8888: False,
        443: True,
        8443: True,
        4443: True,
    }


def _normalize_probe_timeout(timeout_seconds: float | None) -> float | None:
    if timeout_seconds is None:
        return None
    return max(1.0, min(30.0, float(timeout_seconds)))


def _resolve_probe_timeout(probe_type: str, timeout_seconds: float | None) -> float:
    if timeout_seconds is not None:
        return timeout_seconds
    return PROBE_TIMEOUTS.get(probe_type, 6.0)


# ── Probe wrappers ────────────────────────────────────────────────────────────

async def _with_timeout(coro, timeout: float, probe_type: str, port: int | None = None) -> ProbeResult:
    try:
        timeout_context = getattr(asyncio, "timeout", None)
        if timeout_context is not None:
            async with timeout_context(timeout):
                return await coro
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
