"""
Argus Scanner Pipeline — Main Orchestrator

Coordinates all five stages into a single scan workflow:

  Stage 1: Discovery    — who is alive? (ARP + ping sweep)
  Stage 2: Port Scan    — what is open? (nmap)
  Stage 3: Fingerprint  — what is it? (heuristic rules)
  Stage 4: Deep Probes  — prove the hypothesis (HTTP, TLS, SSH, SNMP, mDNS, UPnP, SMB)
  Stage 5: AI Analysis  — synthesize all signals (Ollama ReAct agent)
  Stage 6: Persist      — upsert into database, emit WebSocket events

The pipeline runs per-host work concurrently (asyncio.gather with a semaphore
to limit max parallel investigations). This is like a thread pool but for
async coroutines — we can investigate 10 hosts at once without 10 threads.

Concurrency model:
  - nmap scans the full subnet in one call (internally parallel)
  - Per-host deep probes run concurrently across hosts (semaphore-limited)
  - Per-probe probes within a host also run concurrently (deep_probe.run)
  - AI agent calls run concurrently across hosts but each is sequential internally

So for a /24 with 50 live hosts and CONCURRENT_HOSTS=10:
  ~5 batches of 10 hosts × (probe time + AI time per batch)
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass

from app.scanner.models import (
    DiscoveredHost,
    HostScanResult,
    OSFingerprint,
    ScanProfile,
    ScanSummary,
    get_scan_mode_behavior,
)

log = logging.getLogger(__name__)

# Max hosts investigated simultaneously — tune based on your network + hardware
CONCURRENT_HOSTS = 10


@dataclass(slots=True)
class ScanControlDecision:
    action: str
    mode: str = "discard"
    resume_after: str | None = None
    message: str | None = None


class ScanControlInterrupt(Exception):
    def __init__(
        self,
        *,
        status: str,
        message: str,
        summary: ScanSummary | None = None,
        partial_results: list[HostScanResult] | None = None,
        scanned_ips: set[str] | None = None,
        resume_after: str | None = None,
        mark_missing_offline: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.summary = summary
        self.partial_results = partial_results or []
        self.scanned_ips = scanned_ips or set()
        self.resume_after = resume_after
        self.mark_missing_offline = mark_missing_offline


async def run_scan(
    job_id: str,
    targets: str,
    profile: ScanProfile = ScanProfile.BALANCED,
    enable_ai: bool = True,
    concurrent_hosts: int = CONCURRENT_HOSTS,
    host_chunk_size: int = 64,
    top_ports_count: int = 1000,
    deep_probe_timeout_seconds: int = 6,
    mark_missing_offline: bool = True,
    scanned_ips_buffer: set[str] | None = None,
    db_session=None,
    broadcast_fn=None,   # Optional: async callable(dict) for WebSocket events
    control_fn=None,
) -> ScanSummary:
    """
    Run a complete scan pipeline against `targets`.

    Args:
        job_id:       ScanJob ID for tracking
        targets:      CIDR or space/comma-separated IPs
        profile:      Scan intensity profile
        enable_ai:    Whether to run AI investigation agent
        db_session:   AsyncSession for DB persistence (None = dry run)
        broadcast_fn: Async callable for WebSocket event broadcasting

    Returns:
        ScanSummary with counts and timing
    """
    t0 = time.monotonic()
    summary = ScanSummary(job_id=job_id, targets=targets, profile=profile)
    mode_behavior = get_scan_mode_behavior(profile, top_ports_count=top_ports_count)
    hosts: list[DiscoveredHost]

    log.info("=== Scan started: job=%s targets=%s profile=%s ai=%s ===",
             job_id, targets, profile.value, enable_ai)

    hosts = await _run_discovery_stage(
        targets,
        job_id,
        summary,
        db_session=db_session,
        broadcast_fn=broadcast_fn,
        control_fn=control_fn,
        scanned_ips_buffer=scanned_ips_buffer,
    )
    if not hosts:
        log.info("No hosts discovered in %s", targets)
        summary.duration_seconds = time.monotonic() - t0
        return summary

    port_map = await _run_port_scan_stage(
        hosts,
        profile,
        top_ports_count,
        host_chunk_size,
        summary,
        job_id,
        broadcast_fn,
        control_fn,
    )

    # ── Stages 3–6: Per-host investigation (concurrent) ──────────────────────
    semaphore = asyncio.Semaphore(max(1, concurrent_hosts))
    analyst = None
    if _should_enable_ai(enable_ai, mode_behavior):
        from app.scanner.agent import get_analyst
        if db_session is not None:
            from app.scanner.config import read_effective_scanner_config
            _, runtime_config = await read_effective_scanner_config(db_session)
            analyst = get_analyst(runtime_config)
        else:
            analyst = get_analyst()

    tasks = _build_investigation_tasks(
        hosts,
        port_map,
        profile,
        analyst,
        mode_behavior.run_deep_probes,
        deep_probe_timeout_seconds,
        semaphore,
        broadcast_fn,
        job_id,
    )

    total_hosts = len(tasks)
    await _broadcast_investigation_start(broadcast_fn, job_id, hosts, total_hosts, summary)
    results, completed_hosts, deep_probed_hosts = await _collect_investigation_results(
        tasks,
        hosts,
        total_hosts,
        summary,
        db_session,
        broadcast_fn,
        job_id,
        control_fn,
    )

    # ── Stage 6: Finalize offline reconciliation ────────────────────────────
    if db_session is not None:
        await _check_control(
            control_fn,
            stage="pre_persist",
            summary=summary,
            hosts=hosts,
            completed_results=[r for r in results if r],
        )
        await _broadcast(broadcast_fn, {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "persist",
                "progress": 0.9,
                "hosts_found": len(hosts),
                "hosts_port_scanned": len(hosts),
                "hosts_fingerprinted": completed_hosts,
                "hosts_deep_probed": deep_probed_hosts,
                "hosts_investigated": completed_hosts,
                "assets_created": summary.new_assets,
                "assets_updated": summary.changed_assets,
                "message": f"Persisting results for {completed_hosts} investigated hosts",
            },
        })
        scanned_ips = _build_host_scanned_ips(hosts)
        await _call_persist_results(
            _persist_results,
            db_session,
            [],
            scanned_ips,
            summary,
            broadcast_fn,
            job_id,
            mark_missing_offline=mark_missing_offline,
            stage="persist",
        )

    _tally_summary_from_results(summary, results)

    summary.duration_seconds = round(time.monotonic() - t0, 2)
    log.info("=== Scan complete: %s | %d hosts | %ds ===",
             job_id, len(results), summary.duration_seconds)

    await _broadcast(broadcast_fn, {
        "event": "scan_complete",
        "data": summary.model_dump(mode="json"),
    })

    return summary


def _should_enable_ai(enable_ai: bool, mode_behavior) -> bool:
    return enable_ai and mode_behavior.enable_ai_by_default


def _build_host_scanned_ips(hosts: list[DiscoveredHost]) -> set[str]:
    return {host.ip_address for host in hosts}


def _tally_summary_from_results(summary: ScanSummary, results: list[HostScanResult | None]) -> None:
    for result in results:
        if result is None:
            continue
        summary.total_open_ports += len(result.open_ports)
        if result.ai_analysis:
            summary.ai_analyses_completed += 1


async def _run_port_scan_stage(
    hosts: list[DiscoveredHost],
    profile: ScanProfile,
    top_ports_count: int,
    host_chunk_size: int,
    summary: ScanSummary,
    job_id: str,
    broadcast_fn,
    control_fn,
) -> dict[str, tuple]:
    await _broadcast_port_scan_start(broadcast_fn, job_id, hosts, summary)
    await _check_control(
        control_fn,
        stage="pre_port_scan",
        summary=summary,
        hosts=hosts,
        completed_results=[],
    )
    port_map = await _run_port_scan_chunks(
        hosts,
        profile,
        top_ports_count,
        host_chunk_size,
        broadcast_fn,
        job_id,
        summary,
    )
    await _check_control(
        control_fn,
        stage="post_port_scan",
        summary=summary,
        hosts=hosts,
        completed_results=[],
    )
    return port_map


def _build_investigation_tasks(
    hosts: list[DiscoveredHost],
    port_map: dict[str, tuple],
    profile: ScanProfile,
    analyst,
    run_deep_probes: bool,
    deep_probe_timeout_seconds: int,
    semaphore: asyncio.Semaphore,
    broadcast_fn,
    job_id: str,
) -> list[asyncio.Task]:
    return [
        asyncio.create_task(
            _investigate_host(
                host=host,
                ports=port_details[0],
                os_fp=port_details[1],
                nmap_hostname=port_details[2],
                nmap_vendor=port_details[3],
                profile=profile,
                analyst=analyst,
                run_deep_probes=run_deep_probes,
                deep_probe_timeout_seconds=deep_probe_timeout_seconds,
                semaphore=semaphore,
                broadcast_fn=broadcast_fn,
                job_id=job_id,
            )
        )
        for host in hosts
        for port_details in [_port_details_for_host(port_map, host.ip_address)]
    ]


def _port_details_for_host(port_map: dict[str, tuple], ip_address: str) -> tuple:
    return port_map.get(ip_address, ([], OSFingerprint(), None, None))


async def _broadcast_port_scan_start(broadcast_fn, job_id: str, hosts: list[DiscoveredHost], summary: ScanSummary) -> None:
    await _broadcast(
        broadcast_fn,
        {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "port_scan",
                "progress": 0.2,
                "hosts_found": len(hosts),
                "hosts_port_scanned": 0,
                "hosts_fingerprinted": 0,
                "hosts_deep_probed": 0,
                "assets_created": summary.new_assets,
                "assets_updated": summary.changed_assets,
                "message": f"Running nmap port scan across {len(hosts)} hosts",
            },
        },
    )


async def _broadcast_investigation_start(
    broadcast_fn,
    job_id: str,
    hosts: list[DiscoveredHost],
    total_hosts: int,
    summary: ScanSummary,
) -> None:
    await _broadcast(
        broadcast_fn,
        {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "investigation",
                "progress": 0.25,
                "hosts_found": len(hosts),
                "hosts_port_scanned": len(hosts),
                "hosts_fingerprinted": 0,
                "hosts_deep_probed": 0,
                "hosts_investigated": 0,
                "assets_created": summary.new_assets,
                "assets_updated": summary.changed_assets,
                "message": f"Investigating {total_hosts} discovered hosts",
            },
        },
    )


async def _broadcast_investigation_progress(
    broadcast_fn,
    job_id: str,
    hosts: list[DiscoveredHost],
    summary: ScanSummary,
    completed_hosts: int,
    deep_probed_hosts: int,
    total_hosts: int,
    result: HostScanResult | None,
) -> None:
    progress = 0.25 + (0.6 * (completed_hosts / max(total_hosts, 1)))
    await _broadcast(
        broadcast_fn,
        {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "investigation",
                "progress": round(progress, 3),
                "hosts_found": len(hosts),
                "hosts_port_scanned": len(hosts),
                "hosts_fingerprinted": completed_hosts,
                "hosts_deep_probed": deep_probed_hosts,
                "hosts_investigated": completed_hosts,
                "current_host": result.host.ip_address if result else None,
                "assets_created": summary.new_assets,
                "assets_updated": summary.changed_assets,
                "message": f"Investigated {completed_hosts}/{total_hosts} hosts",
            },
        },
    )


async def _run_discovery_stage(
    targets: str,
    job_id: str,
    summary: ScanSummary,
    *,
    db_session,
    broadcast_fn,
    control_fn,
    scanned_ips_buffer: set[str] | None,
) -> list[DiscoveredHost]:
    await _broadcast(
        broadcast_fn,
        _progress_payload(
            job_id,
            "discovery",
            0.05,
            summary,
            message=f"Starting host discovery for {targets}",
        ),
    )
    from app.scanner.stages import discovery

    hosts = await discovery.sweep(targets)
    summary.hosts_scanned = len(hosts)
    summary.hosts_up = len(hosts)
    if scanned_ips_buffer is not None:
        scanned_ips_buffer.update(host.ip_address for host in hosts)
    if not hosts:
        return []

    await _broadcast(
        broadcast_fn,
        _progress_payload(
            job_id,
            "discovery",
            0.15,
            summary,
            hosts_found=len(hosts),
            message=f"Discovered {len(hosts)} live hosts",
        ),
    )
    if db_session is not None:
        await _call_persist_results(
            _persist_results,
            db_session,
            _build_partial_results(hosts, [], summary.profile),
            {host.ip_address for host in hosts},
            summary,
            broadcast_fn,
            job_id,
            mark_missing_offline=False,
            allow_discovery_only=True,
            stage="discovery",
        )
    await _check_control(
        control_fn,
        stage="post_discovery",
        summary=summary,
        hosts=hosts,
        completed_results=[],
    )
    return hosts


def _progress_payload(
    job_id: str,
    stage: str,
    progress: float,
    summary: ScanSummary,
    **data,
) -> dict:
    payload = {
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": stage,
            "progress": progress,
            "hosts_port_scanned": 0,
            "hosts_fingerprinted": 0,
            "hosts_deep_probed": 0,
            "assets_created": summary.new_assets,
            "assets_updated": summary.changed_assets,
        },
    }
    payload["data"].update(data)
    return payload


async def _check_control(
    control_fn,
    *,
    stage: str,
    summary: ScanSummary,
    hosts: list[DiscoveredHost],
    completed_results: list[HostScanResult],
    tasks: list[asyncio.Task] | None = None,
) -> None:
    if control_fn is None:
        return

    decision = await control_fn()
    if decision is None:
        return

    if decision.action not in {"cancel", "pause"}:
        return

    await _cancel_pending_tasks(tasks)
    partial_results = _build_partial_results(hosts, completed_results, summary.profile)
    raise _build_control_interrupt(decision, stage, summary, partial_results, completed_results)


async def _cancel_pending_tasks(tasks: list[asyncio.Task] | None) -> None:
    if not tasks:
        return
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _collect_investigation_results(
    tasks: list[asyncio.Task],
    hosts: list[DiscoveredHost],
    total_hosts: int,
    summary: ScanSummary,
    db_session,
    broadcast_fn,
    job_id: str,
    control_fn,
) -> tuple[list[HostScanResult | None], int, int]:
    results: list[HostScanResult | None] = []
    completed_hosts = 0
    deep_probed_hosts = 0

    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        completed_hosts += 1
        if result is not None and result.probes:
            deep_probed_hosts += 1
        await _persist_investigation_result(db_session, result, summary, broadcast_fn, job_id)
        await _broadcast_investigation_progress(
            broadcast_fn,
            job_id,
            hosts,
            summary,
            completed_hosts,
            deep_probed_hosts,
            total_hosts,
            result,
        )
        await _check_control(
            control_fn,
            stage="investigation",
            summary=summary,
            hosts=hosts,
            completed_results=[row for row in results if row],
            tasks=tasks,
        )
    return results, completed_hosts, deep_probed_hosts


async def _persist_investigation_result(db_session, result, summary: ScanSummary, broadcast_fn, job_id: str) -> None:
    if db_session is None or result is None:
        return
    await _call_persist_results(
        _persist_results,
        db_session,
        [result],
        {result.host.ip_address},
        summary,
        broadcast_fn,
        job_id,
        mark_missing_offline=False,
        stage="investigation",
    )


def _build_control_interrupt(
    decision: ScanControlDecision,
    stage: str,
    summary: ScanSummary,
    partial_results: list[HostScanResult],
    completed_results: list[HostScanResult],
) -> ScanControlInterrupt:
    preserve_discovery = decision.mode == "preserve_discovery"
    persisted_results = partial_results if preserve_discovery else completed_results
    status = _interrupt_status(decision.action)
    action_label = status
    message = decision.message or f"Scan {action_label} during {stage}"
    return ScanControlInterrupt(
        status=status,
        message=message,
        summary=summary.model_copy(deep=True),
        partial_results=persisted_results,
        scanned_ips={result.host.ip_address for result in persisted_results},
        resume_after=decision.resume_after,
        mark_missing_offline=False,
    )


def _interrupt_status(action: str) -> str:
    return "paused" if action == "pause" else "cancelled"


def _build_partial_results(
    hosts: list[DiscoveredHost],
    completed_results: list[HostScanResult],
    profile: ScanProfile,
) -> list[HostScanResult]:
    completed_by_ip = {result.host.ip_address: result for result in completed_results}
    partial_results: list[HostScanResult] = []
    for host in hosts:
        existing = completed_by_ip.get(host.ip_address)
        if existing is not None:
            partial_results.append(existing)
            continue
        partial_results.append(
            HostScanResult(
                host=host,
                scan_profile=profile,
            )
        )
    return partial_results


async def _investigate_host(
    host: DiscoveredHost,
    ports,
    os_fp: OSFingerprint,
    nmap_hostname: str | None,
    nmap_vendor: str | None,
    profile: ScanProfile,
    analyst,
    run_deep_probes: bool,
    deep_probe_timeout_seconds: int,
    semaphore: asyncio.Semaphore,
    broadcast_fn,
    job_id: str,
) -> HostScanResult:
    """Full per-host investigation pipeline (stages 3–5)."""
    async with semaphore:
        ip = host.ip_address
        t0 = time.monotonic()
        log.info("Investigating %s (%d open ports)", ip, sum(1 for p in ports if p.state == "open"))

        # Stage 3: Heuristic fingerprinting
        from app.scanner.stages.fingerprint import classify, probe_priority
        from app.scanner.enrichment import mac_vendor, dns_lookup

        vendor, reverse_hostname = await _lookup_host_enrichment(mac_vendor, dns_lookup, host, ip, nmap_vendor)
        hint = classify(host, ports, os_fp, vendor)
        priority_probes = probe_priority(ports, hint)

        # Build partial result
        result = HostScanResult(
            host=host,
            ports=ports,
            os_fingerprint=os_fp,
            mac_vendor=vendor,
            reverse_hostname=reverse_hostname or nmap_hostname,
            scan_profile=profile,
        )

        # Stage 4: Deep probes
        probe_results = await _run_deep_probe_stage(
            run_deep_probes,
            host,
            ports,
            priority_probes,
            deep_probe_timeout_seconds,
        )
        result.probes = probe_results

        # Further enrich hostname from probes if still missing
        if not result.reverse_hostname:
            result.reverse_hostname = _resolve_hostname_from_probes(probe_results)

        # Stage 5: AI analysis
        await _run_ai_investigation(analyst, result, broadcast_fn, job_id, ip)

        result.scan_duration_ms = round((time.monotonic() - t0) * 1000, 1)
        return result


async def _run_deep_probe_stage(
    run_deep_probes: bool,
    host: DiscoveredHost,
    ports,
    priority_probes,
    deep_probe_timeout_seconds: int,
) -> list:
    if not run_deep_probes:
        return []
    from app.scanner.stages import deep_probe
    return await deep_probe.run(
        host,
        ports,
        priority_probes,
        timeout_seconds=deep_probe_timeout_seconds,
    )


async def _run_port_scan_chunks(
    hosts: list[DiscoveredHost],
    profile: ScanProfile,
    top_ports_count: int,
    host_chunk_size: int,
    broadcast_fn,
    job_id: str,
    summary: ScanSummary,
) -> dict[str, tuple]:
    from app.scanner.stages import portscan

    chunk_size = max(1, min(256, host_chunk_size))
    chunks = [hosts[index:index + chunk_size] for index in range(0, len(hosts), chunk_size)]
    scanned_hosts = 0
    port_results = []
    for index, chunk in enumerate(chunks, start=1):
        chunk_results = await _call_scan_hosts(
            portscan.scan_hosts,
            chunk,
            profile,
            top_ports_count=top_ports_count,
        )
        port_results.extend(chunk_results)
        scanned_hosts += len(chunk)
        progress = 0.2 + (0.05 * (scanned_hosts / max(len(hosts), 1)))
        await _broadcast(broadcast_fn, {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "port_scan",
                "progress": round(progress, 3),
                "hosts_found": len(hosts),
                "hosts_port_scanned": scanned_hosts,
                "hosts_fingerprinted": 0,
                "hosts_deep_probed": 0,
                "assets_created": summary.new_assets,
                "assets_updated": summary.changed_assets,
                "message": f"Port scanned chunk {index}/{len(chunks)} ({scanned_hosts}/{len(hosts)} hosts)",
            },
        })

    return {
        ip: (ports, os_fp, nmap_hostname, nmap_vendor)
        for ports, os_fp, ip, nmap_hostname, nmap_vendor in port_results
    }


async def _call_scan_hosts(scan_hosts_fn, hosts, profile: ScanProfile, *, top_ports_count: int):
    try:
        return await scan_hosts_fn(
            hosts,
            profile,
            top_ports_count=top_ports_count,
        )
    except TypeError as exc:
        if "unexpected keyword argument 'top_ports_count'" not in str(exc):
            raise
        return await scan_hosts_fn(hosts, profile)


async def _lookup_host_enrichment(mac_vendor, dns_lookup, host: DiscoveredHost, ip: str, nmap_vendor: str | None) -> tuple[str | None, str | None]:
    vendor_lookup, reverse_hostname = await asyncio.gather(
        asyncio.get_event_loop().run_in_executor(None, mac_vendor.lookup, host.mac_address),
        dns_lookup.reverse_lookup(ip),
    )
    return vendor_lookup or nmap_vendor, reverse_hostname


def _resolve_hostname_from_probes(probe_results) -> str | None:
    for probe in probe_results:
        hostname = _extract_probe_hostname(probe)
        if hostname:
            return hostname
    return None


def _extract_probe_hostname(probe) -> str | None:
    if not probe.success:
        return None
    if probe.probe_type == "dns":
        return probe.data.get("hostname")
    if probe.probe_type == "mdns":
        services = probe.data.get("services", [])
        if services and services[0].get("host"):
            return services[0]["host"]
        return None
    if probe.probe_type == "snmp":
        return probe.data.get("sys_name")
    return None


async def _run_ai_investigation(analyst, result: HostScanResult, broadcast_fn, job_id: str, ip: str) -> None:
    if analyst is None:
        return
    try:
        ai_analysis = await analyst.investigate(result)
        result.ai_analysis = ai_analysis
        await _broadcast(broadcast_fn, {
            "event": "device_investigated",
            "data": {
                "job_id": job_id,
                "ip": ip,
                "device_class": ai_analysis.device_class.value,
                "vendor": ai_analysis.vendor,
                "confidence": ai_analysis.confidence,
            },
        })
    except Exception as exc:
        log.error("AI analysis failed for %s: %s", ip, exc)


async def _persist_results(
    db_session,
    results: list[HostScanResult | None],
    scanned_ips: set[str],
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
    mark_missing_offline: bool = True,
    allow_discovery_only: bool = False,
    stage: str = "investigation",
    targets: str | None = None,
) -> None:
    """Persist all scan results to the database."""
    from app.db.upsert import mark_offline, upsert_scan_result
    from app.alerting import notify_devices_offline_if_enabled, notify_new_device_if_enabled
    from app.scanner.config import has_meaningful_scan_evidence
    from app.scanner.topology import infer_topology_links_from_snmp
    from app.topology.segments import ensure_segment_for_asset

    # Find assets that were online before but not in this scan
    from sqlalchemy import select
    from app.db.models import Asset
    offline_ips = await _get_offline_ips(
        db_session,
        select,
        Asset,
        scanned_ips,
        mark_missing_offline,
        targets=targets,
    )

    for result in results:
        await _persist_result(
            db_session,
            result,
            summary,
            broadcast_fn,
            job_id,
            stage,
            allow_discovery_only,
            has_meaningful_scan_evidence,
            upsert_scan_result,
            infer_topology_links_from_snmp,
            ensure_segment_for_asset,
            notify_new_device_if_enabled,
        )

    await _persist_offline_assets(
        db_session,
        offline_ips,
        summary,
        mark_missing_offline,
        mark_offline,
        notify_devices_offline_if_enabled,
    )

    await db_session.commit()


async def _call_persist_results(
    persist_fn,
    db_session,
    results: list[HostScanResult | None],
    scanned_ips: set[str],
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
    *,
    mark_missing_offline: bool = True,
    allow_discovery_only: bool = False,
    stage: str = "investigation",
) -> None:
    try:
        await persist_fn(
            db_session,
            results,
            scanned_ips,
            summary,
            broadcast_fn,
            job_id,
            mark_missing_offline=mark_missing_offline,
            allow_discovery_only=allow_discovery_only,
            stage=stage,
            targets=summary.targets,
        )
    except TypeError as exc:
        if "unexpected keyword argument" not in str(exc):
            raise
        await persist_fn(db_session, results, scanned_ips, summary, broadcast_fn, job_id)


def _ip_in_target_scope(ip_address: str, targets: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    for token in targets.replace(",", " ").split():
        candidate = token.strip()
        if not candidate:
            continue
        try:
            if "/" in candidate:
                network = ipaddress.ip_network(candidate, strict=False)
                if ip_obj in network:
                    return True
            elif ip_obj == ipaddress.ip_address(candidate):
                return True
        except ValueError:
            continue
    return False


async def _get_offline_ips(
    db_session,
    select_fn,
    asset_model,
    scanned_ips: set[str],
    mark_missing_offline: bool,
    targets: str | None = None,
) -> list[str]:
    if not mark_missing_offline:
        return []
    stmt = select_fn(asset_model.ip_address).where(asset_model.status == "online")
    previously_online = {row[0] for row in (await db_session.execute(stmt)).all()}
    offline_candidates = previously_online - scanned_ips
    if not targets:
        return list(offline_candidates)
    return [ip for ip in offline_candidates if _ip_in_target_scope(ip, targets)]


async def _persist_result(
    db_session,
    result: HostScanResult | None,
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
    stage: str,
    allow_discovery_only: bool,
    has_meaningful_scan_evidence,
    upsert_scan_result,
    infer_topology_links_from_snmp,
    ensure_segment_for_asset,
    notify_new_device_if_enabled,
) -> None:
    if result is None:
        return
    if not has_meaningful_scan_evidence(result) and not allow_discovery_only:
        log.info("Skipping weak scan result for %s: insufficient evidence to persist asset", result.host.ip_address)
        return

    try:
        asset, change_type = await upsert_scan_result(db_session, result)
        await ensure_segment_for_asset(db_session, asset)
        await _persist_snmp_topology(db_session, asset, result, infer_topology_links_from_snmp)
        await _update_summary(summary, broadcast_fn, job_id, result, change_type, db_session, notify_new_device_if_enabled, stage)
    except Exception as exc:
        log.error("DB upsert failed for %s: %s", result.host.ip_address, exc)
        summary.errors.append(f"{result.host.ip_address}: {exc}")


async def _persist_offline_assets(
    db_session,
    offline_ips: list[str],
    summary: ScanSummary,
    mark_missing_offline: bool,
    mark_offline,
    notify_devices_offline_if_enabled,
) -> None:
    if not mark_missing_offline:
        return
    offline_count, offline_assets = await mark_offline(db_session, offline_ips)
    summary.offline_assets = offline_count
    if not offline_assets:
        return
    await notify_devices_offline_if_enabled(
        db_session,
        [_offline_notification_payload(asset) for asset in offline_assets],
    )


def _offline_notification_payload(asset) -> dict[str, str | None]:
    return {
        "ip": asset.ip_address,
        "hostname": asset.hostname,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


async def _persist_snmp_topology(db_session, asset, result: HostScanResult, infer_topology_links_from_snmp) -> None:
    snmp_probe = next((probe for probe in result.probes if probe.probe_type == "snmp" and probe.success), None)
    if snmp_probe:
        await infer_topology_links_from_snmp(db_session, asset, snmp_probe.data)


async def _update_summary(
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
    result: HostScanResult,
    change_type: str,
    db_session,
    notify_new_device_if_enabled,
    stage: str,
) -> None:
    if change_type == "discovered":
        summary.new_assets += 1
        discovered_event = _build_discovered_event(job_id, stage, result)
        await _broadcast(broadcast_fn, discovered_event)
        await notify_new_device_if_enabled(db_session, discovered_event["data"])
        return
    if change_type == "updated":
        summary.changed_assets += 1
        await _broadcast(broadcast_fn, _build_updated_event(job_id, stage, result))


def _build_discovered_event(job_id: str, stage: str, result: HostScanResult) -> dict:
    return {
        "event": "device_discovered",
        "data": {
            "job_id": job_id,
            "stage": stage,
            "ip": result.host.ip_address,
            "mac": result.host.mac_address,
            "hostname": result.reverse_hostname,
            "device_class": result.ai_analysis.device_class.value if result.ai_analysis else "unknown",
        },
    }


def _build_updated_event(job_id: str, stage: str, result: HostScanResult) -> dict:
    return {
        "event": "device_updated",
        "data": {
            "job_id": job_id,
            "stage": stage,
            "ip": result.host.ip_address,
            "hostname": result.reverse_hostname,
        },
    }


async def _broadcast(fn, payload: dict) -> None:
    """Call broadcast function if provided, swallow errors."""
    if fn is None:
        return
    try:
        await fn(payload)
    except Exception as exc:
        log.debug("Broadcast error: %s", exc)
