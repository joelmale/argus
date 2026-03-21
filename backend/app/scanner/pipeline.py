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
import logging
import time
from dataclasses import dataclass

from app.scanner.models import (
    DiscoveredHost,
    HostScanResult,
    OSFingerprint,
    ScanProfile,
    ScanSummary,
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

    log.info("=== Scan started: job=%s targets=%s profile=%s ai=%s ===",
             job_id, targets, profile.value, enable_ai)

    await _broadcast(broadcast_fn, {
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "discovery",
            "progress": 0.05,
            "message": f"Starting host discovery for {targets}",
        },
    })

    # ── Stage 1: Discovery ────────────────────────────────────────────────────
    from app.scanner.stages import discovery
    hosts = await discovery.sweep(targets)
    summary.hosts_scanned = len(hosts)
    summary.hosts_up = len(hosts)

    if not hosts:
        log.info("No hosts discovered in %s", targets)
        summary.duration_seconds = time.monotonic() - t0
        return summary

    await _broadcast(broadcast_fn, {
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "discovery",
            "progress": 0.15,
            "hosts_found": len(hosts),
            "message": f"Discovered {len(hosts)} live hosts",
        },
    })

    await _check_control(
        control_fn,
        stage="post_discovery",
        summary=summary,
        hosts=hosts,
        completed_results=[],
        total_hosts=len(hosts),
    )

    # ── Stage 2: Port scan all hosts together (nmap batch) ───────────────────
    await _broadcast(broadcast_fn, {
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "port_scan",
            "progress": 0.2,
            "hosts_found": len(hosts),
            "message": f"Running nmap port scan across {len(hosts)} hosts",
        },
    })

    await _check_control(
        control_fn,
        stage="pre_port_scan",
        summary=summary,
        hosts=hosts,
        completed_results=[],
        total_hosts=len(hosts),
    )

    from app.scanner.stages import portscan
    port_results = await portscan.scan_hosts(hosts, profile)

    # Build a map: ip → (ports, os_fp, nmap_hostname, nmap_vendor)
    port_map: dict[str, tuple] = {
        ip: (ports, os_fp, nmap_hostname, nmap_vendor)
        for ports, os_fp, ip, nmap_hostname, nmap_vendor in port_results
    }

    await _check_control(
        control_fn,
        stage="post_port_scan",
        summary=summary,
        hosts=hosts,
        completed_results=[],
        total_hosts=len(hosts),
    )

    # ── Stages 3–6: Per-host investigation (concurrent) ──────────────────────
    semaphore = asyncio.Semaphore(max(1, concurrent_hosts))
    analyst = None
    if enable_ai:
        from app.scanner.agent import get_analyst
        analyst = get_analyst()

    tasks = [
        asyncio.create_task(
            _investigate_host(
                host=host,
                ports=port_map.get(host.ip_address, ([], OSFingerprint(), None, None))[0],
                os_fp=port_map.get(host.ip_address, ([], OSFingerprint(), None, None))[1],
                nmap_hostname=port_map.get(host.ip_address, ([], OSFingerprint(), None, None))[2],
                nmap_vendor=port_map.get(host.ip_address, ([], OSFingerprint(), None, None))[3],
                profile=profile,
                analyst=analyst,
                semaphore=semaphore,
                broadcast_fn=broadcast_fn,
                job_id=job_id,
            )
        )
        for host in hosts
    ]

    results: list[HostScanResult | None] = []
    completed_hosts = 0
    total_hosts = len(tasks)
    await _broadcast(broadcast_fn, {
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "investigation",
            "progress": 0.25,
            "hosts_found": len(hosts),
            "hosts_investigated": 0,
            "message": f"Investigating {total_hosts} discovered hosts",
        },
    })

    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        completed_hosts += 1
        progress = 0.25 + (0.6 * (completed_hosts / max(total_hosts, 1)))
        current_host = result.host.ip_address if result else None
        await _broadcast(broadcast_fn, {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "investigation",
                "progress": round(progress, 3),
                "hosts_found": len(hosts),
                "hosts_investigated": completed_hosts,
                "current_host": current_host,
                "message": f"Investigated {completed_hosts}/{total_hosts} hosts",
            },
        })

        await _check_control(
            control_fn,
            stage="investigation",
            summary=summary,
            hosts=hosts,
            completed_results=[r for r in results if r],
            total_hosts=total_hosts,
            tasks=tasks,
        )

    # ── Stage 6: Persist all results ─────────────────────────────────────────
    if db_session is not None:
        await _check_control(
            control_fn,
            stage="pre_persist",
            summary=summary,
            hosts=hosts,
            completed_results=[r for r in results if r],
            total_hosts=total_hosts,
        )
        await _broadcast(broadcast_fn, {
            "event": "scan_progress",
            "data": {
                "job_id": job_id,
                "stage": "persist",
                "progress": 0.9,
                "hosts_found": len(hosts),
                "hosts_investigated": completed_hosts,
                "message": f"Persisting results for {completed_hosts} investigated hosts",
            },
        })
        scanned_ips = {r.host.ip_address for r in results if r}
        await _persist_results(db_session, results, scanned_ips, summary, broadcast_fn, job_id)

    # Tally summary
    for r in results:
        if r:
            summary.total_open_ports += len(r.open_ports)
            if r.ai_analysis:
                summary.ai_analyses_completed += 1

    summary.duration_seconds = round(time.monotonic() - t0, 2)
    log.info("=== Scan complete: %s | %d hosts | %ds ===",
             job_id, len(results), summary.duration_seconds)

    await _broadcast(broadcast_fn, {
        "event": "scan_complete",
        "data": summary.model_dump(mode="json"),
    })

    return summary


async def _check_control(
    control_fn,
    *,
    stage: str,
    summary: ScanSummary,
    hosts: list[DiscoveredHost],
    completed_results: list[HostScanResult],
    total_hosts: int,
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


def _build_control_interrupt(
    decision: ScanControlDecision,
    stage: str,
    summary: ScanSummary,
    partial_results: list[HostScanResult],
    completed_results: list[HostScanResult],
) -> ScanControlInterrupt:
    preserve_discovery = decision.mode == "preserve_discovery"
    persisted_results = partial_results if preserve_discovery else completed_results
    action_label = "paused" if decision.action == "pause" else "cancelled"
    message = decision.message or f"Scan {action_label} during {stage}"
    return ScanControlInterrupt(
        status="paused" if decision.action == "pause" else "cancelled",
        message=message,
        summary=summary.model_copy(deep=True),
        partial_results=persisted_results,
        scanned_ips={result.host.ip_address for result in persisted_results},
        resume_after=decision.resume_after,
        mark_missing_offline=False,
    )


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
        priority_probes = probe_priority(host, ports, hint)

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
        from app.scanner.stages import deep_probe
        probe_results = await deep_probe.run(host, ports, priority_probes, profile)
        result.probes = probe_results

        # Further enrich hostname from probes if still missing
        if not result.reverse_hostname:
            result.reverse_hostname = _resolve_hostname_from_probes(probe_results)

        # Stage 5: AI analysis
        await _run_ai_investigation(analyst, result, broadcast_fn, job_id, ip)

        result.scan_duration_ms = round((time.monotonic() - t0) * 1000, 1)
        return result


async def _lookup_host_enrichment(mac_vendor, dns_lookup, host: DiscoveredHost, ip: str, nmap_vendor: str | None) -> tuple[str | None, str | None]:
    vendor_lookup, reverse_hostname = await asyncio.gather(
        asyncio.get_event_loop().run_in_executor(None, mac_vendor.lookup, host.mac_address),
        dns_lookup.reverse_lookup(ip),
    )
    return vendor_lookup or nmap_vendor, reverse_hostname


def _resolve_hostname_from_probes(probe_results) -> str | None:
    for probe in probe_results:
        if probe.probe_type == "dns" and probe.success:
            return probe.data.get("hostname")
        if probe.probe_type == "mdns" and probe.success:
            services = probe.data.get("services", [])
            if services and services[0].get("host"):
                return services[0]["host"]
        if probe.probe_type == "snmp" and probe.success:
            sys_name = probe.data.get("sys_name")
            if sys_name:
                return sys_name
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
) -> None:
    """Persist all scan results to the database."""
    from app.db.upsert import mark_offline, upsert_scan_result
    from app.alerting import notify_devices_offline_if_enabled, notify_new_device_if_enabled
    from app.scanner.config import has_meaningful_scan_evidence
    from app.scanner.topology import infer_topology_links_from_snmp

    # Find assets that were online before but not in this scan
    from sqlalchemy import select
    from app.db.models import Asset
    offline_ips = await _get_offline_ips(db_session, select, Asset, scanned_ips, mark_missing_offline)

    for result in results:
        await _persist_result(
            db_session,
            result,
            summary,
            broadcast_fn,
            job_id,
            allow_discovery_only,
            has_meaningful_scan_evidence,
            upsert_scan_result,
            infer_topology_links_from_snmp,
            notify_new_device_if_enabled,
        )

    # Mark offline assets
    if mark_missing_offline:
        offline_count, offline_assets = await mark_offline(db_session, offline_ips)
        summary.offline_assets = offline_count
        if offline_assets:
            await notify_devices_offline_if_enabled(
                db_session,
                [
                    {
                        "ip": asset.ip_address,
                        "hostname": asset.hostname,
                        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
                    }
                    for asset in offline_assets
                ]
            )

    await db_session.commit()


async def _get_offline_ips(db_session, select_fn, asset_model, scanned_ips: set[str], mark_missing_offline: bool) -> list[str]:
    if not mark_missing_offline:
        return []
    stmt = select_fn(asset_model.ip_address).where(asset_model.status == "online")
    previously_online = {row[0] for row in (await db_session.execute(stmt)).all()}
    return list(previously_online - scanned_ips)


async def _persist_result(
    db_session,
    result: HostScanResult | None,
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
    allow_discovery_only: bool,
    has_meaningful_scan_evidence,
    upsert_scan_result,
    infer_topology_links_from_snmp,
    notify_new_device_if_enabled,
) -> None:
    if result is None:
        return
    if not has_meaningful_scan_evidence(result) and not allow_discovery_only:
        log.info("Skipping weak scan result for %s: insufficient evidence to persist asset", result.host.ip_address)
        return

    try:
        asset, change_type = await upsert_scan_result(db_session, result)
        await _persist_snmp_topology(db_session, asset, result, infer_topology_links_from_snmp)
        await _update_summary(summary, broadcast_fn, job_id, result, change_type, db_session, notify_new_device_if_enabled)
    except Exception as exc:
        log.error("DB upsert failed for %s: %s", result.host.ip_address, exc)
        summary.errors.append(f"{result.host.ip_address}: {exc}")


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
) -> None:
    if change_type == "discovered":
        summary.new_assets += 1
        discovered_event = {
            "event": "device_discovered",
            "data": {
                "job_id": job_id,
                "ip": result.host.ip_address,
                "mac": result.host.mac_address,
                "hostname": result.reverse_hostname,
                "device_class": result.ai_analysis.device_class.value if result.ai_analysis else "unknown",
            },
        }
        await _broadcast(broadcast_fn, discovered_event)
        await notify_new_device_if_enabled(db_session, discovered_event["data"])
    elif change_type == "updated":
        summary.changed_assets += 1


async def _broadcast(fn, payload: dict) -> None:
    """Call broadcast function if provided, swallow errors."""
    if fn is None:
        return
    try:
        await fn(payload)
    except Exception as exc:
        log.debug("Broadcast error: %s", exc)
