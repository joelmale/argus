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
from datetime import datetime, timezone

from app.core.config import settings
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


async def run_scan(
    job_id: str,
    targets: str,
    profile: ScanProfile = ScanProfile.BALANCED,
    enable_ai: bool = True,
    db_session=None,
    broadcast_fn=None,   # Optional: async callable(dict) for WebSocket events
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
            "hosts_found": len(hosts),
            "message": f"Discovered {len(hosts)} live hosts",
        },
    })

    # ── Stage 2: Port scan all hosts together (nmap batch) ───────────────────
    from app.scanner.stages import portscan
    port_results = await portscan.scan_hosts(hosts, profile)

    # Build a map: ip → (ports, os_fp)
    port_map: dict[str, tuple] = {ip: (ports, os_fp) for ports, os_fp, ip in port_results}

    # ── Stages 3–6: Per-host investigation (concurrent) ──────────────────────
    semaphore = asyncio.Semaphore(CONCURRENT_HOSTS)
    analyst = None
    if enable_ai:
        from app.scanner.agent import get_analyst
        analyst = get_analyst()

    tasks = [
        asyncio.create_task(
            _investigate_host(
                host=host,
                ports=port_map.get(host.ip_address, ([], OSFingerprint()))[0],
                os_fp=port_map.get(host.ip_address, ([], OSFingerprint()))[1],
                profile=profile,
                analyst=analyst,
                semaphore=semaphore,
                broadcast_fn=broadcast_fn,
                job_id=job_id,
            )
        )
        for host in hosts
    ]

    results: list[HostScanResult | None] = await asyncio.gather(*tasks, return_exceptions=False)

    # ── Stage 6: Persist all results ─────────────────────────────────────────
    if db_session is not None:
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


async def _investigate_host(
    host: DiscoveredHost,
    ports,
    os_fp: OSFingerprint,
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

        hint = classify(host, ports, os_fp)
        priority_probes = probe_priority(host, ports, hint)

        # Enrichment: MAC vendor + reverse DNS (quick, always run)
        vendor, reverse_hostname = await asyncio.gather(
            asyncio.get_event_loop().run_in_executor(None, mac_vendor.lookup, host.mac_address),
            dns_lookup.reverse_lookup(ip),
        )

        # Build partial result
        result = HostScanResult(
            host=host,
            ports=ports,
            os_fingerprint=os_fp,
            mac_vendor=vendor,
            reverse_hostname=reverse_hostname,
            scan_profile=profile,
        )

        # Stage 4: Deep probes
        from app.scanner.stages import deep_probe
        probe_results = await deep_probe.run(host, ports, priority_probes, profile)
        result.probes = probe_results

        # Enrich hostname from DNS probe if not already set
        if not result.reverse_hostname:
            for pr in probe_results:
                if pr.probe_type == "dns" and pr.success:
                    result.reverse_hostname = pr.data.get("hostname")
                    break

        # Stage 5: AI analysis
        if analyst is not None:
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

        result.scan_duration_ms = round((time.monotonic() - t0) * 1000, 1)
        return result


async def _persist_results(
    db_session,
    results: list[HostScanResult | None],
    scanned_ips: set[str],
    summary: ScanSummary,
    broadcast_fn,
    job_id: str,
) -> None:
    """Persist all scan results to the database."""
    from app.db.upsert import mark_offline, upsert_scan_result

    # Find assets that were online before but not in this scan
    from sqlalchemy import select
    from app.db.models import Asset
    stmt = select(Asset.ip_address).where(Asset.status == "online")
    previously_online = {row[0] for row in (await db_session.execute(stmt)).all()}
    offline_ips = list(previously_online - scanned_ips)

    for result in results:
        if result is None:
            continue
        try:
            asset, change_type = await upsert_scan_result(db_session, result)

            if change_type == "discovered":
                summary.new_assets += 1
                await _broadcast(broadcast_fn, {
                    "event": "device_discovered",
                    "data": {
                        "job_id": job_id,
                        "ip": result.host.ip_address,
                        "mac": result.host.mac_address,
                        "hostname": result.reverse_hostname,
                        "device_class": result.ai_analysis.device_class.value if result.ai_analysis else "unknown",
                    },
                })
            elif change_type == "updated":
                summary.changed_assets += 1

        except Exception as exc:
            log.error("DB upsert failed for %s: %s", result.host.ip_address, exc)
            summary.errors.append(f"{result.host.ip_address}: {exc}")

    # Mark offline assets
    offline_count = await mark_offline(db_session, offline_ips)
    summary.offline_assets = offline_count

    await db_session.commit()


async def _broadcast(fn, payload: dict) -> None:
    """Call broadcast function if provided, swallow errors."""
    if fn is None:
        return
    try:
        await fn(payload)
    except Exception as exc:
        log.debug("Broadcast error: %s", exc)
