from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetHistory, ProbeRun
from app.db.upsert import upsert_scan_result
from app.scanner.agent import get_analyst
from app.scanner.config import read_effective_scanner_config
from app.scanner.models import DiscoveredHost, ScanProfile
from app.scanner.pipeline import _investigate_host
from app.scanner.stages import portscan
from app.scanner.probes.snmp import probe as run_snmp_probe
from app.scanner.topology import infer_topology_links_from_snmp

AI_REFRESH_JOB_TYPE = "asset_ai_refresh"
SNMP_REFRESH_JOB_TYPE = "asset_snmp_refresh"


async def _load_asset(db: AsyncSession, asset_id: UUID) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise ValueError("Asset not found")
    return asset


async def enqueue_asset_refresh_job(
    db: AsyncSession,
    *,
    asset_id: UUID,
    scan_type: str,
    result_summary: dict,
) -> tuple[str, bool]:
    asset = await _load_asset(db, asset_id)
    from app.services.scan_queue import enqueue_scan_job

    job, should_start = await enqueue_scan_job(
        db,
        targets=asset.ip_address,
        scan_type=scan_type,
        triggered_by="manual",
        result_summary=result_summary,
    )
    return str(job.id), should_start


async def run_asset_ai_refresh(db: AsyncSession, asset_id: UUID, *, job_id: str) -> None:
    asset = await _load_asset(db, asset_id)
    _, runtime_config = await read_effective_scanner_config(db)
    host = DiscoveredHost(
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        discovery_method="manual",
        nmap_hostname=asset.hostname,
    )
    ports, os_fp = await portscan.scan_host(host, ScanProfile.DEEP_ENRICHMENT)
    result = await _investigate_host(
        host=host,
        ports=ports,
        os_fp=os_fp,
        nmap_hostname=host.nmap_hostname,
        nmap_vendor=asset.vendor,
        profile=ScanProfile.DEEP_ENRICHMENT,
        analyst=get_analyst(runtime_config),
        run_deep_probes=True,
        deep_probe_timeout_seconds=6,
        semaphore=asyncio.Semaphore(1),
        broadcast_fn=None,
        job_id=job_id,
    )

    await upsert_scan_result(db, result)
    await db.commit()


async def run_asset_snmp_refresh(db: AsyncSession, asset_id: UUID, *, job_id: str) -> None:
    asset = await _load_asset(db, asset_id)
    _, runtime_config = await read_effective_scanner_config(db)
    if not runtime_config.snmp_enabled:
        raise RuntimeError("SNMP enrichment is disabled in Settings.")

    probe_result = await run_snmp_probe(
        asset.ip_address,
        community=runtime_config.snmp_community,
        version=runtime_config.snmp_version,
        timeout_seconds=runtime_config.snmp_timeout,
        v3_username=runtime_config.snmp_v3_username or None,
        v3_auth_key=runtime_config.snmp_v3_auth_key or None,
        v3_priv_key=runtime_config.snmp_v3_priv_key or None,
        v3_auth_protocol=runtime_config.snmp_v3_auth_protocol or None,
        v3_priv_protocol=runtime_config.snmp_v3_priv_protocol or None,
    )

    details = dict(probe_result.data or {})
    if probe_result.error and "error" not in details:
        details["error"] = probe_result.error
    now = datetime.now(timezone.utc)
    db.add(
        ProbeRun(
            asset_id=asset.id,
            probe_type=probe_result.probe_type,
            target_port=probe_result.target_port,
            success=probe_result.success,
            duration_ms=probe_result.duration_ms,
            summary=_probe_run_summary(details, probe_result.success),
            details=details,
            raw_excerpt=probe_result.raw[:4000] if probe_result.raw else None,
            observed_at=now,
        )
    )

    asset.heartbeat_last_checked_at = now
    if probe_result.success:
        was_offline = asset.status == "offline"
        asset.status = "online"
        asset.last_seen = now
        asset.heartbeat_missed_count = 0
        if was_offline:
            db.add(
                AssetHistory(
                    asset_id=asset.id,
                    change_type="status_change",
                    diff={"status": {"old": "offline", "new": "online"}},
                )
            )
        await infer_topology_links_from_snmp(db, asset, details)
    else:
        asset.heartbeat_missed_count = min((asset.heartbeat_missed_count or 0) + 1, 5)

    await db.commit()


def _probe_run_summary(details: dict, probe_success: bool) -> str | None:
    if not probe_success:
        error = details.get("error")
        return str(error)[:512] if error is not None else None
    summary = details.get("title") or details.get("sys_descr") or details.get("friendly_name") or details.get("banner")
    return str(summary)[:512] if summary is not None else None
