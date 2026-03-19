"""Scan job management endpoints."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.db.models import ScanJob
from app.db.models import User
from app.db.session import get_db
from app.db.upsert import upsert_scan_result
from app.fingerprinting.passive import record_passive_observation
from app.ingestion.logs import parse_dns_dhcp_logs
from app.notifications import notify_new_device
from app.scanner.config import get_or_create_scanner_config, resolve_scan_targets
from app.workers.tasks import run_scan_job

router = APIRouter()


class TriggerScanRequest(BaseModel):
    targets: str | None = Field(default=None)
    scan_type: str = "balanced"


class IngestLogsRequest(BaseModel):
    content: str = Field(min_length=1)


@router.get("/")
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.post("/trigger")
async def trigger_scan(
    payload: TriggerScanRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    """Enqueue a manual scan. The scanner worker picks this up via Redis."""
    config = await get_or_create_scanner_config(db)
    try:
        targets = resolve_scan_targets(config, payload.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = ScanJob(targets=targets, scan_type=payload.scan_type, triggered_by="manual")
    db.add(job)
    await db.commit()
    await db.refresh(job)

    run_scan_job.delay(str(job.id))
    return {"job_id": str(job.id), "status": "queued"}


@router.post("/ingest/logs")
async def ingest_logs(
    payload: IngestLogsRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    observations = parse_dns_dhcp_logs(payload.content)

    new_assets = 0
    changed_assets = 0
    for result in observations:
        asset, change_type = await upsert_scan_result(db, result)
        await record_passive_observation(
            db,
            asset=asset,
            source="dhcp_log",
            event_type="lease",
            summary=f"Observed DHCP/DNS lease for {result.host.ip_address}",
            details={
                "ip": result.host.ip_address,
                "mac": result.host.mac_address,
                "hostname": result.reverse_hostname,
                "discovery_method": result.host.discovery_method,
            },
            observed_at=result.scanned_at,
        )
        if change_type == "discovered":
            new_assets += 1
            await notify_new_device(
                {
                    "ip": asset.ip_address,
                    "mac": asset.mac_address,
                    "hostname": asset.hostname,
                    "device_class": asset.effective_device_type,
                }
            )
        elif change_type == "updated":
            changed_assets += 1

    await db.commit()
    return {
        "records_parsed": len(observations),
        "new_assets": new_assets,
        "changed_assets": changed_assets,
    }


@router.get("/{job_id}")
async def get_scan(job_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    job = await db.get(ScanJob, job_id)
    return job
