"""Scan job management endpoints."""
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.db.models import ScanJob
from app.db.models import User
from app.db.session import get_db
from app.db.upsert import upsert_scan_result
from app.ingestion.logs import parse_dns_dhcp_logs
from app.notifications import notify_new_device
from app.workers.tasks import run_scan_job

router = APIRouter()


class TriggerScanRequest(BaseModel):
    targets: str = Field(min_length=1)
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
    job = ScanJob(targets=payload.targets, scan_type=payload.scan_type, triggered_by="manual")
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
        if change_type == "discovered":
            new_assets += 1
            await notify_new_device(
                {
                    "ip": asset.ip_address,
                    "mac": asset.mac_address,
                    "hostname": asset.hostname,
                    "device_class": asset.device_type or "unknown",
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
