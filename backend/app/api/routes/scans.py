"""Scan job management endpoints."""
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ScanJob
from app.db.session import get_db
from app.workers.tasks import run_scan_job

router = APIRouter()


class TriggerScanRequest(BaseModel):
    targets: str = Field(min_length=1)
    scan_type: str = "balanced"


@router.get("/")
async def list_scans(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.post("/trigger")
async def trigger_scan(payload: TriggerScanRequest, db: AsyncSession = Depends(get_db)):
    """Enqueue a manual scan. The scanner worker picks this up via Redis."""
    job = ScanJob(targets=payload.targets, scan_type=payload.scan_type, triggered_by="manual")
    db.add(job)
    await db.commit()
    await db.refresh(job)

    run_scan_job.delay(str(job.id))
    return {"job_id": str(job.id), "status": "queued"}


@router.get("/{job_id}")
async def get_scan(job_id: UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    return job
