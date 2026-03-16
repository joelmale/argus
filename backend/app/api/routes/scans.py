"""Scan job management endpoints."""
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ScanJob
from app.db.session import get_db

router = APIRouter()


@router.get("/")
async def list_scans(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.post("/trigger")
async def trigger_scan(targets: str, scan_type: str = "full", db: AsyncSession = Depends(get_db)):
    """Enqueue a manual scan. The scanner worker picks this up via Redis."""
    job = ScanJob(targets=targets, scan_type=scan_type, triggered_by="manual")
    db.add(job)
    await db.commit()
    await db.refresh(job)
    # TODO: push job.id onto celery/redis task queue
    return {"job_id": str(job.id), "status": "queued"}


@router.get("/{job_id}")
async def get_scan(job_id: UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    return job
