from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ScanJob

SCAN_QUEUE_LOCK_KEY = 6_178_231_911_204_913


async def acquire_scan_queue_lock(db: AsyncSession) -> None:
    await db.execute(select(func.pg_advisory_xact_lock(SCAN_QUEUE_LOCK_KEY)))


async def has_active_scan(db: AsyncSession) -> bool:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status.in_(("running", "paused")))
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def next_queue_position(db: AsyncSession) -> int:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    jobs = list(result.scalars().all())
    if not jobs:
        return 1
    max_position = max((job.queue_position or index + 1) for index, job in enumerate(jobs))
    return max_position + 1


async def normalize_pending_queue(db: AsyncSession) -> None:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    jobs = list(result.scalars().all())
    for index, job in enumerate(jobs, start=1):
        job.queue_position = index


async def get_next_queued_job(db: AsyncSession) -> ScanJob | None:
    await normalize_pending_queue(db)
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc(), ScanJob.created_at.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def enqueue_scan_job(
    db: AsyncSession,
    *,
    targets: str,
    scan_type: str,
    triggered_by: str,
    result_summary: dict | None = None,
) -> tuple[ScanJob, bool]:
    await acquire_scan_queue_lock(db)

    job = ScanJob(
        targets=targets,
        scan_type=scan_type,
        triggered_by=triggered_by,
        queue_position=await next_queue_position(db),
        result_summary=result_summary,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    should_start = not await has_active_scan(db) and job.queue_position == 1
    return job, should_start
