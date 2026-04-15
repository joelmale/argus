from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.config import (
    get_or_create_scanner_config,
    materialize_scan_targets,
    resolve_scan_targets,
    validate_scan_targets_routable,
)
from app.workers.tasks import _has_active_scan, _next_queue_position, run_scan_job
from app.db.models import ScanJob


async def enqueue_manual_scan(db: AsyncSession, *, targets: str | None, scan_type: str) -> tuple[ScanJob, bool]:
    config = await get_or_create_scanner_config(db)
    resolved_targets = resolve_scan_targets(config, targets)
    materialized_targets = materialize_scan_targets(resolved_targets)
    route_error = validate_scan_targets_routable(materialized_targets)
    if route_error:
        raise ValueError(route_error)

    job = ScanJob(
        targets=materialized_targets,
        scan_type=scan_type,
        triggered_by="manual",
        queue_position=await _next_queue_position(db),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    should_start = not await _has_active_scan(db) and job.queue_position == 1
    if should_start:
        run_scan_job.delay(str(job.id))
    return job, should_start

