from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.config import (
    get_or_create_scanner_config,
    materialize_scan_targets,
    resolve_scan_targets,
    validate_scan_targets_routable,
)
from app.db.models import ScanJob
from app.services.scan_queue import enqueue_scan_job
from app.workers.tasks import run_scan_job


async def enqueue_manual_scan(db: AsyncSession, *, targets: str | None, scan_type: str) -> tuple[ScanJob, bool]:
    config = await get_or_create_scanner_config(db)
    resolved_targets = resolve_scan_targets(config, targets)
    materialized_targets = materialize_scan_targets(resolved_targets)
    route_error = validate_scan_targets_routable(materialized_targets)
    if route_error:
        raise ValueError(route_error)

    job, should_start = await enqueue_scan_job(
        db,
        targets=materialized_targets,
        scan_type=scan_type,
        triggered_by="manual",
    )
    if should_start:
        run_scan_job.delay(str(job.id))
    return job, should_start
