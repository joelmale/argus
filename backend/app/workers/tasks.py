"""
Celery task definitions for the scanner worker.

Think of Celery as an assembly line: tasks are work orders placed on a conveyor
belt (Redis queue), and workers pick them up independently. This decouples scan
execution from the HTTP request lifecycle.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery("argus", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    beat_schedule={
        "scheduled-scan": {
            "task": "app.workers.tasks.run_scheduled_scan",
            "schedule": settings.SCANNER_INTERVAL_MINUTES * 60,
        }
    },
)


@celery_app.task(name="app.workers.tasks.run_scan_job")
def run_scan_job(job_id: str):
    """Execute a scan job by ID. Reads targets from DB, runs nmap, upserts assets."""
    # TODO: implement full scan pipeline
    #   1. Load ScanJob from DB
    #   2. Run NetworkScanner.scan(targets)
    #   3. Upsert Asset records, detect changes
    #   4. Write AssetHistory entries for diffs
    #   5. Update ScanJob.status = "done"
    #   6. Broadcast WebSocket event
    raise NotImplementedError(f"run_scan_job({job_id}) — Phase 1 implementation")


@celery_app.task(name="app.workers.tasks.run_scheduled_scan")
def run_scheduled_scan():
    """Periodic task — scan all configured default targets."""
    targets = settings.SCANNER_DEFAULT_TARGETS
    run_scan_job.delay(targets)
