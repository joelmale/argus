"""
Celery task definitions for the scanner worker.

Celery is the "delivery system" between the API (which enqueues jobs) and
the scanner (which does the actual work). The API drops a job_id onto Redis;
a Celery worker picks it up and runs the full pipeline.

Celery Beat handles periodic scans via the beat_schedule config below.
The scanner container runs both worker + beat in the same process (see CMD
in scanner/Dockerfile).
"""
import asyncio
import json
import logging
import threading
import time

from celery import Celery
from celery.signals import worker_ready
from datetime import datetime, timezone

from app.core.config import settings

log = logging.getLogger(__name__)
_passive_arp_thread: threading.Thread | None = None

celery_app = Celery("argus", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    worker_concurrency=2,       # Limit Celery worker threads — scanner is CPU-bound
    task_acks_late=True,        # Don't ack until task completes (safe re-delivery)
    task_reject_on_worker_lost=True,
    beat_schedule={
        "scheduled-scan": {
            "task": "app.workers.tasks.run_scheduled_scan",
            "schedule": 60,
        },
        "scheduled-backups": {
            "task": "app.workers.tasks.run_scheduled_backups",
            "schedule": 60 * 60,
        }
    },
)


@celery_app.task(name="app.workers.tasks.run_scan_job", bind=True, max_retries=2)
def run_scan_job(self, job_id: str):
    """
    Execute a complete scan pipeline for a ScanJob.

    1. Load ScanJob from DB (get targets, profile, enable_ai)
    2. Update status → running
    3. Run the full pipeline (discovery → ports → probes → AI → persist)
    4. Update ScanJob status → done with result_summary
    5. Any exception: status → failed, retry up to 2x
    """
    log.info("Starting scan job: %s", job_id)
    asyncio.run(_run_job_async(job_id))


@celery_app.task(name="app.workers.tasks.run_scheduled_scan")
def run_scheduled_scan():
    """Periodic task — enqueue a scan of all configured default targets."""
    asyncio.run(_enqueue_scheduled_scan())


@celery_app.task(name="app.workers.tasks.run_scheduled_backups")
def run_scheduled_backups():
    asyncio.run(_run_scheduled_backups_async())


async def _run_job_async(job_id: str) -> None:
    """Async implementation of the scan job — runs the full pipeline."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.db.models import ScanJob
    from app.scanner.config import get_or_create_scanner_config, materialize_scan_targets
    from app.scanner.models import ScanProfile
    from app.scanner.pipeline import run_scan

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as db:
        # Load the job
        job = await db.get(ScanJob, job_id)
        if job is None:
            log.error("ScanJob %s not found", job_id)
            return

        # Mark as running
        job.targets = materialize_scan_targets(job.targets)
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        config = await get_or_create_scanner_config(db)
        await db.commit()

        job.result_summary = {
            "stage": "queued",
            "progress": 0.0,
            "message": f"Queued scan for {job.targets}",
        }
        await db.commit()

        try:
            try:
                profile = ScanProfile(job.scan_type)
            except ValueError:
                profile = ScanProfile.BALANCED
            enable_ai = settings.AI_ENABLE_PER_SCAN

            summary = await run_scan(
                job_id=job_id,
                targets=job.targets,
                profile=profile,
                enable_ai=enable_ai,
                concurrent_hosts=config.concurrent_hosts,
                db_session=db,
                broadcast_fn=_get_job_broadcast_fn(db, job),
            )

            job.status = "done"
            job.finished_at = datetime.now(timezone.utc)
            job.result_summary = summary.model_dump(mode="json")
            await db.commit()

            log.info("Scan job %s completed: %s", job_id, summary.model_dump(mode="json"))

        except Exception as exc:
            log.exception("Scan job %s failed: %s", job_id, exc)
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            job.result_summary = {"error": str(exc)}
            await db.commit()
            await _publish_event({
                "event": "scan_complete",
                "data": {
                    "job_id": job_id,
                    "status": "failed",
                    "error": str(exc),
                },
            })
            raise

    await engine.dispose()


async def _enqueue_scheduled_scan() -> None:
    """Create and enqueue a ScanJob for the default targets."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy import select
    from app.db.models import ScanJob
    from app.scanner.config import get_or_create_scanner_config, resolve_scan_targets, should_enqueue_scheduled_scan

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as db:
        config = await get_or_create_scanner_config(db)
        if not should_enqueue_scheduled_scan(config):
            return
        existing_job = (
            await db.execute(
                select(ScanJob).where(ScanJob.status.in_(("pending", "running")))
            )
        ).scalar_one_or_none()
        if existing_job is not None:
            log.info("Skipping scheduled scan enqueue; scan already active: job_id=%s status=%s", existing_job.id, existing_job.status)
            return
        targets = resolve_scan_targets(config, None)
        job = ScanJob(
            targets=targets,
            scan_type=config.default_profile,
            triggered_by="schedule",
        )
        config.last_scheduled_scan_at = datetime.now(timezone.utc)
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = str(job.id)

    await engine.dispose()

    # Enqueue the actual work
    run_scan_job.delay(job_id)
    log.info("Scheduled scan enqueued: job_id=%s targets=%s", job_id, targets)


async def _run_scheduled_backups_async() -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.backups import run_scheduled_backups as execute_scheduled_backups

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as db:
        result = await execute_scheduled_backups(db)
        log.info("Scheduled backups checked: %s", result)

    await engine.dispose()


def _get_broadcast_fn():
    """Return a broadcast function that publishes events to Redis pub/sub."""
    async def broadcast(payload: dict):
        await _publish_event(payload)

    return broadcast


def _get_job_broadcast_fn(db, job):
    progress_state = {"last_flush": 0.0, "last_stage": None}

    async def broadcast(payload: dict):
        await _record_job_progress(db, job, payload, progress_state)
        await _publish_event(payload)

    return broadcast


async def _record_job_progress(db, job, payload: dict, progress_state: dict) -> None:
    if payload.get("event") != "scan_progress":
        return

    data = payload.get("data", {})
    summary = dict(job.result_summary or {})
    summary.update(data)
    job.result_summary = summary

    now = time.monotonic()
    stage = data.get("stage")
    should_flush = stage != progress_state["last_stage"] or (now - progress_state["last_flush"]) >= 5.0
    if should_flush:
        progress_state["last_stage"] = stage
        progress_state["last_flush"] = now
        await db.commit()


async def _publish_event(payload: dict) -> None:
    import redis

    r = redis.from_url(settings.REDIS_URL)
    try:
        r.publish("argus:events", json.dumps(payload))
    except Exception as exc:
        log.debug("Redis publish error: %s", exc)
    finally:
        r.close()


@worker_ready.connect
def _start_passive_arp_listener(**_: object) -> None:
    global _passive_arp_thread
    if not settings.SCANNER_PASSIVE_ARP:
        return
    if _passive_arp_thread and _passive_arp_thread.is_alive():
        return

    _passive_arp_thread = threading.Thread(target=_run_passive_arp_listener, daemon=True)
    _passive_arp_thread.start()


def _run_passive_arp_listener() -> None:
    asyncio.run(_passive_arp_loop())


async def _passive_arp_loop() -> None:
    from app.alerting import notify_new_device_if_enabled
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.upsert import upsert_scan_result
    from app.scanner.models import HostScanResult, ScanProfile
    from app.scanner.stages.discovery import PassiveArpListener

    listener = PassiveArpListener(interface=settings.SCANNER_PASSIVE_ARP_INTERFACE)
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async for host in listener.listen():
            async with Session() as db:
                asset, change_type = await upsert_scan_result(
                    db,
                    HostScanResult(host=host, scan_profile=ScanProfile.BALANCED),
                )
                await db.commit()

                if change_type == "discovered":
                    payload = {
                        "event": "device_discovered",
                        "data": {
                            "ip": asset.ip_address,
                            "mac": asset.mac_address,
                            "hostname": asset.hostname,
                            "device_class": asset.effective_device_type,
                        },
                    }
                    await _publish_event(payload)
                    await notify_new_device_if_enabled(db, payload["data"])
    finally:
        listener.stop()
        await engine.dispose()
