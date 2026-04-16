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
import hashlib
import json
import logging
import math
import threading
import time
from uuid import UUID

from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from datetime import datetime, timezone
from sqlalchemy import select

from app.core.config import settings
from app.db.models import Asset, AssetHistory, ScanJob
from app.services.asset_exports import EXPORT_JOB_FILENAMES, run_asset_export_job
from app.services.asset_refresh import AI_REFRESH_JOB_TYPE, SNMP_REFRESH_JOB_TYPE, run_asset_ai_refresh, run_asset_snmp_refresh
from app.services.scan_queue import acquire_scan_queue_lock, dispose_scan_queue_lock_engine

log = logging.getLogger(__name__)
_passive_arp_thread: threading.Thread | None = None
_queue_resume_thread: threading.Thread | None = None
_worker_engine = None
_worker_session_factory = None
_worker_sessionmaker_impl = None

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
        },
        "asset-heartbeat": {
            "task": "app.workers.tasks.run_asset_heartbeat_checks",
            "schedule": settings.ASSET_HEARTBEAT_INTERVAL_SECONDS,
        },
        "resume-paused-scans": {
            "task": "app.workers.tasks.run_resume_paused_scans",
            "schedule": 60,
        }
    },
)


def _get_active_scan_task_ids(job_id: str) -> list[str]:
    """Return active Celery task ids currently executing the given scan job."""
    try:
        inspector = celery_app.control.inspect()
        active = inspector.active() or {}
    except Exception as exc:
        log.warning("Unable to inspect active Celery tasks for scan %s: %s", job_id, exc)
        return []

    return [
        task_id
        for worker_tasks in active.values()
        for task in (worker_tasks or [])
        for task_id in [_get_scan_task_id(task, job_id)]
        if task_id is not None
    ]


def _get_scan_task_id(task: dict, job_id: str) -> str | None:
    if task.get("name") != "app.workers.tasks.run_scan_job":
        return None
    if _extract_scan_job_id(task, job_id) != job_id:
        return None
    task_id = task.get("id")
    return str(task_id) if task_id else None


def _extract_scan_job_id(task: dict, job_id: str) -> str | None:
    args = task.get("args", [])
    kwargs = task.get("kwargs", {})

    if isinstance(args, (list, tuple)) and args:
        return str(args[0])
    if isinstance(kwargs, dict) and "job_id" in kwargs:
        return str(kwargs["job_id"])
    if isinstance(args, str) and job_id in args:
        return job_id
    return None


def revoke_active_scan_job(job_id: str) -> bool:
    """Terminate active Celery tasks currently executing the given scan job."""
    task_ids = _get_active_scan_task_ids(job_id)
    revoked = False
    for task_id in task_ids:
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
        revoked = True
        log.info("Revoked active Celery task %s for scan job %s", task_id, job_id)

    return revoked


def _get_worker_session_factory():
    global _worker_engine, _worker_session_factory, _worker_sessionmaker_impl
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    if _worker_session_factory is None or _worker_sessionmaker_impl is not async_sessionmaker:
        _worker_engine = create_async_engine(settings.DATABASE_URL.get_secret_value(), echo=False)
        _worker_session_factory = async_sessionmaker(_worker_engine, expire_on_commit=False)
        _worker_sessionmaker_impl = async_sessionmaker
    return _worker_session_factory


async def _dispose_worker_database() -> None:
    global _worker_engine, _worker_session_factory, _worker_sessionmaker_impl
    if _worker_engine is not None:
        await _worker_engine.dispose()
    _worker_engine = None
    _worker_session_factory = None
    _worker_sessionmaker_impl = None
    await dispose_scan_queue_lock_engine()


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


@celery_app.task(name="app.workers.tasks.run_asset_heartbeat_checks")
def run_asset_heartbeat_checks():
    asyncio.run(_run_asset_heartbeat_checks_async())


@celery_app.task(name="app.workers.tasks.run_resume_paused_scans")
def run_resume_paused_scans():
    asyncio.run(_resume_paused_scans_async())


async def _run_job_async(job_id: str) -> None:
    """Async implementation of the scan job — runs the full pipeline."""
    from app.scanner.config import get_or_create_scanner_config, materialize_scan_targets, validate_scan_targets_routable
    from app.scanner.models import ScanProfile, ScanSummary
    from app.scanner.pipeline import ScanControlDecision, ScanControlInterrupt, _persist_results, run_scan

    session_factory = _get_worker_session_factory()

    async with session_factory() as db:
        job = await _get_runnable_job(db, job_id)
        if job is None:
            return

        if await _run_export_job_async(db, job, job_id):
            return

        if await _run_refresh_job_async(db, job, job_id):
            return

        if await _should_run_parent_job(db, job):
            await _run_parent_job_async(
                db,
                job,
                job_id,
                config_factory=get_or_create_scanner_config,
                scan_profile_enum=ScanProfile,
                scan_summary_model=ScanSummary,
                run_scan_fn=run_scan,
                persist_results=_persist_results,
                scan_control_decision=ScanControlDecision,
                scan_control_interrupt=ScanControlInterrupt,
            )
            return

        route_error = _prepare_scan_job_targets(
            job,
            materialize_scan_targets,
            validate_scan_targets_routable,
        )
        if route_error:
            await _fail_scan_job(db, job, job_id, route_error)
            return
        config = await get_or_create_scanner_config(db)
        await _mark_job_running(db, job)
        control_fn = _build_control_fn(db, job, ScanControlDecision)

        try:
            profile = _resolve_scan_profile(job.scan_type, ScanProfile)
            summary = ScanSummary(job_id=job_id, targets=job.targets, profile=profile)

            summary = await run_scan(
                job_id=job_id,
                targets=job.targets,
                profile=profile,
                enable_ai=_scan_config_value(
                    config,
                    "ai_after_scan_enabled",
                    settings.AI_ENABLE_PER_SCAN,
                ),
                concurrent_hosts=config.concurrent_hosts,
                host_chunk_size=_scan_config_value(config, "host_chunk_size", 64),
                top_ports_count=_scan_config_value(config, "top_ports_count", 1000),
                deep_probe_timeout_seconds=_scan_config_value(
                    config,
                    "deep_probe_timeout_seconds",
                    6,
                ),
                db_session=db,
                broadcast_fn=_get_job_broadcast_fn(db, job),
                control_fn=control_fn,
                mark_missing_offline=False,
            )

            await _complete_scan_job(db, job, job_id, summary)

        except ScanControlInterrupt as exc:
            await _handle_scan_interrupt(db, job, job_id, exc, summary, _persist_results)
        except Exception as exc:
            await _publish_scan_failure(db, job, job_id, exc)
            raise

        await _dispatch_next_scan_if_idle(db)


async def _run_refresh_job_async(db, job: ScanJob, job_id: str) -> bool:
    if job.scan_type not in {AI_REFRESH_JOB_TYPE, SNMP_REFRESH_JOB_TYPE}:
        return False

    asset_id = _extract_refresh_asset_id(job)
    job_label = "AI analysis refresh" if job.scan_type == AI_REFRESH_JOB_TYPE else "SNMP refresh"
    await _mark_job_running(db, job, message=f"Queued {job_label} for {job.targets}")
    await _publish_event({
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "running",
            "progress": 0.0,
            "message": f"Running {job_label}",
            "asset_id": str(asset_id),
            "job_type": job.scan_type,
        },
    })

    try:
        if job.scan_type == AI_REFRESH_JOB_TYPE:
            await run_asset_ai_refresh(db, asset_id, job_id=job_id)
        else:
            await run_asset_snmp_refresh(db, asset_id, job_id=job_id)

        await _complete_background_job(
            db,
            job,
            job_id,
            {
                "job_type": job.scan_type,
                "asset_id": str(asset_id),
                "stage": "done",
                "message": f"{job_label} completed",
            },
        )
    except Exception as exc:
        await _publish_scan_failure(db, job, job_id, exc)
        raise
    finally:
        await _dispatch_next_scan_if_idle(db)
    return True


async def _run_export_job_async(db, job: ScanJob, job_id: str) -> bool:
    if job.scan_type not in EXPORT_JOB_FILENAMES:
        return False

    await _mark_job_running(db, job, message=f"Queued export for {job.scan_type}")
    await _publish_event({
        "event": "scan_progress",
        "data": {
            "job_id": job_id,
            "stage": "running",
            "progress": 0.0,
            "message": f"Building export {job.scan_type}",
            "job_type": job.scan_type,
        },
    })

    try:
        await run_asset_export_job(db, job, job_id)
        summary = dict(job.result_summary or {})
        await _complete_background_job(db, job, job_id, summary)
    except Exception as exc:
        await _publish_scan_failure(db, job, job_id, exc)
        raise
    finally:
        await _dispatch_next_scan_if_idle(db)
    return True


def _extract_refresh_asset_id(job: ScanJob) -> UUID:
    summary = job.result_summary or {}
    asset_id = summary.get("asset_id")
    if not asset_id:
        raise ValueError("Refresh job missing asset_id")
    return UUID(str(asset_id))


async def _should_run_parent_job(db, job: ScanJob) -> bool:
    return job.parent_id is None and await _has_child_jobs(db, job.id)


def _prepare_scan_job_targets(
    job: ScanJob,
    materialize_scan_targets,
    validate_scan_targets_routable,
) -> str | None:
    job.targets = materialize_scan_targets(job.targets)
    return validate_scan_targets_routable(job.targets)


def _scan_config_value(config, key: str, default):
    return getattr(config, key, default)


async def _run_parent_job_async(
    db,
    job: ScanJob,
    job_id: str,
    *,
    config_factory,
    scan_profile_enum,
    scan_summary_model,
    run_scan_fn,
    persist_results,
    scan_control_decision,
    scan_control_interrupt,
) -> None:
    config = await config_factory(db)
    await _mark_job_running(db, job)
    profile = _resolve_scan_profile(job.scan_type, scan_profile_enum)
    summary = scan_summary_model(job_id=job_id, targets=job.targets, profile=profile)
    scanned_ips: set[str] = set()
    children = await _list_child_jobs(db, job.id)
    progress_state = {"last_flush": 0.0, "last_stage": None}

    for child in children:
        if child.status == "done":
            continue
        child_summary = await _run_parent_child_scan(
            db,
            job,
            child,
            job_id,
            children,
            profile,
            config,
            scanned_ips,
            progress_state,
            run_scan_fn=run_scan_fn,
            scan_control_decision=scan_control_decision,
            scan_control_interrupt=scan_control_interrupt,
            summary=summary,
        )
        if child_summary is None:
            return
        _merge_scan_summary(summary, child_summary)
        _record_parent_chunk_progress(job, child, summary)
        await db.commit()

    if scanned_ips:
        await persist_results(
            db,
            [],
            scanned_ips,
            summary,
            None,
            job_id,
            mark_missing_offline=False,
            stage="persist",
        )

    await _complete_scan_job(db, job, job_id, summary)
    await _publish_event({
        "event": "scan_complete",
        "data": summary.model_dump(mode="json"),
    })


async def _run_parent_child_scan(
    db,
    job: ScanJob,
    child: ScanJob,
    job_id: str,
    children: list[ScanJob],
    profile,
    config,
    scanned_ips: set[str],
    progress_state: dict,
    *,
    run_scan_fn,
    scan_control_decision,
    scan_control_interrupt,
    summary,
):
    _mark_child_running(child)
    await db.commit()
    child_broadcast = _build_parent_chunk_broadcast_fn(
        db,
        job,
        progress_state,
        chunk_index=child.chunk_index or 1,
        chunk_count=child.chunk_count or len(children) or 1,
    )
    control_fn = _build_control_fn(db, job, scan_control_decision)
    try:
        child_summary = await run_scan_fn(
            job_id=job_id,
            targets=child.targets,
            profile=profile,
            enable_ai=config.ai_after_scan_enabled,
            concurrent_hosts=config.concurrent_hosts,
            host_chunk_size=config.host_chunk_size,
            top_ports_count=config.top_ports_count,
            deep_probe_timeout_seconds=config.deep_probe_timeout_seconds,
            db_session=db,
            broadcast_fn=child_broadcast,
            control_fn=control_fn,
            mark_missing_offline=False,
            scanned_ips_buffer=scanned_ips,
        )
    except scan_control_interrupt as exc:
        await _handle_parent_child_interrupt(db, job, child, job_id, exc, summary)
        return None
    except Exception as exc:
        await _handle_parent_child_failure(db, job, child, job_id, exc)
        raise
    _mark_child_done(child, child_summary)
    return child_summary


def _mark_child_running(child: ScanJob) -> None:
    child.status = "running"
    child.started_at = datetime.now(timezone.utc)
    child.finished_at = None


def _mark_child_done(child: ScanJob, child_summary) -> None:
    child.status = "done"
    child.finished_at = datetime.now(timezone.utc)
    child.result_summary = child_summary.model_dump(mode="json")


def _record_parent_chunk_progress(job: ScanJob, child: ScanJob, summary) -> None:
    job.result_summary = {
        **summary.model_dump(mode="json"),
        "stage": "investigation",
        "chunk_index": child.chunk_index,
        "chunk_count": child.chunk_count,
        "message": f"Completed chunk {child.chunk_index}/{child.chunk_count}",
    }


async def _handle_parent_child_interrupt(db, job: ScanJob, child: ScanJob, job_id: str, exc, summary) -> None:
    child.status = exc.status
    child.finished_at = datetime.now(timezone.utc) if exc.status == "cancelled" else None
    child.result_summary = {
        **(child.result_summary or {}),
        **summary.model_dump(mode="json"),
        "stage": exc.status,
        "message": exc.message,
    }
    if exc.status == "cancelled":
        await _cancel_remaining_child_jobs(db, job.id, message=exc.message)
    await _apply_interrupt_result(db, job, exc, summary)
    await db.commit()
    await _publish_event({
        "event": "scan_complete",
        "data": {
            "job_id": job_id,
            "status": exc.status,
            "message": exc.message,
            "resume_after": exc.resume_after,
        },
    })


async def _handle_parent_child_failure(db, job: ScanJob, child: ScanJob, job_id: str, exc: Exception) -> None:
    child.status = "failed"
    child.finished_at = datetime.now(timezone.utc)
    child.result_summary = {"error": str(exc)}
    await db.commit()
    await _publish_scan_failure(db, job, job_id, exc)


def _build_parent_chunk_broadcast_fn(db, job, progress_state: dict, *, chunk_index: int, chunk_count: int):
    async def broadcast(payload: dict):
        event = payload.get("event")
        data = dict(payload.get("data", {}))
        if "job_id" in data:
            data["job_id"] = str(job.id)
        if event == "scan_complete":
            return
        if event == "scan_progress":
            child_progress = float(data.get("progress", 0.0) or 0.0)
            overall_progress = ((chunk_index - 1) + child_progress) / max(chunk_count, 1)
            data["progress"] = round(overall_progress, 3)
            data["chunk_index"] = chunk_index
            data["chunk_count"] = chunk_count
            message = data.get("message")
            if isinstance(message, str) and message:
                data["message"] = f"Chunk {chunk_index}/{chunk_count}: {message}"
            payload = {"event": event, "data": data}
            await _record_job_progress(db, job, payload, progress_state)
            await _publish_event(payload)
            return

        payload = {"event": event, "data": data}
        await _publish_event(payload)

    return broadcast


def _merge_scan_summary(parent_summary, child_summary) -> None:
    parent_summary.hosts_scanned += child_summary.hosts_scanned
    parent_summary.hosts_up += child_summary.hosts_up
    parent_summary.total_open_ports += child_summary.total_open_ports
    parent_summary.new_assets += child_summary.new_assets
    parent_summary.changed_assets += child_summary.changed_assets
    parent_summary.offline_assets += child_summary.offline_assets
    parent_summary.ai_analyses_completed += child_summary.ai_analyses_completed
    parent_summary.duration_seconds = round(parent_summary.duration_seconds + child_summary.duration_seconds, 2)


async def _has_child_jobs(db, parent_id) -> bool:
    result = await db.execute(select(ScanJob).where(ScanJob.parent_id == parent_id).limit(1))
    return result.scalar_one_or_none() is not None


async def _list_child_jobs(db, parent_id) -> list[ScanJob]:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id == parent_id)
        .order_by(ScanJob.chunk_index.asc().nullslast(), ScanJob.created_at.asc())
    )
    return list(result.scalars().all())


async def _cancel_remaining_child_jobs(db, parent_id, *, message: str) -> None:
    children = await _list_child_jobs(db, parent_id)
    finished_at = datetime.now(timezone.utc)
    for child in children:
        if child.status in {"done", "failed", "cancelled"}:
            continue
        child.status = "cancelled"
        child.finished_at = finished_at
        child.control_action = None
        child.control_mode = None
        child.result_summary = {
            **(child.result_summary or {}),
            "stage": "cancelled",
            "message": message,
        }
    await db.commit()


async def _get_runnable_job(db, job_id: str):
    job = await db.get(ScanJob, job_id)
    if job is None:
        log.error("ScanJob %s not found", job_id)
        return None
    if job.status == "cancelled":
        log.info("Skipping cancelled scan job: %s", job_id)
        return None
    if job.status == "paused":
        log.info("Skipping paused scan job until resumed: %s", job_id)
        return None
    return job


async def _fail_scan_job(db, job: ScanJob, job_id: str, route_error: str) -> None:
    job.status = "failed"
    job.finished_at = datetime.now(timezone.utc)
    job.control_action = None
    job.control_mode = None
    job.resume_after = None
    job.result_summary = {
        "stage": "failed",
        "message": route_error,
        "error": route_error,
    }
    await db.commit()
    await _publish_event({
        "event": "scan_complete",
        "data": {
            "job_id": job_id,
            "status": "failed",
            "error": route_error,
        },
    })
    await _dispatch_next_scan_if_idle(db)


async def _mark_job_running(db, job: ScanJob, message: str | None = None) -> None:
    job.status = "running"
    job.queue_position = None
    job.control_action = None
    job.started_at = datetime.now(timezone.utc)
    await db.commit()
    job.result_summary = {
        "stage": "queued",
        "progress": 0.0,
        "message": message or f"Queued scan for {job.targets}",
    }
    await db.commit()


def _build_control_fn(db, job, scan_control_decision):
    async def control_fn():
        await db.refresh(job)
        return _scan_control_decision_from_job(job, scan_control_decision)

    return control_fn


def _scan_control_decision_from_job(job, scan_control_decision):
    if job.control_action == "cancel":
        return scan_control_decision(
            action="cancel",
            mode=job.control_mode or "discard",
            message="Operator cancelled scan",
        )
    if job.control_action == "requeue":
        return scan_control_decision(
            action="pause",
            mode="requeue",
            message="Operator preempted scan and returned it to the queue",
        )
    if job.control_action == "pause":
        return scan_control_decision(
            action="pause",
            mode=job.control_mode or "preserve_discovery",
            resume_after=job.resume_after.isoformat() if job.resume_after else None,
            message="Operator paused scan",
        )
    return None


def _resolve_scan_profile(scan_type: str, scan_profile_enum):
    from app.scanner.models import LEGACY_SCAN_PROFILE_ALIASES

    try:
        return scan_profile_enum(scan_type)
    except ValueError:
        return LEGACY_SCAN_PROFILE_ALIASES.get(scan_type, scan_profile_enum.BALANCED)


async def _complete_scan_job(db, job: ScanJob, job_id: str, summary) -> None:
    job.status = "done"
    job.finished_at = datetime.now(timezone.utc)
    job.result_summary = summary.model_dump(mode="json")
    await db.commit()
    log.info("Scan job %s completed: %s", job_id, summary.model_dump(mode="json"))
    await _publish_event({"event": "topology:updated", "data": {}})


async def _complete_background_job(db, job: ScanJob, job_id: str, summary: dict) -> None:
    job.status = "done"
    job.finished_at = datetime.now(timezone.utc)
    job.result_summary = summary
    await db.commit()
    log.info("Background job %s completed: %s", job_id, summary)
    await _publish_event({
        "event": "scan_complete",
        "data": {
            "job_id": job_id,
            "status": "done",
            **summary,
        },
    })


async def _handle_scan_interrupt(db, job, job_id: str, exc, summary, persist_results) -> None:
    summary = exc.summary or summary
    if exc.partial_results:
        await persist_results(
            db,
            exc.partial_results,
            exc.scanned_ips,
            summary,
            _get_job_broadcast_fn(db, job),
            job_id,
            mark_missing_offline=exc.mark_missing_offline,
            allow_discovery_only=True,
        )

    await _apply_interrupt_result(db, job, exc, summary)
    await db.commit()
    await _publish_event({
        "event": "scan_complete",
        "data": {
            "job_id": job_id,
            "status": exc.status,
            "message": exc.message,
            "resume_after": exc.resume_after,
            "preserved_hosts": len(exc.scanned_ips),
        },
    })


async def _apply_interrupt_result(db, job, exc, summary) -> None:
    _apply_interrupt_status(job, exc.status)

    job.result_summary = {
        **summary.model_dump(mode="json"),
        **(job.result_summary or {}),
        "stage": _interrupt_stage(job.status, exc.status),
        "message": exc.message,
        "resume_after": exc.resume_after,
        "preserved_hosts": len(exc.scanned_ips),
    }
    if job.status == "pending":
        job.resume_after = None
        job.queue_position = await _next_queue_position(db)
    elif exc.status == "paused":
        job.resume_after = datetime.fromisoformat(exc.resume_after) if exc.resume_after else None
    else:
        job.resume_after = None
    job.control_action = None
    job.control_mode = None


def _apply_interrupt_status(job, interrupt_status: str) -> None:
    if interrupt_status == "paused" and job.control_mode == "requeue":
        job.status = "pending"
        job.started_at = None
        job.finished_at = None
        return
    job.status = interrupt_status
    job.finished_at = datetime.now(timezone.utc) if interrupt_status == "cancelled" else None


def _interrupt_stage(job_status: str, interrupt_status: str) -> str:
    if job_status == "pending":
        return "queued"
    if interrupt_status == "paused":
        return "paused"
    return "cancelled"


async def _publish_scan_failure(db, job: ScanJob, job_id: str, exc: Exception) -> None:
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


async def _enqueue_scheduled_scan() -> None:
    """Create and enqueue a ScanJob for the default targets."""
    from app.db.models import ScanJob
    from app.scanner.config import get_or_create_scanner_config, resolve_scan_targets, should_enqueue_scheduled_scan, split_scan_targets

    session_factory = _get_worker_session_factory()
    job_id: str | None = None
    should_start = False
    targets: str | None = None

    async with session_factory() as db:
        async with acquire_scan_queue_lock(db):
            config = await get_or_create_scanner_config(db)
            if not should_enqueue_scheduled_scan(config):
                if not getattr(config, "scheduled_scans_enabled", False):
                    log.debug("Scheduled scan skipped: scheduler disabled")
                return
            existing_scheduled = await db.scalar(
                select(ScanJob.id).where(
                    ScanJob.parent_id.is_(None),
                    ScanJob.triggered_by == "schedule",
                    ScanJob.status.in_(("pending", "running", "paused")),
                ).limit(1)
            )
            if existing_scheduled is not None:
                log.info("Scheduled scan skipped: existing scheduled job is still active (job_id=%s)", existing_scheduled)
                return
            targets = resolve_scan_targets(config, None)
            job = ScanJob(
                targets=targets,
                scan_type=config.default_profile,
                triggered_by="schedule",
                queue_position=await _next_queue_position(db),
            )
            db.add(job)
            await db.flush()
            child_targets = split_scan_targets(targets)
            if len(child_targets) > 1:
                job.result_summary = {
                    "stage": "queued",
                    "message": f"Queued parent scan with {len(child_targets)} child chunks",
                    "chunk_count": len(child_targets),
                }
                for index, child_target in enumerate(child_targets, start=1):
                    db.add(ScanJob(
                        parent_id=job.id,
                        targets=child_target,
                        scan_type=config.default_profile,
                        triggered_by="schedule",
                        status="pending",
                        queue_position=None,
                        chunk_index=index,
                        chunk_count=len(child_targets),
                        result_summary={
                            "stage": "queued",
                            "message": f"Queued chunk {index}/{len(child_targets)}",
                        },
                    ))
            else:
                job.targets = child_targets[0]
            config.last_scheduled_scan_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(job)
            job_id = str(job.id)
            should_start = not await _has_active_scan(db) and job.queue_position == 1

    if job_id and should_start:
        run_scan_job.delay(job_id)
        log.info("Scheduled scan started immediately: job_id=%s targets=%s", job_id, targets)
    elif job_id:
        log.info("Scheduled scan queued: job_id=%s targets=%s", job_id, targets)


async def _run_scheduled_backups_async() -> None:
    from app.backups import run_scheduled_backups as execute_scheduled_backups

    session_factory = _get_worker_session_factory()
    async with session_factory() as db:
        result = await execute_scheduled_backups(db)
        log.info("Scheduled backups checked: %s", result)


async def _run_asset_heartbeat_checks_async() -> None:
    from app.alerting import notify_devices_offline_if_enabled
    from app.scanner.stages.discovery import ping_hosts_sync
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(settings.DATABASE_URL.get_secret_value(), echo=False, poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            result = await db.execute(select(Asset).order_by(Asset.ip_address.asc()))
            assets = [asset for asset in result.scalars().all() if asset.ip_address]
            if not assets:
                return

            checked_at = datetime.now(timezone.utc)
            slot_count = _heartbeat_slot_count(
                interval_seconds=settings.ASSET_HEARTBEAT_INTERVAL_SECONDS,
                target_interval_seconds=settings.ASSET_HEARTBEAT_TARGET_INTERVAL_SECONDS,
            )
            assets = _select_assets_for_heartbeat_slot(
                assets,
                checked_at=checked_at,
                interval_seconds=settings.ASSET_HEARTBEAT_INTERVAL_SECONDS,
                slot_count=slot_count,
            )
            if not assets:
                return

            responsive_hosts = await asyncio.to_thread(
                ping_hosts_sync,
                [asset.ip_address for asset in assets],
                host_timeout_seconds=settings.ASSET_HEARTBEAT_TIMEOUT_SECONDS,
                batch_size=settings.ASSET_HEARTBEAT_BATCH_SIZE,
            )
            responsive_ips = {host.ip_address for host in responsive_hosts}
            status_changes, offline_notifications = _reconcile_asset_heartbeats(
                assets,
                responsive_ips,
                checked_at,
                miss_threshold=settings.ASSET_HEARTBEAT_MISS_THRESHOLD,
            )

            for asset, diff in status_changes:
                db.add(AssetHistory(
                    asset_id=asset.id,
                    change_type="status_change",
                    diff={"status": diff},
                ))

            await db.commit()

        if offline_notifications:
            async with session_factory() as notify_db:
                await notify_devices_offline_if_enabled(notify_db, offline_notifications)

        for asset, _diff in status_changes:
            await _publish_event(_asset_status_change_payload(asset))
    finally:
        await engine.dispose()


async def _resume_paused_scans_async() -> None:
    from sqlalchemy import select
    from app.db.models import ScanJob

    session_factory = _get_worker_session_factory()
    now = datetime.now(timezone.utc)
    first_job_id: str | None = None

    async with session_factory() as db:
        async with acquire_scan_queue_lock(db):
            result = await db.execute(
                select(ScanJob).where(
                    ScanJob.status == "paused",
                    ScanJob.resume_after.is_not(None),
                    ScanJob.resume_after <= now,
                )
            )
            jobs = list(result.scalars().all())
            for job in jobs:
                _resume_paused_job(job, now)
            await db.commit()

            await _normalize_pending_queue(db)
            should_start = jobs and not await _has_active_scan(db)
            next_job = await _get_next_queued_job(db) if should_start else None
            first_job_id = str(next_job.id) if next_job is not None else None

    if first_job_id:
        run_scan_job.delay(first_job_id)
        log.info("Resumed paused queue; started job_id=%s", first_job_id)


def _resume_paused_job(job, now: datetime) -> None:
    job.status = "pending"
    job.control_action = None
    job.control_mode = None
    job.resume_after = None
    job.queue_position = 1
    summary = dict(job.result_summary or {})
    summary.update(
        {
            "stage": "queued",
            "message": "Resuming paused scan by restarting the job",
            "resumed_at": now.isoformat(),
        }
    )
    job.result_summary = summary


async def _has_active_scan(db) -> bool:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status.in_(("running", "paused")))
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def _next_queue_position(db) -> int:
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


async def _normalize_pending_queue(db) -> None:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    jobs = list(result.scalars().all())
    for index, job in enumerate(jobs, start=1):
        job.queue_position = index


async def _get_next_queued_job(db):
    await _normalize_pending_queue(db)
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc(), ScanJob.created_at.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _dispatch_next_scan_if_idle(db) -> None:
    async with acquire_scan_queue_lock(db):
        if await _has_active_scan(db):
            return
        next_job = await _get_next_queued_job(db)
        if next_job is None:
            return
        await db.commit()
        run_scan_job.delay(str(next_job.id))
        log.info("Queued scan started: job_id=%s queue_position=%s", next_job.id, next_job.queue_position)


async def _resume_pending_queue_on_startup() -> None:
    session_factory = _get_worker_session_factory()

    async with session_factory() as db:
        async with acquire_scan_queue_lock(db):
            if await _has_active_scan(db):
                return
            next_job = await _get_next_queued_job(db)
            if next_job is None:
                return
            await db.commit()
            run_scan_job.delay(str(next_job.id))
            log.info("Scanner startup resumed queued scan: job_id=%s queue_position=%s", next_job.id, next_job.queue_position)


def _get_broadcast_fn():
    """Return a broadcast function that publishes events to Redis pub/sub."""
    return _publish_event


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


def _publish_event_sync(payload: dict) -> None:
    import redis

    r = redis.from_url(settings.REDIS_URL)
    try:
        r.publish("argus:events", json.dumps(payload))
    except Exception as exc:
        log.debug("Redis publish error: %s", exc)
    finally:
        r.close()


async def _publish_event(payload: dict) -> None:
    await asyncio.to_thread(_publish_event_sync, payload)


def _asset_status_change_payload(asset: Asset) -> dict:
    return {
        "event": "device_status_change",
        "data": {
            "id": str(asset.id),
            "status": asset.status,
        },
    }


def _asset_offline_notification_payload(asset: Asset) -> dict[str, str | None]:
    return {
        "ip": asset.ip_address,
        "hostname": asset.hostname,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


def _heartbeat_slot_count(*, interval_seconds: int, target_interval_seconds: int) -> int:
    if interval_seconds <= 0 or target_interval_seconds <= 0:
        return 1
    return max(1, math.ceil(target_interval_seconds / interval_seconds))


def _heartbeat_slot_index(
    checked_at: datetime,
    *,
    interval_seconds: int,
    slot_count: int,
) -> int:
    if interval_seconds <= 0 or slot_count <= 1:
        return 0
    return (int(checked_at.timestamp()) // interval_seconds) % slot_count


def _heartbeat_slot_for_asset(asset: Asset, *, slot_count: int) -> int:
    if slot_count <= 1:
        return 0
    digest = hashlib.sha1(asset.ip_address.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % slot_count


def _select_assets_for_heartbeat_slot(
    assets: list[Asset],
    *,
    checked_at: datetime,
    interval_seconds: int,
    slot_count: int,
) -> list[Asset]:
    slot_index = _heartbeat_slot_index(
        checked_at,
        interval_seconds=interval_seconds,
        slot_count=slot_count,
    )
    return [
        asset
        for asset in assets
        if _heartbeat_slot_for_asset(asset, slot_count=slot_count) == slot_index
    ]


def _reconcile_asset_heartbeats(
    assets: list[Asset],
    responsive_ips: set[str],
    checked_at: datetime,
    *,
    miss_threshold: int,
) -> tuple[list[tuple[Asset, dict[str, str]]], list[dict[str, str | None]]]:
    status_changes: list[tuple[Asset, dict[str, str]]] = []
    offline_notifications: list[dict[str, str | None]] = []

    for asset in assets:
        status_diff = _apply_asset_heartbeat(
            asset,
            is_reachable=asset.ip_address in responsive_ips,
            checked_at=checked_at,
            miss_threshold=miss_threshold,
        )
        if status_diff is None:
            continue
        status_changes.append((asset, status_diff))
        if status_diff["new"] == "offline":
            offline_notifications.append(_asset_offline_notification_payload(asset))

    return status_changes, offline_notifications


def _apply_asset_heartbeat(
    asset: Asset,
    *,
    is_reachable: bool,
    checked_at: datetime,
    miss_threshold: int,
) -> dict[str, str] | None:
    previous_status = asset.status
    asset.heartbeat_last_checked_at = checked_at

    if is_reachable:
        asset.heartbeat_missed_count = 0
        asset.last_seen = checked_at
        if asset.status != "online":
            asset.status = "online"
            return {"old": previous_status, "new": "online"}
        return None

    asset.heartbeat_missed_count = min((asset.heartbeat_missed_count or 0) + 1, miss_threshold)
    if asset.heartbeat_missed_count < miss_threshold:
        return None
    if asset.status == "offline":
        return None

    asset.status = "offline"
    return {"old": previous_status, "new": "offline"}


@worker_ready.connect
def _start_passive_arp_listener(**_: object) -> None:
    global _passive_arp_thread
    if not settings.SCANNER_PASSIVE_ARP:
        return
    if _passive_arp_thread and _passive_arp_thread.is_alive():
        return

    _passive_arp_thread = threading.Thread(target=_run_passive_arp_listener, daemon=True)
    _passive_arp_thread.start()


@worker_ready.connect
def _resume_scan_queue_on_worker_ready(**_: object) -> None:
    global _queue_resume_thread
    if _queue_resume_thread and _queue_resume_thread.is_alive():
        return

    _queue_resume_thread = threading.Thread(target=_run_resume_pending_queue_on_startup, daemon=True)
    _queue_resume_thread.start()


@worker_shutdown.connect
def _shutdown_worker_database(**_: object) -> None:
    if _worker_engine is None:
        return
    asyncio.run(_dispose_worker_database())


def _run_passive_arp_listener() -> None:
    asyncio.run(_passive_arp_loop())


def _run_resume_pending_queue_on_startup() -> None:
    asyncio.run(_resume_pending_queue_on_startup())


async def _passive_arp_loop() -> None:
    from app.alerting import notify_new_device_if_enabled

    from app.db.upsert import upsert_scan_result
    from app.fingerprinting.passive import record_passive_observation
    from app.scanner.config import build_effective_scanner_config, get_or_create_scanner_config
    from app.scanner.models import HostScanResult, ScanProfile
    from app.scanner.stages.discovery import PassiveArpListener

    session_factory = _get_worker_session_factory()
    listener: PassiveArpListener | None = None

    try:
        async with session_factory() as db:
            config = await get_or_create_scanner_config(db)
            effective = build_effective_scanner_config(config)

        interface = effective.passive_arp_effective_interface
        if not effective.passive_arp_enabled or not interface:
            log.warning(
                "Passive ARP listener disabled: no viable interface detected (configured=%s effective_targets=%s)",
                effective.passive_arp_interface,
                effective.effective_targets,
            )
            return

        log.info(
            "Passive ARP listener starting on interface %s (%s)",
            interface,
            "auto-detected" if effective.passive_arp_interface_auto else "configured",
        )
        listener = PassiveArpListener(interface=interface)
        async for host in listener.listen():
            async with session_factory() as db:
                asset, change_type = await upsert_scan_result(
                    db,
                    HostScanResult(host=host, scan_profile=ScanProfile.BALANCED),
                )
                await record_passive_observation(
                    db,
                    asset=asset,
                    source="passive_arp",
                    event_type="seen",
                    summary=f"Observed ARP traffic from {host.ip_address}",
                    details={
                        "ip": host.ip_address,
                        "mac": host.mac_address,
                        "discovery_method": host.discovery_method,
                    },
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
        if listener is not None:
            listener.stop()
