"""Scan job management endpoints."""
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
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
from app.scanner.config import (
    get_or_create_scanner_config,
    materialize_scan_targets,
    resolve_scan_targets,
    split_scan_targets,
    validate_scan_targets_routable,
)
from app.workers.tasks import (
    _get_active_scan_task_ids,
    _get_next_queued_job,
    _has_active_scan,
    _next_queue_position,
    _normalize_pending_queue,
    _publish_event,
    revoke_active_scan_job,
    run_scan_job,
)

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]


class TriggerScanRequest(BaseModel):
    targets: str | None = Field(default=None)
    scan_type: str = "balanced"


class IngestLogsRequest(BaseModel):
    content: str = Field(min_length=1)


class ScanControlRequest(BaseModel):
    action: str
    mode: str | None = None
    resume_in_minutes: int | None = None


class ScanQueueRequest(BaseModel):
    action: str


SCAN_NOT_FOUND_DETAIL = "Scan not found"
SCAN_NOT_FOUND_RESPONSE = {404: {"description": SCAN_NOT_FOUND_DETAIL}}
TRIGGER_SCAN_RESPONSES = {400: {"description": "Invalid or unroutable scan targets"}}
SCAN_CONTROL_RESPONSES = {
    400: {"description": "Unsupported or invalid scan control request"},
    404: {"description": SCAN_NOT_FOUND_DETAIL},
    409: {"description": "Scan is not in a valid state for this action"},
}
SCAN_QUEUE_RESPONSES = {
    400: {"description": "Unsupported queue action"},
    404: {"description": SCAN_NOT_FOUND_DETAIL},
    409: {"description": "Scan cannot be reordered in its current state"},
}
SCAN_NOT_FOUND_ERROR = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=SCAN_NOT_FOUND_DETAIL)


def _mark_job_cancelled(job: ScanJob, *, finished_at: datetime, message: str) -> None:
    job.status = "cancelled"
    job.finished_at = finished_at
    job.resume_after = None
    job.result_summary = {
        **(job.result_summary or {}),
        "stage": "cancelled",
        "message": message,
        "preserved_hosts": 0,
    }
    job.control_action = None
    job.control_mode = None


async def _cancel_child_scan_jobs(db: AsyncSession, parent_id: UUID | str, *, message: str) -> None:
    result = await db.execute(select(ScanJob).where(ScanJob.parent_id == parent_id))
    finished_at = datetime.now(timezone.utc)
    for child in result.scalars().all():
        if child.status in {"done", "failed", "cancelled"}:
            continue
        child.status = "cancelled"
        child.finished_at = finished_at
        child.control_action = None
        child.control_mode = None
        child.resume_after = None
        child.result_summary = {
            **(child.result_summary or {}),
            "stage": "cancelled",
            "message": message,
        }


async def _resume_scan_job(job: ScanJob, db: AsyncSession) -> dict:
    if job.status != "paused":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only paused scans can be resumed")

    job.status = "pending"
    job.control_action = None
    job.control_mode = None
    job.resume_after = None
    summary = dict(job.result_summary or {})
    summary.update({
        "stage": "queued",
        "message": "Operator resumed scan; restarting job",
        "resumed_at": datetime.now(timezone.utc).isoformat(),
    })
    job.result_summary = summary
    await db.commit()
    run_scan_job.delay(str(job.id))
    return {"status": "pending", "message": "Scan resume queued"}


async def _pause_scan_job(job: ScanJob, payload: ScanControlRequest, db: AsyncSession) -> dict:
    if payload.resume_in_minutes not in {15, 30, 60, 240, 720}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pause duration must be one of 15, 30, 60, 240, 720 minutes")
    if job.status not in {"pending", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending or running scans can be paused")

    resume_after = datetime.now(timezone.utc) + timedelta(minutes=payload.resume_in_minutes)
    job.control_action = "pause"
    job.control_mode = "preserve_discovery"
    job.resume_after = resume_after
    if job.status == "pending":
        job.status = "paused"
        job.result_summary = {
            **(job.result_summary or {}),
            "stage": "paused",
            "message": "Paused before execution",
            "resume_after": resume_after.isoformat(),
        }
    await db.commit()
    return {"status": job.status, "message": "Pause requested", "resume_after": resume_after.isoformat()}


async def _cancel_scan_job(job: ScanJob, mode: str, db: AsyncSession) -> tuple[bool, bool]:
    if job.status not in {"pending", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending or running scans can be cancelled")
    if mode not in {"discard", "preserve_discovery"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cancel mode must be discard or preserve_discovery")

    job.control_action = "cancel"
    job.control_mode = mode
    finished_at = datetime.now(timezone.utc)
    terminated = False
    orphaned_cancel = False

    if job.status == "running" and mode == "discard":
        terminated = bool(_get_active_scan_task_ids(str(job.id)))
        if terminated:
            revoke_active_scan_job(str(job.id))
        else:
            orphaned_cancel = True

        if terminated or orphaned_cancel:
            message = "Operator terminated scan" if terminated else "Operator cancelled stale running scan"
            await _cancel_child_scan_jobs(db, job.id, message=message)
            _mark_job_cancelled(
                job,
                finished_at=finished_at,
                message=message,
            )

    if job.status == "pending":
        await _cancel_child_scan_jobs(db, job.id, message="Cancelled before execution")
        _mark_job_cancelled(job, finished_at=finished_at, message="Cancelled before execution")

    await db.commit()
    return terminated, orphaned_cancel


def _move_queue_item(queue: list[ScanJob], current_index: int, action: str) -> None:
    if action == "move_up" and current_index > 0:
        queue[current_index - 1], queue[current_index] = queue[current_index], queue[current_index - 1]
    elif action == "move_down" and current_index < len(queue) - 1:
        queue[current_index + 1], queue[current_index] = queue[current_index], queue[current_index + 1]
    elif action in {"move_to_front", "start_now"}:
        queue.insert(0, queue.pop(current_index))


async def _handle_start_now(queue: list[ScanJob], db: AsyncSession) -> None:
    active_result = await db.execute(
        select(ScanJob).where(ScanJob.parent_id.is_(None), ScanJob.status == "running").limit(1)
    )
    active = active_result.scalar_one_or_none()
    if active is not None:
        active.control_action = "requeue"
        active.control_mode = "preserve_discovery"
        return
    queue[0].queue_position = 1


def _serialize_queue(queue: list[ScanJob]) -> list[dict]:
    return [{"id": str(item.id), "queue_position": item.queue_position} for item in queue]


def _serialize_scan_job(job: ScanJob) -> dict:
    return {column.name: getattr(job, column.name) for column in job.__table__.columns}


async def _create_scan_job_graph(
    db: AsyncSession,
    *,
    targets: str,
    scan_type: str,
    triggered_by: str,
) -> tuple[ScanJob, list[ScanJob]]:
    queue_position = await _next_queue_position(db)
    child_targets = split_scan_targets(targets)
    parent = ScanJob(
        targets=targets,
        scan_type=scan_type,
        triggered_by=triggered_by,
        queue_position=queue_position,
    )
    db.add(parent)
    await db.flush()

    if len(child_targets) == 1:
        parent.targets = child_targets[0]
        return parent, []

    children: list[ScanJob] = []
    for index, child_target in enumerate(child_targets, start=1):
        child = ScanJob(
            parent_id=parent.id,
            targets=child_target,
            scan_type=scan_type,
            triggered_by=triggered_by,
            status="pending",
            queue_position=None,
            chunk_index=index,
            chunk_count=len(child_targets),
            result_summary={
                "stage": "queued",
                "message": f"Queued chunk {index}/{len(child_targets)}",
            },
        )
        children.append(child)
        db.add(child)

    parent.result_summary = {
        "stage": "queued",
        "message": f"Queued parent scan with {len(child_targets)} child chunks",
        "chunk_count": len(child_targets),
    }
    return parent, children


@router.get("/")
async def list_scans(
    db: DBSession,
    _: CurrentUser,
    limit: int = 20,
):
    result = await db.execute(select(ScanJob))
    scans = [scan for scan in result.scalars().all() if scan.parent_id is None]
    scans.sort(
        key=lambda scan: (
            0 if scan.status == "running" else 1 if scan.status == "paused" else 2 if scan.status == "pending" else 3,
            scan.queue_position if scan.queue_position is not None else 10_000,
            -(scan.created_at.timestamp() if scan.created_at else 0),
        )
    )
    return scans[:limit]


@router.post("/trigger", responses=TRIGGER_SCAN_RESPONSES)
async def trigger_scan(
    payload: TriggerScanRequest,
    db: DBSession,
    _: AdminUser,
):
    """Enqueue a manual scan. The scanner worker picks this up via Redis."""
    config = await get_or_create_scanner_config(db)
    try:
        targets = resolve_scan_targets(config, payload.targets)
        materialized_targets = materialize_scan_targets(targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    route_error = validate_scan_targets_routable(materialized_targets)
    if route_error:
        raise HTTPException(status_code=400, detail=route_error)
    job, _ = await _create_scan_job_graph(
        db,
        targets=materialized_targets,
        scan_type=payload.scan_type,
        triggered_by="manual",
    )
    await db.commit()
    await db.refresh(job)
    should_start = not await _has_active_scan(db) and job.queue_position == 1
    if should_start:
        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.post("/ingest/logs")
async def ingest_logs(
    payload: IngestLogsRequest,
    db: DBSession,
    _: AdminUser,
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


@router.get("/{job_id}", responses=SCAN_NOT_FOUND_RESPONSE)
async def get_scan(job_id: UUID, db: DBSession, _: CurrentUser):
    job = await db.get(ScanJob, job_id)
    if job is None:
        raise SCAN_NOT_FOUND_ERROR
    if job.parent_id is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Child scan chunks are controlled through the parent scan")
    if job.parent_id is None:
        child_result = await db.execute(
            select(ScanJob)
            .where(ScanJob.parent_id == job.id)
            .order_by(ScanJob.chunk_index.asc().nullslast(), ScanJob.created_at.asc())
        )
        child_jobs = list(child_result.scalars().all())
        if child_jobs:
            return {
                **_serialize_scan_job(job),
                "child_jobs": [_serialize_scan_job(child) for child in child_jobs],
            }
    return job


@router.post("/{job_id}/control", responses=SCAN_CONTROL_RESPONSES)
async def control_scan(
    job_id: UUID,
    payload: ScanControlRequest,
    db: DBSession,
    _: AdminUser,
):
    job = await db.get(ScanJob, job_id)
    if job is None:
        raise SCAN_NOT_FOUND_ERROR

    action = payload.action.lower()
    mode = (payload.mode or "discard").lower()
    if action not in {"cancel", "pause", "resume"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported control action")

    if action == "resume":
        return await _resume_scan_job(job, db)

    if action == "pause":
        return await _pause_scan_job(job, payload, db)

    terminated, orphaned_cancel = await _cancel_scan_job(job, mode, db)

    if terminated or orphaned_cancel:
        message = "Operator terminated scan" if terminated else "Operator cancelled stale running scan"
        await _publish_event({
            "event": "scan_complete",
            "data": {
                "job_id": str(job.id),
                "status": "cancelled",
                "message": message,
                "preserved_hosts": 0,
            },
        })
        if not await _has_active_scan(db):
            next_job = await _get_next_queued_job(db)
            if next_job is not None:
                run_scan_job.delay(str(next_job.id))

    return {"status": job.status, "message": "Cancel requested", "mode": mode}


@router.post("/{job_id}/queue", responses=SCAN_QUEUE_RESPONSES)
async def reorder_scan_queue(
    job_id: UUID,
    payload: ScanQueueRequest,
    db: DBSession,
    _: AdminUser,
):
    action = payload.action.lower()
    if action not in {"move_up", "move_down", "move_to_front", "start_now"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported queue action")

    job = await db.get(ScanJob, job_id)
    if job is None:
        raise SCAN_NOT_FOUND_ERROR
    if job.parent_id is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Child scan chunks cannot be reordered directly")
    if job.status != "pending":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only queued pending scans can be reordered")

    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    queue = list(result.scalars().all())
    await _normalize_pending_queue(db)
    queue.sort(key=lambda item: (item.queue_position or 10_000, item.created_at))
    current_index = next((index for index, item in enumerate(queue) if item.id == job.id), None)
    if current_index is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not currently in the queue")

    _move_queue_item(queue, current_index, action)
    if action == "start_now":
        await _handle_start_now(queue, db)

    for index, item in enumerate(queue, start=1):
        item.queue_position = index

    await db.commit()

    if action == "start_now" and not await _has_active_scan(db):
        next_job = await _get_next_queued_job(db)
        if next_job is not None:
            run_scan_job.delay(str(next_job.id))

    return {
        "status": "ok",
        "action": action,
        "queue": _serialize_queue(queue),
    }
