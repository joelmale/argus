"""Scan job management endpoints."""
from datetime import datetime, timedelta, timezone
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
from app.scanner.config import get_or_create_scanner_config, resolve_scan_targets
from app.workers.tasks import run_scan_job, _get_next_queued_job, _has_active_scan, _next_queue_position, _normalize_pending_queue

router = APIRouter()


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


@router.get("/")
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob))
    scans = list(result.scalars().all())
    scans.sort(
        key=lambda scan: (
            0 if scan.status == "running" else 1 if scan.status == "paused" else 2 if scan.status == "pending" else 3,
            scan.queue_position if scan.queue_position is not None else 10_000,
            -(scan.created_at.timestamp() if scan.created_at else 0),
        )
    )
    return scans[:limit]


@router.post("/trigger")
async def trigger_scan(
    payload: TriggerScanRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    """Enqueue a manual scan. The scanner worker picks this up via Redis."""
    config = await get_or_create_scanner_config(db)
    try:
        targets = resolve_scan_targets(config, payload.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = ScanJob(
        targets=targets,
        scan_type=payload.scan_type,
        triggered_by="manual",
        queue_position=await _next_queue_position(db),
    )
    db.add(job)
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
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
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


@router.get("/{job_id}")
async def get_scan(job_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    job = await db.get(ScanJob, job_id)
    return job


@router.post("/{job_id}/control")
async def control_scan(
    job_id: UUID,
    payload: ScanControlRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    job = await db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    action = payload.action.lower()
    mode = (payload.mode or "discard").lower()
    if action not in {"cancel", "pause", "resume"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported control action")

    if action == "resume":
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

    if action == "pause":
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

    # cancel
    if job.status not in {"pending", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending or running scans can be cancelled")
    if mode not in {"discard", "preserve_discovery"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cancel mode must be discard or preserve_discovery")
    job.control_action = "cancel"
    job.control_mode = mode
    if job.status == "pending":
        job.status = "cancelled"
        job.finished_at = datetime.now(timezone.utc)
        job.result_summary = {
            **(job.result_summary or {}),
            "stage": "cancelled",
            "message": "Cancelled before execution",
            "preserved_hosts": 0,
        }
        job.control_action = None
        job.control_mode = None
    await db.commit()
    return {"status": job.status, "message": "Cancel requested", "mode": mode}


@router.post("/{job_id}/queue")
async def reorder_scan_queue(
    job_id: UUID,
    payload: ScanQueueRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    action = payload.action.lower()
    if action not in {"move_up", "move_down", "move_to_front", "start_now"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported queue action")

    job = await db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if job.status != "pending":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only queued pending scans can be reordered")

    result = await db.execute(
        select(ScanJob).where(ScanJob.status == "pending").order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    queue = list(result.scalars().all())
    await _normalize_pending_queue(db)
    queue.sort(key=lambda item: (item.queue_position or 10_000, item.created_at))
    current_index = next((index for index, item in enumerate(queue) if item.id == job.id), None)
    if current_index is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not currently in the queue")

    if action == "move_up" and current_index > 0:
        queue[current_index - 1], queue[current_index] = queue[current_index], queue[current_index - 1]
    elif action == "move_down" and current_index < len(queue) - 1:
        queue[current_index + 1], queue[current_index] = queue[current_index], queue[current_index + 1]
    elif action == "move_to_front":
        queue.insert(0, queue.pop(current_index))
    elif action == "start_now":
        queue.insert(0, queue.pop(current_index))
        active_result = await db.execute(select(ScanJob).where(ScanJob.status == "running").limit(1))
        active = active_result.scalar_one_or_none()
        if active is not None:
            active.control_action = "requeue"
            active.control_mode = "preserve_discovery"
        else:
            queue[0].queue_position = 1

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
        "queue": [{"id": str(item.id), "queue_position": item.queue_position} for item in queue],
    }
