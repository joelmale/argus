"""Assets CRUD — the core inventory endpoints."""
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin, get_current_user
from app.core.limiter import limiter
from app.backups import (
    capture_backup_for_asset,
    generate_backup_diff,
    generate_restore_assist,
    get_backup_snapshot,
    get_backup_target,
    list_backup_snapshots,
    upsert_backup_target,
)
from app.assets.serialization import (
    SUPPORTED_ASSET_INCLUDES,
    AssetDetail,
    AssetStats,
    AssetSummary,
    serialize_asset as _serialize_asset,
    serialize_asset_summary as _serialize_asset_summary,
)
from app.db.models import (
    Asset,
    AssetHistory,
    AssetNote,
    AssetTag,
    ConfigBackupSnapshot,
    Finding,
    Port,
    ScanJob,
    User,
    WirelessAssociation,
)
from app.db.session import get_db
from app.scanner.config import materialize_scan_targets, read_effective_scanner_config, validate_scan_targets_routable
from app.scanner.models import DeviceClass, ScanProfile
from app.services.asset_exports import (
    EXPORT_ANSIBLE_JOB_TYPE,
    EXPORT_CSV_JOB_TYPE,
    EXPORT_INVENTORY_JSON_JOB_TYPE,
    EXPORT_REPORT_HTML_JOB_TYPE,
    EXPORT_REPORT_JSON_JOB_TYPE,
    EXPORT_TERRAFORM_JOB_TYPE,
    enqueue_asset_export_job,
    export_download_info,
)
from app.services.asset_refresh import AI_REFRESH_JOB_TYPE, SNMP_REFRESH_JOB_TYPE
from app.services.scan_queue import enqueue_scan_job

VALID_DEVICE_TYPES = {member.value for member in DeviceClass}
ASSET_NOT_FOUND_DETAIL = "Asset not found"
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]
AssetSearch = Annotated[str | None, Query(description="Search by IP, hostname, or vendor", max_length=200)]
AssetStatus = Annotated[str | None, Query(description="Filter by status: online | offline")]
AssetTagFilter = Annotated[str | None, Query(description="Filter by tag")]
AssetInclude = Annotated[str | None, Query(description="Comma-separated expansions: ports,tags,ai,probe_runs")]
CompareToSnapshot = Annotated[int | None, Query()]
PLAIN_TEXT_MEDIA_TYPE = "text/plain"
ASSET_NOT_FOUND_RESPONSE = {404: {"description": ASSET_NOT_FOUND_DETAIL}}
ASSET_UPDATE_RESPONSES = {
    404: {"description": ASSET_NOT_FOUND_DETAIL},
    422: {"description": "Invalid asset update payload"},
}
ASSET_TAG_RESPONSES = {
    400: {"description": "Tag value is invalid"},
    404: {"description": ASSET_NOT_FOUND_DETAIL},
    409: {"description": "Tag already exists"},
}
BACKUP_TARGET_RESPONSES = {
    400: {"description": "Backup target configuration is invalid"},
    404: {"description": ASSET_NOT_FOUND_DETAIL},
}
BACKUP_CAPTURE_RESPONSES = {
    400: {"description": "Backup capture failed"},
    404: {"description": ASSET_NOT_FOUND_DETAIL},
}
BACKUP_SNAPSHOT_RESPONSES = {404: {"description": "Backup snapshot not found"}}
router = APIRouter(responses=ASSET_NOT_FOUND_RESPONSE)


def _parse_asset_includes(include: str | None) -> set[str]:
    if not include:
        return set()
    requested = {item.strip() for item in include.split(",") if item.strip()}
    unknown = requested - SUPPORTED_ASSET_INCLUDES
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unsupported asset include: {', '.join(sorted(unknown))}")
    return requested


class AssetTagRequest(BaseModel):
    tag: str


class AssetNoteCreateRequest(BaseModel):
    content: str


class ConfigBackupTargetRequest(BaseModel):
    driver: str
    username: str
    password_env_var: str | None = None
    port: int = 22
    host_override: str | None = None
    enabled: bool = True


class BulkDeleteAssetsRequest(BaseModel):
    asset_ids: list[UUID]


class JobSubmissionResponse(BaseModel):
    job_id: str
    status: str
    queue_position: int | None = None


async def _load_asset(db: AsyncSession, asset_id: UUID) -> Asset:
    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.tags),
            selectinload(Asset.note_entries).selectinload(AssetNote.user),
            selectinload(Asset.ai_analysis),
            selectinload(Asset.evidence),
            selectinload(Asset.probe_runs),
            selectinload(Asset.observations),
            selectinload(Asset.fingerprint_hypotheses),
            selectinload(Asset.internet_lookup_results),
            selectinload(Asset.lifecycle_records),
            selectinload(Asset.autopsy),
        )
        .where(Asset.id == asset_id)
    )
    asset = (await db.execute(stmt)).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)
    return asset


async def _load_open_port_counts(db: AsyncSession, asset_ids: list[UUID]) -> dict[UUID, int]:
    if not asset_ids:
        return {}
    result = await db.execute(
        select(Port.asset_id, func.count(Port.id))
        .where(Port.asset_id.in_(asset_ids), Port.state == "open")
        .group_by(Port.asset_id)
    )
    return {asset_id: int(count) for asset_id, count in result.all()}


@router.get("/", response_model=list[AssetSummary], response_model_exclude_none=True)
async def list_assets(
    search: AssetSearch = None,
    status: AssetStatus = None,
    tag: AssetTagFilter = None,
    include: AssetInclude = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, le=500),
    db: DBSession = None,
    _: CurrentUser = None,
):
    """Return compact asset summaries with optional light expansions."""
    includes = _parse_asset_includes(include)
    load_options = []
    if "tags" in includes:
        load_options.append(selectinload(Asset.tags))
    if "ports" in includes:
        load_options.append(selectinload(Asset.ports))
    if "ai" in includes:
        load_options.append(selectinload(Asset.ai_analysis))
    if "probe_runs" in includes:
        load_options.append(selectinload(Asset.probe_runs))

    q = select(Asset)
    if load_options:
        q = q.options(*load_options)
    if status:
        q = q.where(Asset.status == status)
    if search:
        like = f"%{search}%"
        q = q.where(
            Asset.ip_address.ilike(like)
            | Asset.hostname.ilike(like)
            | Asset.vendor.ilike(like)
        )
    if tag:
        q = q.join(AssetTag).where(AssetTag.tag == tag)
    q = q.order_by(Asset.ip_address.asc()).offset(skip).limit(limit)
    result = await db.execute(q)
    assets = list(result.scalars().all())
    open_port_counts = await _load_open_port_counts(db, [asset.id for asset in assets])
    return [
        _serialize_asset_summary(
            asset,
            includes=includes,
            open_ports_count=open_port_counts.get(asset.id, 0),
        )
        for asset in assets
    ]


@router.get("/stats", response_model=AssetStats)
async def get_asset_stats(
    new_since: datetime | None = Query(default=None, description="Timestamp used for the New Today count"),
    db: DBSession = None,
    _: CurrentUser = None,
):
    since = new_since or datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)

    status_rows = await db.execute(select(Asset.status, func.count(Asset.id)).group_by(Asset.status))
    counts = {status: int(count) for status, count in status_rows.all()}
    total = sum(counts.values())
    new_today = await db.scalar(select(func.count(Asset.id)).where(Asset.first_seen >= since)) or 0
    return {
        "total": total,
        "online": counts.get("online", 0),
        "offline": counts.get("offline", 0),
        "unknown": counts.get("unknown", 0),
        "new_today": int(new_today),
    }


@router.get("/inventory")
async def get_asset_inventory(
    db: DBSession = None,
    _: CurrentUser = None,
):
    """Return aggregate inventory statistics — OS, device type, vendor, top ports, top services."""

    # ── OS distribution ──────────────────────────────────────────────────────
    os_rows = await db.execute(
        select(Asset.os_name, func.count(Asset.id).label("n"))
        .where(Asset.os_name.isnot(None), Asset.os_name != "")
        .group_by(Asset.os_name)
        .order_by(func.count(Asset.id).desc())
        .limit(30)
    )
    os_counts = [{"label": row.os_name, "count": row.n} for row in os_rows.all()]

    # ── Device type distribution ─────────────────────────────────────────────
    dtype_rows = await db.execute(
        select(
            func.coalesce(Asset.device_type_override, Asset.device_type).label("dtype"),
            func.count(Asset.id).label("n"),
        )
        .where(
            func.coalesce(Asset.device_type_override, Asset.device_type).isnot(None),
            func.coalesce(Asset.device_type_override, Asset.device_type) != "unknown",
        )
        .group_by("dtype")
        .order_by(func.count(Asset.id).desc())
    )
    device_type_counts = [{"label": row.dtype, "count": row.n} for row in dtype_rows.all()]

    # ── Vendor distribution ───────────────────────────────────────────────────
    vendor_rows = await db.execute(
        select(Asset.vendor, func.count(Asset.id).label("n"))
        .where(Asset.vendor.isnot(None), Asset.vendor != "")
        .group_by(Asset.vendor)
        .order_by(func.count(Asset.id).desc())
        .limit(20)
    )
    vendor_counts = [{"label": row.vendor, "count": row.n} for row in vendor_rows.all()]

    # ── Top open ports ────────────────────────────────────────────────────────
    port_rows = await db.execute(
        select(
            Port.port_number,
            Port.protocol,
            Port.service,
            func.count(Port.asset_id.distinct()).label("asset_count"),
        )
        .where(Port.state == "open")
        .group_by(Port.port_number, Port.protocol, Port.service)
        .order_by(func.count(Port.asset_id.distinct()).desc())
        .limit(20)
    )
    top_ports = [
        {
            "port": row.port_number,
            "protocol": row.protocol,
            "service": row.service,
            "asset_count": row.asset_count,
        }
        for row in port_rows.all()
    ]

    # ── Top services (by name) ────────────────────────────────────────────────
    svc_rows = await db.execute(
        select(Port.service, func.count(Port.asset_id.distinct()).label("asset_count"))
        .where(Port.state == "open", Port.service.isnot(None), Port.service != "")
        .group_by(Port.service)
        .order_by(func.count(Port.asset_id.distinct()).desc())
        .limit(15)
    )
    top_services = [
        {"service": row.service, "asset_count": row.asset_count}
        for row in svc_rows.all()
    ]

    # ── Top software versions ─────────────────────────────────────────────────
    ver_rows = await db.execute(
        select(
            Port.service,
            Port.version,
            func.count(Port.asset_id.distinct()).label("asset_count"),
        )
        .where(
            Port.state == "open",
            Port.service.isnot(None),
            Port.service != "",
            Port.version.isnot(None),
            Port.version != "",
        )
        .group_by(Port.service, Port.version)
        .order_by(func.count(Port.asset_id.distinct()).desc())
        .limit(25)
    )
    top_versions = [
        {"service": row.service, "version": row.version, "asset_count": row.asset_count}
        for row in ver_rows.all()
    ]

    # ── Total open-port count across all assets ───────────────────────────────
    total_open_ports = await db.scalar(
        select(func.count(Port.id)).where(Port.state == "open")
    ) or 0

    # ── Asset count ───────────────────────────────────────────────────────────
    total_assets = await db.scalar(select(func.count(Asset.id))) or 0

    return {
        "total_assets": int(total_assets),
        "total_open_ports": int(total_open_ports),
        "os_counts": os_counts,
        "device_type_counts": device_type_counts,
        "vendor_counts": vendor_counts,
        "top_ports": top_ports,
        "top_services": top_services,
        "top_versions": top_versions,
    }


async def _queue_export_job(export_type: str, db: DBSession) -> dict[str, int | str | None]:
    job, should_start = await enqueue_asset_export_job(db, export_type=export_type)
    if should_start:
        from app.workers.tasks import run_scan_job

        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.get("/export.csv")
async def export_assets_csv(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_CSV_JOB_TYPE, db)


@router.get("/export.ansible.ini")
async def export_assets_ansible(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_ANSIBLE_JOB_TYPE, db)


@router.get("/export.terraform.tf.json")
async def export_assets_terraform(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_TERRAFORM_JOB_TYPE, db)


@router.get("/export.inventory.json")
async def export_assets_inventory_json(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_INVENTORY_JSON_JOB_TYPE, db)


@router.get("/report.json")
async def export_assets_report_json(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_REPORT_JSON_JOB_TYPE, db)


@router.get("/report.html")
async def export_assets_report_html(db: DBSession, _: CurrentUser):
    return await _queue_export_job(EXPORT_REPORT_HTML_JOB_TYPE, db)


@router.get("/export-jobs/{job_id}/download")
async def download_export_artifact(job_id: UUID, db: DBSession, _: CurrentUser):
    job = await db.get(ScanJob, job_id)
    if job is None or job.scan_type not in {
        EXPORT_CSV_JOB_TYPE,
        EXPORT_ANSIBLE_JOB_TYPE,
        EXPORT_TERRAFORM_JOB_TYPE,
        EXPORT_INVENTORY_JSON_JOB_TYPE,
        EXPORT_REPORT_JSON_JOB_TYPE,
        EXPORT_REPORT_HTML_JOB_TYPE,
    }:
        raise HTTPException(status_code=404, detail="Export job not found")

    try:
        artifact_path, filename, content_type = export_download_info(job)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    if not artifact_path.exists():
        raise HTTPException(status_code=404, detail="Export artifact is not ready")

    return Response(
        content=artifact_path.read_bytes(),
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{asset_id}", response_model=AssetDetail, responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset(asset_id: UUID, db: DBSession, _: CurrentUser):
    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.tags),
            selectinload(Asset.note_entries).selectinload(AssetNote.user),
            selectinload(Asset.history),
            selectinload(Asset.ai_analysis),
            selectinload(Asset.evidence),
            selectinload(Asset.probe_runs),
            selectinload(Asset.observations),
            selectinload(Asset.fingerprint_hypotheses),
            selectinload(Asset.internet_lookup_results),
            selectinload(Asset.lifecycle_records),
            selectinload(Asset.autopsy),
        )
        .where(Asset.id == asset_id)
    )
    asset = (await db.execute(stmt)).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)
    return _serialize_asset(asset)


@router.post("/{asset_id}/port-scan", response_model=JobSubmissionResponse, responses=ASSET_NOT_FOUND_RESPONSE)
async def run_asset_port_scan(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    targets = materialize_scan_targets(asset.ip_address)
    route_error = validate_scan_targets_routable(targets)
    if route_error:
        raise HTTPException(status_code=400, detail=route_error)

    job, should_start = await enqueue_scan_job(
        db,
        targets=targets,
        scan_type=ScanProfile.DEEP_ENRICHMENT.value,
        triggered_by="manual",
        result_summary={
            "stage": "queued",
            "message": f"Queued targeted deep port scan for {asset.ip_address}",
            "asset_id": str(asset.id),
        },
    )
    if should_start:
        from app.workers.tasks import run_scan_job

        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.post("/{asset_id}/ai-analysis/refresh", response_model=JobSubmissionResponse, responses=ASSET_NOT_FOUND_RESPONSE)
@limiter.limit("3/minute")
async def run_asset_ai_refresh(
    request: Request,
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    job, should_start = await enqueue_scan_job(
        db,
        targets=asset.ip_address,
        scan_type=AI_REFRESH_JOB_TYPE,
        triggered_by="manual",
        result_summary={
            "stage": "queued",
            "message": f"Queued AI analysis refresh for {asset.ip_address}",
            "asset_id": str(asset.id),
            "asset_ip": asset.ip_address,
        },
    )
    if should_start:
        from app.workers.tasks import run_scan_job

        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.post("/{asset_id}/snmp-refresh", response_model=JobSubmissionResponse, responses=ASSET_NOT_FOUND_RESPONSE)
@limiter.limit("3/minute")
async def run_asset_snmp_refresh(
    request: Request,
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    _, runtime_config = await read_effective_scanner_config(db)
    if not runtime_config.snmp_enabled:
        raise HTTPException(status_code=400, detail="SNMP enrichment is disabled in Settings.")
    job, should_start = await enqueue_scan_job(
        db,
        targets=asset.ip_address,
        scan_type=SNMP_REFRESH_JOB_TYPE,
        triggered_by="manual",
        result_summary={
            "stage": "queued",
            "message": f"Queued SNMP refresh for {asset.ip_address}",
            "asset_id": str(asset.id),
            "asset_ip": asset.ip_address,
        },
    )
    if should_start:
        from app.workers.tasks import run_scan_job

        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.patch("/{asset_id}", response_model=AssetDetail, responses=ASSET_UPDATE_RESPONSES)
async def update_asset(
    asset_id: UUID,
    payload: dict,
    db: DBSession,
    _: AdminUser,
):
    """Update mutable fields: hostname, notes, tags, custom_fields."""
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)
    allowed = {"hostname", "notes", "custom_fields", "device_type"}
    for key, val in payload.items():
        if key not in allowed:
            continue
        if key == "device_type":
            if val in ("", None):
                asset.device_type_override = None
            else:
                if val not in VALID_DEVICE_TYPES:
                    raise HTTPException(status_code=422, detail=f"Invalid device_type '{val}'")
                asset.device_type_override = val
            continue
        setattr(asset, key, val)
    await db.commit()
    await db.refresh(asset)
    await db.refresh(asset)
    refreshed = (
        await db.execute(
            select(Asset)
            .options(
                selectinload(Asset.ports),
                selectinload(Asset.tags),
                selectinload(Asset.note_entries).selectinload(AssetNote.user),
                selectinload(Asset.ai_analysis),
                selectinload(Asset.evidence),
                selectinload(Asset.probe_runs),
                selectinload(Asset.observations),
                selectinload(Asset.fingerprint_hypotheses),
                selectinload(Asset.internet_lookup_results),
                selectinload(Asset.lifecycle_records),
            )
            .where(Asset.id == asset_id)
        )
    ).scalar_one()
    return _serialize_asset(refreshed)


@router.get("/{asset_id}/evidence", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_evidence(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await _load_asset(db, asset_id)
    return _serialize_asset(asset)["evidence"]


@router.get("/{asset_id}/notes", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_notes(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await _load_asset(db, asset_id)
    return _serialize_asset(asset)["note_entries"]


@router.post("/{asset_id}/notes", responses=ASSET_NOT_FOUND_RESPONSE)
async def add_asset_note(asset_id: UUID, payload: AssetNoteCreateRequest, db: DBSession, current_user: CurrentUser):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="Note content cannot be empty")

    note = AssetNote(asset_id=asset.id, user_id=current_user.id, content=content)
    db.add(note)
    await db.commit()
    refreshed = (
        await db.execute(
            select(AssetNote)
            .options(selectinload(AssetNote.user))
            .where(AssetNote.id == note.id)
        )
    ).scalar_one()
    return {
        "id": refreshed.id,
        "content": refreshed.content,
        "created_at": refreshed.created_at.isoformat(),
        "updated_at": refreshed.updated_at.isoformat(),
        "user": {
            "id": str(refreshed.user.id),
            "username": refreshed.user.username,
        } if refreshed.user else None,
    }


@router.get("/{asset_id}/probe-runs", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_probe_runs(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await _load_asset(db, asset_id)
    return _serialize_asset(asset)["probe_runs"]


@router.post("/bulk-delete")
async def bulk_delete_assets(
    payload: BulkDeleteAssetsRequest,
    db: DBSession,
    _: AdminUser,
):
    if not payload.asset_ids:
        return {"deleted": 0}

    result = await db.execute(select(Asset).where(Asset.id.in_(payload.asset_ids)))
    assets = list(result.scalars().all())
    for asset in assets:
        await db.delete(asset)
    await db.commit()
    return {"deleted": len(assets)}


@router.delete("/{asset_id}", status_code=204, responses=ASSET_NOT_FOUND_RESPONSE)
async def delete_asset(asset_id: UUID, db: DBSession, _: AdminUser):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)
    await db.delete(asset)
    await db.commit()


@router.get("/{asset_id}/history", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_history(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    result = await db.execute(
        select(AssetHistory)
        .where(AssetHistory.asset_id == asset_id)
        .order_by(AssetHistory.changed_at.desc())
    )
    return result.scalars().all()


@router.get("/{asset_id}/ports", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_ports(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    result = await db.execute(
        select(Port)
        .where(Port.asset_id == asset_id)
        .order_by(Port.port_number.asc(), Port.protocol.asc())
    )
    return result.scalars().all()


@router.get("/{asset_id}/wireless-clients", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_wireless_clients(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    result = await db.execute(
        select(WirelessAssociation)
        .where(
            (WirelessAssociation.access_point_asset_id == asset_id)
            | (WirelessAssociation.client_asset_id == asset_id)
        )
        .order_by(WirelessAssociation.last_seen.desc())
    )
    associations = result.scalars().all()
    return [
        {
            "id": association.id,
            "access_point_asset_id": str(association.access_point_asset_id),
            "client_asset_id": str(association.client_asset_id) if association.client_asset_id else None,
            "client_mac": association.client_mac,
            "client_ip": association.client_ip,
            "ssid": association.ssid,
            "band": association.band,
            "signal_dbm": association.signal_dbm,
            "source": association.source,
            "first_seen": association.first_seen.isoformat(),
            "last_seen": association.last_seen.isoformat(),
        }
        for association in associations
    ]


@router.post("/{asset_id}/tags", status_code=201, responses=ASSET_TAG_RESPONSES)
async def add_asset_tag(
    asset_id: UUID,
    payload: AssetTagRequest,
    db: DBSession,
    _: AdminUser,
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    normalized = payload.tag.strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="Tag cannot be empty")

    existing = await db.execute(
        select(AssetTag).where(AssetTag.asset_id == asset_id, AssetTag.tag == normalized)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Tag already exists")

    tag = AssetTag(asset_id=asset_id, tag=normalized)
    db.add(tag)
    await db.commit()
    await db.refresh(tag)
    return tag


@router.delete("/{asset_id}/tags/{tag}", status_code=204)
async def delete_asset_tag(
    asset_id: UUID,
    tag: str,
    db: DBSession,
    _: AdminUser,
):
    result = await db.execute(
        select(AssetTag).where(AssetTag.asset_id == asset_id, AssetTag.tag == tag.lower())
    )
    asset_tag = result.scalar_one_or_none()
    if asset_tag is None:
        return
    await db.delete(asset_tag)
    await db.commit()


@router.get("/{asset_id}/config-backup-target", responses=ASSET_NOT_FOUND_RESPONSE)
async def read_config_backup_target(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    target = await get_backup_target(db, asset_id)
    if target is None:
        return None

    return {
        "id": target.id,
        "asset_id": str(target.asset_id),
        "driver": target.driver,
        "username": target.username,
        "password_env_var": target.password_env_var,
        "port": target.port,
        "host_override": target.host_override,
        "enabled": target.enabled,
        "created_at": target.created_at.isoformat(),
        "updated_at": target.updated_at.isoformat(),
    }


@router.put("/{asset_id}/config-backup-target", responses=BACKUP_TARGET_RESPONSES)
async def write_config_backup_target(
    asset_id: UUID,
    payload: ConfigBackupTargetRequest,
    db: DBSession,
    _: AdminUser,
):
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    try:
        target = await upsert_backup_target(
            db,
            asset_id=asset_id,
            driver=payload.driver,
            username=payload.username.strip(),
            password_env_var=payload.password_env_var.strip() if payload.password_env_var else None,
            port=payload.port,
            host_override=payload.host_override.strip() if payload.host_override else None,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "id": target.id,
        "asset_id": str(target.asset_id),
        "driver": target.driver,
        "username": target.username,
        "password_env_var": target.password_env_var,
        "port": target.port,
        "host_override": target.host_override,
        "enabled": target.enabled,
        "created_at": target.created_at.isoformat(),
        "updated_at": target.updated_at.isoformat(),
    }


@router.get("/{asset_id}/config-backups", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_config_backups(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=ASSET_NOT_FOUND_DETAIL)

    snapshots = await list_backup_snapshots(db, asset_id)
    return [
        {
            "id": snapshot.id,
            "asset_id": str(snapshot.asset_id),
            "target_id": snapshot.target_id,
            "status": snapshot.status,
            "driver": snapshot.driver,
            "command": snapshot.command,
            "content": snapshot.content,
            "error": snapshot.error,
            "captured_at": snapshot.captured_at.isoformat(),
        }
        for snapshot in snapshots
    ]


@router.post("/{asset_id}/config-backups", status_code=201, responses=BACKUP_CAPTURE_RESPONSES)
async def trigger_config_backup(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    try:
        snapshot = await capture_backup_for_asset(db, asset_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "id": snapshot.id,
        "asset_id": str(snapshot.asset_id),
        "target_id": snapshot.target_id,
        "status": snapshot.status,
        "driver": snapshot.driver,
        "command": snapshot.command,
        "content": snapshot.content,
        "error": snapshot.error,
        "captured_at": snapshot.captured_at.isoformat(),
    }


@router.get("/{asset_id}/config-backups/{snapshot_id}/download", responses=BACKUP_SNAPSHOT_RESPONSES)
async def download_config_backup(
    asset_id: UUID,
    snapshot_id: int,
    db: DBSession,
    _: AdminUser,
):
    snapshot = await get_backup_snapshot(db, asset_id, snapshot_id)
    if snapshot is None or not snapshot.content:
        raise HTTPException(status_code=404, detail="Backup snapshot not found")
    return Response(
        content=snapshot.content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="argus-backup-{snapshot_id}.txt"'},
    )


@router.get("/{asset_id}/config-backups/{snapshot_id}/diff", responses=BACKUP_SNAPSHOT_RESPONSES)
async def diff_config_backup(
    asset_id: UUID,
    snapshot_id: int,
    compare_to: CompareToSnapshot = None,
    db: DBSession = None,
    _: AdminUser = None,
):
    try:
        diff = await generate_backup_diff(db, asset_id, snapshot_id, compare_to)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=diff or "No diff\n", media_type=PLAIN_TEXT_MEDIA_TYPE)


@router.get("/{asset_id}/config-backups/{snapshot_id}/restore-assist", responses=BACKUP_SNAPSHOT_RESPONSES)
async def get_restore_assist(
    asset_id: UUID,
    snapshot_id: int,
    db: DBSession,
    _: AdminUser,
):
    try:
        return await generate_restore_assist(db, asset_id, snapshot_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
