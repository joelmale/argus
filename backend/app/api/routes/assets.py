"""Assets CRUD — the core inventory endpoints."""
import asyncio
import csv
import html
from datetime import datetime, timezone
from io import StringIO
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
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
    ProbeRun,
    ScanJob,
    User,
    WirelessAssociation,
)
from app.db.session import get_db
from app.exporters import build_inventory_snapshot, render_ansible_inventory, render_terraform_inventory
from app.scanner.agent import get_analyst
from app.scanner.config import materialize_scan_targets, read_effective_scanner_config, validate_scan_targets_routable
from app.scanner.models import DeviceClass, DiscoveredHost, ScanProfile
from app.scanner.pipeline import _investigate_host
from app.scanner.stages import portscan
from app.workers.tasks import _has_active_scan, _next_queue_position, run_scan_job

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


def _probe_run_summary(details: dict, probe_success: bool) -> str | None:
    if not probe_success:
        error = details.get("error")
        return str(error)[:512] if error is not None else None
    summary = details.get("title") or details.get("sys_descr") or details.get("friendly_name") or details.get("banner")
    return str(summary)[:512] if summary is not None else None


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


@router.get("/export.csv")
async def export_assets_csv(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports), selectinload(Asset.ai_analysis)))
    assets = result.scalars().all()

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "id",
        "ip_address",
        "hostname",
        "mac_address",
        "vendor",
        "os_name",
        "device_type",
        "status",
        "first_seen",
        "last_seen",
        "tags",
        "custom_fields",
    ])
    for asset in assets:
        writer.writerow(
            [
                str(asset.id),
                asset.ip_address,
                asset.hostname or "",
                asset.mac_address or "",
                asset.vendor or "",
                asset.os_name or "",
                asset.effective_device_type,
                asset.status,
                asset.first_seen.isoformat(),
                asset.last_seen.isoformat(),
                ",".join(sorted(tag.tag for tag in asset.tags)),
                asset.custom_fields or {},
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="argus-assets.csv"'},
    )


@router.get("/export.ansible.ini")
async def export_assets_ansible(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports), selectinload(Asset.ai_analysis)))
    assets = result.scalars().all()
    return Response(
        content=render_ansible_inventory(assets),
        media_type=PLAIN_TEXT_MEDIA_TYPE,
        headers={"Content-Disposition": 'attachment; filename="argus-inventory.ini"'},
    )


@router.get("/export.terraform.tf.json")
async def export_assets_terraform(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports), selectinload(Asset.ai_analysis)))
    assets = result.scalars().all()
    return Response(
        content=render_terraform_inventory(assets),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="argus-assets.tf.json"'},
    )


@router.get("/export.inventory.json")
async def export_assets_inventory_json(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports), selectinload(Asset.ai_analysis)))
    assets = result.scalars().all()
    return build_inventory_snapshot(assets)


@router.get("/report.json")
async def export_assets_report_json(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports), selectinload(Asset.ai_analysis)))
    assets = result.scalars().all()
    open_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0
    total_findings = await db.scalar(select(func.count()).select_from(Finding)) or 0
    successful_backups = await db.scalar(
        select(func.count()).select_from(ConfigBackupSnapshot).where(ConfigBackupSnapshot.status == "done")
    ) or 0
    recent_changes_result = await db.execute(
        select(AssetHistory)
        .order_by(AssetHistory.changed_at.desc())
        .limit(10)
    )
    recent_changes = recent_changes_result.scalars().all()

    return {
        "summary": {
            "total_assets": len(assets),
            "online_assets": sum(1 for asset in assets if asset.status == "online"),
            "offline_assets": sum(1 for asset in assets if asset.status == "offline"),
            "total_findings": total_findings,
            "open_findings": open_findings,
            "successful_backups": successful_backups,
        },
        "recent_changes": [
            {
                "asset_id": str(change.asset_id),
                "change_type": change.change_type,
                "changed_at": change.changed_at.isoformat(),
                "diff": change.diff or {},
            }
            for change in recent_changes
        ],
        "inventory": build_inventory_snapshot(assets),
    }


@router.get("/report.html", response_class=HTMLResponse)
async def export_assets_report_html(db: DBSession, _: CurrentUser):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports)))
    assets = result.scalars().all()

    total = len(assets)
    online = sum(1 for asset in assets if asset.status == "online")
    offline = sum(1 for asset in assets if asset.status == "offline")
    open_findings = await db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0
    successful_backups = await db.scalar(
        select(func.count()).select_from(ConfigBackupSnapshot).where(ConfigBackupSnapshot.status == "done")
    ) or 0

    rows = "".join(
        f"<tr><td>{html.escape(asset.ip_address)}</td><td>{html.escape(asset.hostname or '')}</td><td>{html.escape(asset.vendor or '')}</td><td>{html.escape(asset.effective_device_type)}</td><td>{html.escape(asset.status)}</td><td>{html.escape(', '.join(tag.tag for tag in asset.tags))}</td></tr>"
        for asset in assets
    )
    return HTMLResponse(
        f"""
        <html>
          <head>
            <title>Argus Inventory Report</title>
            <style>
              body {{ font-family: sans-serif; margin: 32px; color: #18181b; }}
              h1 {{ margin-bottom: 8px; }}
              .summary {{ display: flex; gap: 16px; margin: 16px 0 24px; }}
              .card {{ border: 1px solid #d4d4d8; border-radius: 12px; padding: 12px 16px; }}
              table {{ width: 100%; border-collapse: collapse; }}
              th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e4e4e7; font-size: 14px; }}
              th {{ background: #f4f4f5; }}
            </style>
          </head>
          <body>
            <h1>Argus Inventory Report</h1>
            <p>Generated from the current inventory snapshot.</p>
            <div class="summary">
              <div class="card"><strong>Total assets:</strong> {total}</div>
              <div class="card"><strong>Online:</strong> {online}</div>
              <div class="card"><strong>Offline:</strong> {offline}</div>
              <div class="card"><strong>Open findings:</strong> {open_findings}</div>
              <div class="card"><strong>Successful backups:</strong> {successful_backups}</div>
            </div>
            <table>
              <thead>
                <tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>Status</th><th>Tags</th></tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </body>
        </html>
        """
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


@router.post("/{asset_id}/port-scan", responses=ASSET_NOT_FOUND_RESPONSE)
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

    job = ScanJob(
        targets=targets,
        scan_type=ScanProfile.DEEP_ENRICHMENT.value,
        triggered_by="manual",
        queue_position=await _next_queue_position(db),
        result_summary={
            "stage": "queued",
            "message": f"Queued targeted deep port scan for {asset.ip_address}",
            "asset_id": str(asset.id),
        },
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    should_start = not await _has_active_scan(db) and job.queue_position == 1
    if should_start:
        run_scan_job.delay(str(job.id))
        return {"job_id": str(job.id), "status": "started", "queue_position": job.queue_position}
    return {"job_id": str(job.id), "status": "queued", "queue_position": job.queue_position}


@router.post("/{asset_id}/ai-analysis/refresh", response_model=AssetDetail, responses=ASSET_NOT_FOUND_RESPONSE)
@limiter.limit("3/minute")
async def run_asset_ai_refresh(
    request: Request,
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    _, runtime_config = await read_effective_scanner_config(db)
    host = DiscoveredHost(
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        discovery_method="manual",
        nmap_hostname=asset.hostname,
    )
    ports, os_fp = await portscan.scan_host(host, ScanProfile.DEEP_ENRICHMENT)
    result = await _investigate_host(
        host=host,
        ports=ports,
        os_fp=os_fp,
        nmap_hostname=host.nmap_hostname,
        nmap_vendor=asset.vendor,
        profile=ScanProfile.DEEP_ENRICHMENT,
        analyst=get_analyst(runtime_config),
        run_deep_probes=True,
        deep_probe_timeout_seconds=6,
        semaphore=asyncio.Semaphore(1),
        broadcast_fn=None,
        job_id=f"asset-{asset.id}",
    )

    from app.db.upsert import upsert_scan_result

    await upsert_scan_result(db, result)
    await db.commit()
    return _serialize_asset(await _load_asset(db, asset_id))


@router.post("/{asset_id}/snmp-refresh", response_model=AssetDetail, responses=ASSET_NOT_FOUND_RESPONSE)
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

    from app.scanner.probes.snmp import probe as run_snmp_probe
    from app.scanner.topology import infer_topology_links_from_snmp

    probe_result = await run_snmp_probe(
        asset.ip_address,
        community=runtime_config.snmp_community,
        version=runtime_config.snmp_version,
        timeout_seconds=runtime_config.snmp_timeout,
        v3_username=runtime_config.snmp_v3_username or None,
        v3_auth_key=runtime_config.snmp_v3_auth_key or None,
        v3_priv_key=runtime_config.snmp_v3_priv_key or None,
        v3_auth_protocol=runtime_config.snmp_v3_auth_protocol or None,
        v3_priv_protocol=runtime_config.snmp_v3_priv_protocol or None,
    )

    details = dict(probe_result.data or {})
    if probe_result.error and "error" not in details:
        details["error"] = probe_result.error
    now = datetime.now(timezone.utc)
    db.add(
        ProbeRun(
            asset_id=asset.id,
            probe_type=probe_result.probe_type,
            target_port=probe_result.target_port,
            success=probe_result.success,
            duration_ms=probe_result.duration_ms,
            summary=_probe_run_summary(details, probe_result.success),
            details=details,
            raw_excerpt=probe_result.raw[:4000] if probe_result.raw else None,
            observed_at=now,
        )
    )

    asset.heartbeat_last_checked_at = now
    if probe_result.success:
        was_offline = asset.status == "offline"
        asset.status = "online"
        asset.last_seen = now
        asset.heartbeat_missed_count = 0
        if was_offline:
            db.add(
                AssetHistory(
                    asset_id=asset.id,
                    change_type="status_change",
                    diff={"status": {"old": "offline", "new": "online"}},
                )
            )
        if details:
            await infer_topology_links_from_snmp(db, asset, details)

    await db.commit()
    return _serialize_asset(await _load_asset(db, asset_id))


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
