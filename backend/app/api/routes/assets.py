"""Assets CRUD — the core inventory endpoints."""
import asyncio
import csv
from io import StringIO
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin, get_current_user
from app.backups import (
    capture_backup_for_asset,
    generate_backup_diff,
    generate_restore_assist,
    get_backup_snapshot,
    get_backup_target,
    list_backup_snapshots,
    upsert_backup_target,
)
from app.db.models import Asset, AssetAIAnalysis, AssetHistory, AssetTag, ConfigBackupSnapshot, Finding, Port, User, WirelessAssociation
from app.db.session import get_db
from app.exporters import build_inventory_snapshot, render_ansible_inventory, render_terraform_inventory
from app.scanner.agent import get_analyst
from app.scanner.models import DeviceClass, DiscoveredHost, HostScanResult, ScanProfile
from app.scanner.pipeline import _investigate_host
from app.scanner.stages import portscan

VALID_DEVICE_TYPES = {member.value for member in DeviceClass}
ASSET_NOT_FOUND_DETAIL = "Asset not found"
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]
AssetSearch = Annotated[str | None, Query(description="Search by IP, hostname, or vendor")]
AssetStatus = Annotated[str | None, Query(description="Filter by status: online | offline")]
AssetTagFilter = Annotated[str | None, Query(description="Filter by tag")]
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


def _serialize_ai_analysis(ai: AssetAIAnalysis | None) -> dict | None:
    if ai is None:
        return None
    return {
        "device_class": ai.device_class,
        "confidence": ai.confidence,
        "vendor": ai.vendor,
        "model": ai.model,
        "os_guess": ai.os_guess,
        "device_role": ai.device_role,
        "open_services_summary": ai.open_services_summary or [],
        "security_findings": ai.security_findings or [],
        "investigation_notes": ai.investigation_notes or "",
        "suggested_tags": ai.suggested_tags or [],
        "ai_backend": ai.ai_backend,
        "model_used": ai.model_used,
        "agent_steps": ai.agent_steps,
        "analyzed_at": ai.analyzed_at.isoformat(),
    }


def _serialize_asset(asset: Asset) -> dict:
    return {
        "id": str(asset.id),
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address,
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "device_type": asset.effective_device_type,
        "device_type_source": asset.effective_device_type_source,
        "device_type_override": asset.device_type_override,
        "status": asset.status,
        "notes": asset.notes,
        "custom_fields": asset.custom_fields,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "ports": [
            {
                "id": port.id,
                "port_number": port.port_number,
                "protocol": port.protocol,
                "service": port.service,
                "version": port.version,
                "state": port.state,
            }
            for port in asset.ports
        ],
        "tags": [{"tag": tag.tag} for tag in asset.tags],
        "ai_analysis": _serialize_ai_analysis(asset.ai_analysis),
        "evidence": [
            {
                "id": row.id,
                "source": row.source,
                "category": row.category,
                "key": row.key,
                "value": row.value,
                "confidence": row.confidence,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in sorted(asset.evidence, key=lambda item: (item.category, -item.confidence, item.key))
        ],
        "probe_runs": [
            {
                "id": row.id,
                "probe_type": row.probe_type,
                "target_port": row.target_port,
                "success": row.success,
                "duration_ms": row.duration_ms,
                "summary": row.summary,
                "details": row.details,
                "raw_excerpt": row.raw_excerpt,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in sorted(asset.probe_runs, key=lambda item: (item.probe_type, item.target_port or 0))
        ],
        "observations": [
            {
                "id": row.id,
                "source": row.source,
                "event_type": row.event_type,
                "summary": row.summary,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in sorted(asset.observations, key=lambda item: item.observed_at, reverse=True)
        ],
        "fingerprint_hypotheses": [
            {
                "id": row.id,
                "source": row.source,
                "device_type": row.device_type,
                "vendor": row.vendor,
                "model": row.model,
                "os_guess": row.os_guess,
                "confidence": row.confidence,
                "summary": row.summary,
                "supporting_evidence": row.supporting_evidence or [],
                "prompt_version": row.prompt_version,
                "model_used": row.model_used,
                "raw_response": row.raw_response,
                "created_at": row.created_at.isoformat(),
            }
            for row in sorted(asset.fingerprint_hypotheses, key=lambda item: item.created_at, reverse=True)
        ],
        "internet_lookup_results": [
            {
                "id": row.id,
                "query": row.query,
                "domain": row.domain,
                "url": row.url,
                "title": row.title,
                "snippet": row.snippet,
                "confidence": row.confidence,
                "looked_up_at": row.looked_up_at.isoformat(),
            }
            for row in sorted(asset.internet_lookup_results, key=lambda item: item.looked_up_at, reverse=True)
        ],
        "lifecycle_records": [
            {
                "id": row.id,
                "product": row.product,
                "version": row.version,
                "support_status": row.support_status,
                "eol_date": row.eol_date,
                "reference": row.reference,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in sorted(asset.lifecycle_records, key=lambda item: (item.support_status, item.product))
        ],
        "autopsy": {
            "id": asset.autopsy.id,
            "trace": asset.autopsy.trace,
            "created_at": asset.autopsy.created_at.isoformat(),
            "updated_at": asset.autopsy.updated_at.isoformat(),
        } if asset.autopsy else None,
    }


class AssetTagRequest(BaseModel):
    tag: str


class ConfigBackupTargetRequest(BaseModel):
    driver: str
    username: str
    password_env_var: str | None = None
    port: int = 22
    host_override: str | None = None
    enabled: bool = True


async def _load_asset(db: AsyncSession, asset_id: UUID) -> Asset:
    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.tags),
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


@router.get("/")
async def list_assets(
    search: AssetSearch = None,
    status: AssetStatus = None,
    tag: AssetTagFilter = None,
    skip: int = 0,
    limit: int = 100,
    db: DBSession = None,
    _: CurrentUser = None,
):
    """Return all discovered assets with optional filtering."""
    q = select(Asset).options(
        selectinload(Asset.tags),
        selectinload(Asset.ports),
        selectinload(Asset.ai_analysis),
        selectinload(Asset.evidence),
        selectinload(Asset.probe_runs),
        selectinload(Asset.observations),
        selectinload(Asset.fingerprint_hypotheses),
        selectinload(Asset.internet_lookup_results),
        selectinload(Asset.lifecycle_records),
        selectinload(Asset.autopsy),
    )
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
    q = q.offset(skip).limit(limit)
    result = await db.execute(q)
    return [_serialize_asset(asset) for asset in result.scalars().all()]


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
        f"<tr><td>{asset.ip_address}</td><td>{asset.hostname or ''}</td><td>{asset.vendor or ''}</td><td>{asset.effective_device_type}</td><td>{asset.status}</td><td>{', '.join(tag.tag for tag in asset.tags)}</td></tr>"
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


@router.get("/{asset_id}", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset(asset_id: UUID, db: DBSession, _: CurrentUser):
    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.tags),
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


@router.post("/{asset_id}/port-scan")
async def run_asset_port_scan(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    host = DiscoveredHost(
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        discovery_method="manual",
        nmap_hostname=asset.hostname,
    )
    ports, os_fp = await portscan.scan_host(host, ScanProfile.BALANCED)
    result = HostScanResult(
        host=host,
        ports=ports,
        os_fingerprint=os_fp,
        reverse_hostname=asset.hostname,
        scan_profile=ScanProfile.BALANCED,
    )

    from app.db.upsert import upsert_scan_result

    await upsert_scan_result(db, result)
    await db.commit()
    return _serialize_asset(await _load_asset(db, asset_id))


@router.post("/{asset_id}/ai-analysis/refresh")
async def run_asset_ai_refresh(
    asset_id: UUID,
    db: DBSession,
    _: AdminUser,
):
    asset = await _load_asset(db, asset_id)
    host = DiscoveredHost(
        ip_address=asset.ip_address,
        mac_address=asset.mac_address,
        discovery_method="manual",
        nmap_hostname=asset.hostname,
    )
    ports, os_fp = await portscan.scan_host(host, ScanProfile.BALANCED)
    result = await _investigate_host(
        host=host,
        ports=ports,
        os_fp=os_fp,
        nmap_hostname=host.nmap_hostname,
        nmap_vendor=asset.vendor,
        profile=ScanProfile.BALANCED,
        analyst=get_analyst(),
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


@router.patch("/{asset_id}", responses=ASSET_UPDATE_RESPONSES)
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


@router.get("/{asset_id}/probe-runs", responses=ASSET_NOT_FOUND_RESPONSE)
async def get_asset_probe_runs(asset_id: UUID, db: DBSession, _: CurrentUser):
    asset = await _load_asset(db, asset_id)
    return _serialize_asset(asset)["probe_runs"]


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
