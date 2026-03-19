from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin
from app.audit import log_audit_event
from app.backups import get_backup_policy, list_backup_drivers, update_backup_policy
from app.db.models import Asset, User
from app.db.session import get_db
from app.exporters import build_inventory_snapshot
from app.integrations import build_home_assistant_entities, list_integration_events
from app.plugins import list_plugins
from app.scanner.config import clear_inventory, read_effective_scanner_config, update_scanner_config

router = APIRouter()


class BackupPolicyUpdateRequest(BaseModel):
    enabled: bool
    interval_minutes: int
    tag_filter: str
    retention_count: int


class ScannerConfigUpdateRequest(BaseModel):
    enabled: bool
    default_targets: str | None = None
    auto_detect_targets: bool
    default_profile: str
    interval_minutes: int
    concurrent_hosts: int
    fingerprint_ai_enabled: bool = False
    fingerprint_ai_model: str | None = None
    fingerprint_ai_min_confidence: float = 0.75
    fingerprint_ai_prompt_suffix: str | None = None


class ResetInventoryRequest(BaseModel):
    include_scan_history: bool = False
    confirm: str


def _serialize_scanner_config(config, effective) -> dict:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "default_targets": config.default_targets,
        "auto_detect_targets": config.auto_detect_targets,
        "detected_targets": effective.detected_targets,
        "effective_targets": effective.effective_targets,
        "default_profile": config.default_profile,
        "interval_minutes": config.interval_minutes,
        "concurrent_hosts": config.concurrent_hosts,
        "fingerprint_ai_enabled": config.fingerprint_ai_enabled,
        "fingerprint_ai_model": effective.fingerprint_ai_model,
        "fingerprint_ai_min_confidence": config.fingerprint_ai_min_confidence,
        "fingerprint_ai_prompt_suffix": config.fingerprint_ai_prompt_suffix,
        "last_scheduled_scan_at": config.last_scheduled_scan_at.isoformat() if config.last_scheduled_scan_at else None,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


@router.get("/backup-drivers")
async def get_backup_drivers(_: User = Depends(get_current_admin)):
    return list_backup_drivers()


@router.get("/plugins")
async def get_plugins(_: User = Depends(get_current_admin)):
    return list_plugins()


@router.get("/integration-events")
async def get_integration_events(_: User = Depends(get_current_admin)):
    return list_integration_events()


@router.get("/integrations/home-assistant/entities")
async def get_home_assistant_entities(
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.tags), selectinload(Asset.ports))
        .where(Asset.status != "unknown")
        .order_by(Asset.hostname.asc())
    )
    assets = result.scalars().all()
    return build_home_assistant_entities(assets)


@router.get("/integrations/inventory-sync")
async def get_inventory_sync_export(
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.tags), selectinload(Asset.ports))
        .order_by(Asset.ip_address.asc())
    )
    assets = result.scalars().all()
    return {
        "mode": "read_only_export",
        "description": "Use this normalized snapshot to sync Argus inventory into external systems.",
        "snapshot": build_inventory_snapshot(assets),
    }


@router.get("/backup-policy")
async def read_backup_policy(
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    policy = await get_backup_policy(db)
    return {
        "id": policy.id,
        "enabled": policy.enabled,
        "interval_minutes": policy.interval_minutes,
        "tag_filter": policy.tag_filter,
        "retention_count": policy.retention_count,
        "last_run_at": policy.last_run_at.isoformat() if policy.last_run_at else None,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }


@router.get("/scanner-config")
async def get_scanner_config(
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    config, effective = await read_effective_scanner_config(db)
    return _serialize_scanner_config(config, effective)


@router.put("/scanner-config")
async def write_scanner_config(
    payload: ScannerConfigUpdateRequest,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    try:
        config, effective = await update_scanner_config(
            db,
            enabled=payload.enabled,
            default_targets=payload.default_targets,
            auto_detect_targets=payload.auto_detect_targets,
            default_profile=payload.default_profile,
            interval_minutes=payload.interval_minutes,
            concurrent_hosts=payload.concurrent_hosts,
            fingerprint_ai_enabled=payload.fingerprint_ai_enabled,
            fingerprint_ai_model=payload.fingerprint_ai_model,
            fingerprint_ai_min_confidence=payload.fingerprint_ai_min_confidence,
            fingerprint_ai_prompt_suffix=payload.fingerprint_ai_prompt_suffix,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="scanner.config.updated",
        user=user,
        target_type="scanner_config",
        target_id=str(config.id),
        details={"effective_targets": effective.effective_targets},
    )
    await db.commit()
    return _serialize_scanner_config(config, effective)


@router.post("/inventory/reset")
async def reset_inventory(
    payload: ResetInventoryRequest,
    user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    if payload.confirm.strip().lower() != "reset inventory":
        raise HTTPException(status_code=400, detail="Confirmation text must be 'reset inventory'")
    result = await clear_inventory(db, include_scan_history=payload.include_scan_history, actor=user)
    await db.commit()
    return result


@router.put("/backup-policy")
async def write_backup_policy(
    payload: BackupPolicyUpdateRequest,
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    policy = await update_backup_policy(
        db,
        enabled=payload.enabled,
        interval_minutes=payload.interval_minutes,
        tag_filter=payload.tag_filter,
        retention_count=payload.retention_count,
    )
    return {
        "id": policy.id,
        "enabled": policy.enabled,
        "interval_minutes": policy.interval_minutes,
        "tag_filter": policy.tag_filter,
        "retention_count": policy.retention_count,
        "last_run_at": policy.last_run_at.isoformat() if policy.last_run_at else None,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }
