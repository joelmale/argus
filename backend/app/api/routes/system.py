from __future__ import annotations

from typing import Annotated

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
from app.fingerprinting.datasets import list_datasets, refresh_dataset
from app.integrations import build_home_assistant_entities, list_integration_events
from app.modules.tplink_deco import (
    audit_tplink_config_change,
    get_or_create_tplink_deco_config,
    list_recent_tplink_deco_sync_runs,
    serialize_tplink_deco_config,
    serialize_tplink_deco_sync_run,
    sync_tplink_deco_module,
    test_tplink_deco_connection,
    update_tplink_deco_config,
)
from app.plugins import list_plugins
from app.scanner.config import clear_inventory, read_effective_scanner_config, update_scanner_config

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
FINGERPRINT_REFRESH_RESPONSES = {404: {"description": "Fingerprint dataset not found"}}
TPLINK_MODULE_RESPONSES = {
    400: {"description": "Module configuration is invalid"},
    502: {"description": "Module connection failed"},
}
SCANNER_CONFIG_RESPONSES = {400: {"description": "Scanner configuration is invalid"}}
RESET_INVENTORY_RESPONSES = {400: {"description": "Inventory reset confirmation text is invalid"}}


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
    passive_arp_enabled: bool = True
    passive_arp_interface: str = "eth0"
    snmp_enabled: bool = True
    snmp_version: str = "2c"
    snmp_community: str | None = None
    snmp_timeout: int = 5
    snmp_v3_username: str | None = None
    snmp_v3_auth_key: str | None = None
    snmp_v3_priv_key: str | None = None
    snmp_v3_auth_protocol: str = "sha"
    snmp_v3_priv_protocol: str = "aes"
    fingerprint_ai_enabled: bool = False
    fingerprint_ai_model: str | None = None
    fingerprint_ai_min_confidence: float = 0.75
    fingerprint_ai_prompt_suffix: str | None = None
    internet_lookup_enabled: bool = False
    internet_lookup_allowed_domains: str | None = None
    internet_lookup_budget: int = 3
    internet_lookup_timeout_seconds: int = 5


class ResetInventoryRequest(BaseModel):
    include_scan_history: bool = False
    confirm: str


class TplinkDecoConfigUpdateRequest(BaseModel):
    enabled: bool
    base_url: str = "http://tplinkdeco.net"
    owner_username: str | None = None
    owner_password: str | None = None
    fetch_connected_clients: bool = True
    fetch_portal_logs: bool = True
    request_timeout_seconds: int = 10
    verify_tls: bool = False


def _serialize_dataset(row) -> dict:
    return {
        "id": row.id,
        "key": row.key,
        "name": row.name,
        "category": row.category,
        "description": row.description,
        "upstream_url": row.upstream_url,
        "local_path": row.local_path,
        "update_mode": row.update_mode,
        "enabled": row.enabled,
        "status": row.status,
        "last_checked_at": row.last_checked_at.isoformat() if row.last_checked_at else None,
        "last_updated_at": row.last_updated_at.isoformat() if row.last_updated_at else None,
        "upstream_last_modified": row.upstream_last_modified,
        "etag": row.etag,
        "sha256": row.sha256,
        "record_count": row.record_count,
        "error": row.error,
        "notes": row.notes,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


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
        "passive_arp_enabled": config.passive_arp_enabled,
        "passive_arp_interface": config.passive_arp_interface,
        "snmp_enabled": config.snmp_enabled,
        "snmp_version": config.snmp_version,
        "snmp_community": config.snmp_community,
        "snmp_timeout": config.snmp_timeout,
        "snmp_v3_username": config.snmp_v3_username,
        "snmp_v3_auth_key": config.snmp_v3_auth_key,
        "snmp_v3_priv_key": config.snmp_v3_priv_key,
        "snmp_v3_auth_protocol": config.snmp_v3_auth_protocol,
        "snmp_v3_priv_protocol": config.snmp_v3_priv_protocol,
        "fingerprint_ai_enabled": config.fingerprint_ai_enabled,
        "fingerprint_ai_model": effective.fingerprint_ai_model,
        "fingerprint_ai_min_confidence": config.fingerprint_ai_min_confidence,
        "fingerprint_ai_prompt_suffix": config.fingerprint_ai_prompt_suffix,
        "internet_lookup_enabled": config.internet_lookup_enabled,
        "internet_lookup_allowed_domains": config.internet_lookup_allowed_domains,
        "internet_lookup_budget": config.internet_lookup_budget,
        "internet_lookup_timeout_seconds": config.internet_lookup_timeout_seconds,
        "last_scheduled_scan_at": config.last_scheduled_scan_at.isoformat() if config.last_scheduled_scan_at else None,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


@router.get("/backup-drivers")
async def get_backup_drivers(_: AdminUser):
    return list_backup_drivers()


@router.get("/plugins")
async def get_plugins(_: AdminUser):
    return list_plugins()


@router.get("/integration-events")
async def get_integration_events(_: AdminUser):
    return list_integration_events()


@router.get("/fingerprint-datasets")
async def get_fingerprint_datasets(
    _: AdminUser,
    db: DBSession,
):
    rows = await list_datasets(db)
    await db.commit()
    return [_serialize_dataset(row) for row in rows]


@router.post("/fingerprint-datasets/{dataset_key}/refresh", responses=FINGERPRINT_REFRESH_RESPONSES)
async def refresh_fingerprint_dataset(
    dataset_key: str,
    user: AdminUser,
    db: DBSession,
):
    try:
        row = await refresh_dataset(db, dataset_key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="fingerprint.dataset.refreshed",
        user=user,
        target_type="fingerprint_dataset",
        target_id=dataset_key,
        details={"status": row.status, "record_count": row.record_count, "error": row.error},
    )
    await db.commit()
    return _serialize_dataset(row)


@router.get("/integrations/home-assistant/entities")
async def get_home_assistant_entities(
    _: AdminUser,
    db: DBSession,
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
    _: AdminUser,
    db: DBSession,
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
    _: AdminUser,
    db: DBSession,
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
    _: AdminUser,
    db: DBSession,
):
    config, effective = await read_effective_scanner_config(db)
    return _serialize_scanner_config(config, effective)


@router.get("/modules/tplink-deco")
async def get_tplink_deco_module(
    _: AdminUser,
    db: DBSession,
):
    config = await get_or_create_tplink_deco_config(db)
    runs = await list_recent_tplink_deco_sync_runs(db)
    return {
        "config": serialize_tplink_deco_config(config),
        "recent_runs": [serialize_tplink_deco_sync_run(row) for row in runs],
    }


@router.put("/modules/tplink-deco")
async def write_tplink_deco_module(
    payload: TplinkDecoConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    config = await update_tplink_deco_config(
        db,
        enabled=payload.enabled,
        base_url=payload.base_url,
        owner_username=payload.owner_username,
        owner_password=payload.owner_password,
        fetch_connected_clients=payload.fetch_connected_clients,
        fetch_portal_logs=payload.fetch_portal_logs,
        request_timeout_seconds=payload.request_timeout_seconds,
        verify_tls=payload.verify_tls,
    )
    await audit_tplink_config_change(db, user=user, config=config)
    await db.commit()
    return serialize_tplink_deco_config(config)


@router.post("/modules/tplink-deco/test", responses=TPLINK_MODULE_RESPONSES)
async def test_tplink_deco_module(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await test_tplink_deco_connection(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.tplink_deco.tested",
        user=user,
        target_type="tplink_deco_config",
        details=result,
    )
    await db.commit()
    return result


@router.post("/modules/tplink-deco/sync", responses=TPLINK_MODULE_RESPONSES)
async def run_tplink_deco_module_sync(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await sync_tplink_deco_module(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.tplink_deco.synced",
        user=user,
        target_type="tplink_deco_sync",
        target_id=str(result.get("run_id")),
        details=result,
    )
    await db.commit()
    return result


@router.put("/scanner-config", responses=SCANNER_CONFIG_RESPONSES)
async def write_scanner_config(
    payload: ScannerConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
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
            passive_arp_enabled=payload.passive_arp_enabled,
            passive_arp_interface=payload.passive_arp_interface,
            snmp_enabled=payload.snmp_enabled,
            snmp_version=payload.snmp_version,
            snmp_community=payload.snmp_community,
            snmp_timeout=payload.snmp_timeout,
            snmp_v3_username=payload.snmp_v3_username,
            snmp_v3_auth_key=payload.snmp_v3_auth_key,
            snmp_v3_priv_key=payload.snmp_v3_priv_key,
            snmp_v3_auth_protocol=payload.snmp_v3_auth_protocol,
            snmp_v3_priv_protocol=payload.snmp_v3_priv_protocol,
            fingerprint_ai_enabled=payload.fingerprint_ai_enabled,
            fingerprint_ai_model=payload.fingerprint_ai_model,
            fingerprint_ai_min_confidence=payload.fingerprint_ai_min_confidence,
            fingerprint_ai_prompt_suffix=payload.fingerprint_ai_prompt_suffix,
            internet_lookup_enabled=payload.internet_lookup_enabled,
            internet_lookup_allowed_domains=payload.internet_lookup_allowed_domains,
            internet_lookup_budget=payload.internet_lookup_budget,
            internet_lookup_timeout_seconds=payload.internet_lookup_timeout_seconds,
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


@router.post("/inventory/reset", responses=RESET_INVENTORY_RESPONSES)
async def reset_inventory(
    payload: ResetInventoryRequest,
    user: AdminUser,
    db: DBSession,
):
    if payload.confirm.strip().lower() != "reset inventory":
        raise HTTPException(status_code=400, detail="Confirmation text must be 'reset inventory'")
    result = await clear_inventory(db, include_scan_history=payload.include_scan_history, actor=user)
    await db.commit()
    return result


@router.put("/backup-policy")
async def write_backup_policy(
    payload: BackupPolicyUpdateRequest,
    _: AdminUser,
    db: DBSession,
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
