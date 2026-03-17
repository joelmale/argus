from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin
from app.backups import get_backup_policy, list_backup_drivers, update_backup_policy
from app.db.models import Asset, User
from app.db.session import get_db
from app.exporters import build_inventory_snapshot
from app.integrations import build_home_assistant_entities, list_integration_events
from app.plugins import list_plugins

router = APIRouter()


class BackupPolicyUpdateRequest(BaseModel):
    enabled: bool
    interval_minutes: int
    tag_filter: str
    retention_count: int


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
