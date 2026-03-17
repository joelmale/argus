from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.backups import get_backup_policy, list_backup_drivers, update_backup_policy
from app.db.models import User
from app.db.session import get_db
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
