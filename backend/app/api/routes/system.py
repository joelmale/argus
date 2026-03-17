from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_current_admin
from app.backups import list_backup_drivers
from app.db.models import User
from app.plugins import list_plugins

router = APIRouter()


@router.get("/backup-drivers")
async def get_backup_drivers(_: User = Depends(get_current_admin)):
    return list_backup_drivers()


@router.get("/plugins")
async def get_plugins(_: User = Depends(get_current_admin)):
    return list_plugins()
