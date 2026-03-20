from __future__ import annotations

from app.alerting import ensure_default_alert_rules
from app.backups import get_backup_policy
from app.db.session import AsyncSessionLocal
from app.scanner.config import get_or_create_scanner_config


async def ensure_system_defaults() -> None:
    async with AsyncSessionLocal() as db:
        await ensure_default_alert_rules(db)
        await get_backup_policy(db)
        await get_or_create_scanner_config(db)
        await db.commit()
