from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AlertRule
from app.notifications import notify_devices_offline, notify_new_device

DEFAULT_ALERT_RULES = {
    "new_device": {
        "description": "Notify when a new device is discovered",
        "enabled": True,
        "notify_email": True,
        "notify_webhook": True,
    },
    "devices_offline": {
        "description": "Notify when a device goes offline",
        "enabled": True,
        "notify_email": True,
        "notify_webhook": True,
    },
}


async def ensure_default_alert_rules(db: AsyncSession) -> None:
    for event_type, config in DEFAULT_ALERT_RULES.items():
        result = await db.execute(select(AlertRule).where(AlertRule.event_type == event_type))
        if result.scalar_one_or_none() is None:
            db.add(AlertRule(event_type=event_type, **config))
    await db.commit()


async def list_alert_rules(db: AsyncSession) -> list[AlertRule]:
    result = await db.execute(select(AlertRule).order_by(AlertRule.event_type.asc()))
    return result.scalars().all()


async def notify_new_device_if_enabled(db: AsyncSession, payload: dict) -> None:
    rule = await _get_rule(db, "new_device")
    if not rule or not rule.enabled:
        return
    await notify_new_device(payload, webhook=rule.notify_webhook, email=rule.notify_email)


async def notify_devices_offline_if_enabled(db: AsyncSession, devices: list[dict]) -> None:
    rule = await _get_rule(db, "devices_offline")
    if not rule or not rule.enabled:
        return
    await notify_devices_offline(devices, webhook=rule.notify_webhook, email=rule.notify_email)


async def _get_rule(db: AsyncSession, event_type: str) -> AlertRule | None:
    result = await db.execute(select(AlertRule).where(AlertRule.event_type == event_type))
    return result.scalar_one_or_none()
