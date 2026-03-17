from __future__ import annotations

from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.alerting import ensure_default_alert_rules
from app.db.models import User
from app.db.session import AsyncSessionLocal


async def ensure_admin_user() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == settings.ADMIN_USERNAME))
        user = result.scalar_one_or_none()

        if user is not None:
            return

        db.add(
            User(
                username=settings.ADMIN_USERNAME,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
        )
        await db.commit()


async def ensure_system_defaults() -> None:
    async with AsyncSessionLocal() as db:
        await ensure_default_alert_rules(db)
