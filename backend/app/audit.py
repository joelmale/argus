from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, User


async def log_audit_event(
    db: AsyncSession,
    *,
    action: str,
    user: User | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user is not None else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
        )
    )
    await db.flush()
