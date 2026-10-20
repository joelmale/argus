from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.security import decode_access_token, api_key_prefix, verify_api_key
from app.db.models import ApiKey, User
from app.db.session import get_db


async def user_from_access_token(db: AsyncSession, token: str) -> User | None:
    """Active user for a login token, or None if invalid, revoked or the user is disabled."""
    decoded = decode_access_token(token)
    if decoded is None:
        return None
    subject, version = decoded
    try:
        user = await db.get(User, subject)
    except (ValueError, TypeError):
        return None
    if user is None or not user.is_active or version != (user.token_version or 0):
        return None
    return user


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        user = await user_from_access_token(db, token)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user

    raw_api_key = request.headers.get("X-API-Key")
    if raw_api_key:
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_prefix == api_key_prefix(raw_api_key), ApiKey.is_active.is_(True))
        )
        api_key = result.scalar_one_or_none()
        if api_key is None or not verify_api_key(raw_api_key, api_key.hashed_key):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        user = await db.get(User, api_key.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        now = datetime.now(timezone.utc)
        if api_key.last_used_at is None or (now - api_key.last_used_at).total_seconds() > 60:
            api_key.last_used_at = now
            await db.commit()
        return user

    # Browser session: httpOnly cookie set at login (SameSite=Strict, so not sent cross-site).
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token:
        user = await user_from_access_token(db, cookie_token)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
        return user

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def get_ingest_user(user: User = Depends(get_current_user)) -> User:
    """Admins, or `service` accounts used by integrations (read access plus ingest only)."""
    if user.role not in ("admin", "service"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin or service access required")
    return user


def require_role(role: str) -> Callable[[User], User]:
    def _require_role(user: User = Depends(get_current_user)) -> User:
        if user.role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{role.title()} access required")
        return user

    return _require_role
