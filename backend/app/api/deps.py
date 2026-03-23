from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.security import decode_token, api_key_prefix, verify_api_key
from app.db.models import ApiKey, User
from app.db.session import get_db

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        subject = decode_token(token)
        if not subject:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        user = await db.get(User, subject)
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
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

        api_key.last_used_at = datetime.now(timezone.utc)
        await db.commit()
        return user

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_role(role: str) -> Callable[[User], User]:
    async def _require_role(user: User = Depends(get_current_user)) -> User:
        if user.role != role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{role.title()} access required")
        return user

    return _require_role
