"""Auth endpoints — login and token refresh."""
from uuid import UUID
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.alerting import list_alert_rules
from app.audit import log_audit_event
from app.core.security import (
    api_key_prefix,
    create_access_token,
    generate_api_key,
    hash_api_key,
    verify_password,
)
from app.db.models import ApiKey, AuditLog, User
from app.db.session import get_db
from app.core.security import hash_password

router = APIRouter()


class UserCreateRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    role: Literal["admin", "viewer"] = "viewer"


class UserUpdateRequest(BaseModel):
    role: Literal["admin", "viewer"] | None = None
    is_active: bool | None = None


class ApiKeyCreateRequest(BaseModel):
    name: str


class AlertRuleUpdateRequest(BaseModel):
    enabled: bool | None = None
    notify_email: bool | None = None
    notify_webhook: bool | None = None


def _serialize_user(user: User) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat(),
    }


def _serialize_api_key(api_key: ApiKey) -> dict:
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "is_active": api_key.is_active,
        "last_used_at": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        "created_at": api_key.created_at.isoformat(),
    }


def _serialize_audit_log(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details,
        "created_at": entry.created_at.isoformat(),
        "user": {
            "id": str(entry.user.id),
            "username": entry.user.username,
        } if entry.user else None,
    }


def _serialize_alert_rule(rule) -> dict:
    return {
        "id": rule.id,
        "event_type": rule.event_type,
        "description": rule.description,
        "enabled": rule.enabled,
        "notify_email": rule.notify_email,
        "notify_webhook": rule.notify_webhook,
        "created_at": rule.created_at.isoformat(),
    }


@router.post("/token")
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == form.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    await log_audit_event(db, action="auth.login", user=user)
    await db.commit()
    token = create_access_token(subject=str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return _serialize_user(current_user)


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    if payload.email:
        existing_email = await db.execute(select(User).where(User.email == payload.email))
        if existing_email.scalar_one_or_none() is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await log_audit_event(
        db,
        action="auth.user_created",
        user=_,
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username, "role": user.role},
    )
    await db.commit()
    await db.refresh(user)
    return _serialize_user(user)


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    result = await db.execute(select(User).order_by(User.created_at.asc()))
    return [_serialize_user(user) for user in result.scalars().all()]


@router.patch("/users/{user_id}")
async def update_user(
    user_id: UUID,
    payload: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    new_role = payload.role if payload.role is not None else user.role
    new_is_active = payload.is_active if payload.is_active is not None else user.is_active

    if user.id == current_user.id and (new_role != "admin" or not new_is_active):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot remove your own admin access")

    if user.role == "admin" and (new_role != "admin" or not new_is_active):
        admin_count = await db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True)))
        if admin_count is not None and admin_count <= 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one active admin is required")

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    await log_audit_event(
        db,
        action="auth.user_updated",
        user=current_user,
        target_type="user",
        target_id=str(user.id),
        details={"role": user.role, "is_active": user.is_active},
    )
    await db.commit()
    await db.refresh(user)
    return _serialize_user(user)


@router.get("/api-keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(ApiKey).where(ApiKey.user_id == current_user.id).order_by(ApiKey.created_at.desc()))
    return [_serialize_api_key(api_key) for api_key in result.scalars().all()]


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    raw_key = generate_api_key()
    api_key = ApiKey(
        user_id=current_user.id,
        name=payload.name.strip() or "API key",
        key_prefix=api_key_prefix(raw_key),
        hashed_key=hash_api_key(raw_key),
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    await log_audit_event(
        db,
        action="auth.api_key_created",
        user=current_user,
        target_type="api_key",
        target_id=str(api_key.id),
        details={"name": api_key.name, "key_prefix": api_key.key_prefix},
    )
    await db.commit()
    await db.refresh(api_key)
    return {**_serialize_api_key(api_key), "token": raw_key}


@router.delete("/api-keys/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    api_key_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    api_key = await db.get(ApiKey, api_key_id)
    if api_key is None or api_key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    await log_audit_event(
        db,
        action="auth.api_key_deleted",
        user=current_user,
        target_type="api_key",
        target_id=str(api_key.id),
        details={"name": api_key.name, "key_prefix": api_key.key_prefix},
    )
    await db.delete(api_key)
    await db.commit()


@router.get("/alert-rules")
async def get_alert_rules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    return [_serialize_alert_rule(rule) for rule in await list_alert_rules(db)]


@router.patch("/alert-rules/{rule_id}")
async def update_alert_rule(
    rule_id: int,
    payload: AlertRuleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    from app.db.models import AlertRule

    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")

    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.notify_email is not None:
        rule.notify_email = payload.notify_email
    if payload.notify_webhook is not None:
        rule.notify_webhook = payload.notify_webhook

    await log_audit_event(
        db,
        action="alert.rule_updated",
        user=current_user,
        target_type="alert_rule",
        target_id=str(rule.id),
        details={
            "event_type": rule.event_type,
            "enabled": rule.enabled,
            "notify_email": rule.notify_email,
            "notify_webhook": rule.notify_webhook,
        },
    )
    await db.commit()
    await db.refresh(rule)
    return _serialize_alert_rule(rule)


@router.get("/audit-logs")
async def list_audit_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(AuditLog).options(selectinload(AuditLog.user)).order_by(AuditLog.created_at.desc()).limit(limit)
    )
    return [_serialize_audit_log(entry) for entry in result.scalars().all()]
