"""Security operations: a read-mostly proxy to InSOC so Argus is the single console.

InSOC's API token stays on the server (INSOC_API_TOKEN); the browser only talks to Argus.
Any signed-in user can view incidents; approving or denying InSOC's proposed actions
(e.g. restarting a container) is admin-only and audit-logged.
"""
from __future__ import annotations

import re
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.audit import log_audit_event
from app.core.config import settings
from app.db.models import User
from app.db.session import get_db

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]

INCIDENT_ID = r"^INC-\d{8}-[0-9a-f]{6}$"
_ACTION_ID = re.compile(r"^[0-9a-f]{8}$")
IncidentId = Annotated[str, Path(pattern=INCIDENT_ID)]

# Fields passed through from InSOC's incident detail; the rest (checkpoint ledger etc.) stays there.
_DETAIL_FIELDS = (
    "id", "status", "severity", "alert_severity", "trigger", "created", "report", "finding_states",
    "resolved_findings", "pending_approval", "action_results", "usage", "error",
)


class ResumeRequest(BaseModel):
    approve: list[str] = Field(default_factory=list, max_length=50)
    deny: list[str] = Field(default_factory=list, max_length=50)


def _configured() -> bool:
    return bool(settings.INSOC_URL and settings.INSOC_API_TOKEN)


async def _insoc(method: str, path: str, *, json: dict | None = None, params: dict | None = None):
    if not _configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="InSOC is not configured (INSOC_URL / INSOC_API_TOKEN)")
    try:
        async with httpx.AsyncClient(base_url=settings.INSOC_URL.rstrip("/"), timeout=15) as client:
            response = await client.request(
                method, path, json=json, params=params,
                headers={"Authorization": f"Bearer {settings.INSOC_API_TOKEN}"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"InSOC unreachable: {type(exc).__name__}") from exc
    if response.status_code == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if response.status_code == 409:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=response.json().get("detail", "Conflict"))
    if response.status_code in (401, 403):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="InSOC rejected Argus's token (check INSOC_API_TOKEN)")
    if response.status_code >= 400:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"InSOC returned HTTP {response.status_code}")
    return response.json()


@router.get("/status")
async def soc_status(_: CurrentUser):
    if not _configured():
        return {"configured": False, "reachable": False}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.INSOC_URL.rstrip('/')}/healthz")
        reachable = response.status_code == 200
    except httpx.HTTPError:
        reachable = False
    return {"configured": True, "reachable": reachable}


@router.get("/digest")
async def get_digest(_: CurrentUser):
    """InSOC's daily digest: the narrative brief of open findings (Argus doesn't build its own)."""
    data = await _insoc("GET", "/digest")
    keep = ("text", "generated_at", "open", "acknowledged", "next_scheduled", "timezone")
    return {k: data.get(k) for k in keep}


@router.get("/incidents")
async def list_incidents(_: CurrentUser, limit: int = Query(default=50, ge=1, le=200)):
    rows = await _insoc("GET", "/incidents", params={"limit": limit})
    keep = ("id", "created", "trigger", "status", "severity", "alert_severity", "cost_usd", "duration_s")
    return [{k: row.get(k) for k in keep} for row in rows]


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: IncidentId, _: CurrentUser):
    data = await _insoc("GET", f"/incidents/{incident_id}")
    return {k: data.get(k) for k in _DETAIL_FIELDS}


@router.post("/incidents/{incident_id}/resume")
async def resume_incident(incident_id: IncidentId, payload: ResumeRequest, db: DBSession, user: AdminUser):
    """Approve or deny the remediation actions an incident is waiting on."""
    ids = payload.approve + payload.deny
    if not ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Approve or deny at least one action")
    if any(not _ACTION_ID.match(i) for i in ids) or set(payload.approve) & set(payload.deny):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid action ids")
    result = await _insoc("POST", f"/incidents/{incident_id}/resume", json={"approve": payload.approve, "deny": payload.deny})
    await log_audit_event(
        db,
        action="soc.incident_resumed",
        user=user,
        target_type="insoc_incident",
        target_id=incident_id,
        details={"approve": payload.approve, "deny": payload.deny},
    )
    await db.commit()
    return result
