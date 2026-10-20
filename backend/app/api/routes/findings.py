from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerting import notify_new_findings_if_enabled
from app.api.deps import get_current_admin, get_current_user, get_ingest_user
from app.db.models import Finding, User
from app.db.session import get_db
from app.findings import acknowledge, finding_state, ingest_findings, summarize_findings, unacknowledge

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]
IngestUser = Annotated[User, Depends(get_ingest_user)]
SeverityFilter = Annotated[str | None, Query()]
StatusFilter = Annotated[str | None, Query(alias="status")]
AssetFilter = Annotated[str | None, Query()]


class FindingIngestItem(BaseModel):
    asset_id: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    hostname: str | None = None
    source_tool: str | None = None
    external_id: str | None = None
    title: str
    description: str | None = None
    severity: str = "info"
    status: str = "open"
    cve: str | None = None
    service: str | None = None
    port_number: int | None = None
    protocol: str | None = None
    metadata: dict | None = None


class FindingIngestRequest(BaseModel):
    source_tool: str = "import"
    findings: list[FindingIngestItem] = Field(default_factory=list)
    # External ids (for this source_tool) the source reports as gone: open ones are resolved.
    resolved_external_ids: list[str] = Field(default_factory=list, max_length=1000)


class FindingStatusRequest(BaseModel):
    status: Literal["open", "resolved", "ignored"]


class FindingAckRequest(BaseModel):
    # None = until the finding resolves (or is seen at a higher severity).
    hours: float | None = Field(default=None, gt=0, le=24 * 365)
    note: str | None = Field(default=None, max_length=500)


def _serialize_finding(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "asset_id": str(finding.asset_id),
        "port_id": finding.port_id,
        "source_tool": finding.source_tool,
        "external_id": finding.external_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "status": finding.status,
        "cve": finding.cve,
        "service": finding.service,
        "port_number": finding.port_number,
        "protocol": finding.protocol,
        "metadata": finding.finding_metadata,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "state": finding_state(finding),
        "occurrences": finding.occurrences,
        "ack_until": finding.ack_until.isoformat() if finding.ack_until else None,
        "ack_note": finding.ack_note,
        "acked_by": finding.acked_by,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }


@router.get("", include_in_schema=False)
@router.get("/")
async def list_findings(
    severity: SeverityFilter = None,
    status_filter: StatusFilter = None,
    asset_id: AssetFilter = None,
    source_tool: Annotated[str | None, Query(max_length=64)] = None,
    external_id: Annotated[str | None, Query(max_length=128)] = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=200, le=1000),
    db: DBSession = None,
    _: CurrentUser = None,
):
    stmt = select(Finding).order_by(Finding.last_seen.desc())
    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter.lower())
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if source_tool:
        stmt = stmt.where(Finding.source_tool == source_tool)
    if external_id:
        stmt = stmt.where(Finding.external_id == external_id)
    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    return [_serialize_finding(finding) for finding in result.scalars().all()]


@router.get("/summary")
async def get_findings_summary(
    db: DBSession,
    _: CurrentUser,
):
    return await summarize_findings(db)


@router.post("/ingest")
async def ingest_findings_route(
    payload: FindingIngestRequest,
    db: DBSession,
    _: IngestUser,
):
    created: list[dict] = []
    result = await ingest_findings(
        db,
        [item.model_dump(mode="json") for item in payload.findings],
        source_default=payload.source_tool,
        created_out=created,
        resolved_external_ids=payload.resolved_external_ids,
    )
    if created:
        await notify_new_findings_if_enabled(db, {"findings": created})
    return result


@router.patch("/{finding_id}")
async def update_finding_status(
    finding_id: int,
    payload: FindingStatusRequest,
    db: DBSession,
    _: AdminUser,
):
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.status = payload.status
    finding.resolved_at = datetime.now(timezone.utc) if payload.status == "resolved" else None
    if payload.status != "open":
        unacknowledge(finding)
    await db.commit()
    await db.refresh(finding)
    return _serialize_finding(finding)


@router.post("/{finding_id}/ack")
async def acknowledge_finding(
    finding_id: int,
    payload: FindingAckRequest,
    db: DBSession,
    user: IngestUser,
):
    """Known issue: stop re-alerting until `hours` pass, it resolves, or it escalates."""
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if finding.status != "open":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Finding is {finding.status}, not open")
    now = datetime.now(timezone.utc)
    until = now + (timedelta(hours=payload.hours) if payload.hours is not None else timedelta(days=3650))
    acknowledge(finding, until=until, note=payload.note, by=user.username)
    await db.commit()
    await db.refresh(finding)
    return _serialize_finding(finding)


@router.post("/{finding_id}/unack")
async def unacknowledge_finding(
    finding_id: int,
    db: DBSession,
    _: IngestUser,
):
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    unacknowledge(finding)
    await db.commit()
    await db.refresh(finding)
    return _serialize_finding(finding)
