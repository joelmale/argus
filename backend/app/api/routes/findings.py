from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.db.models import Finding, User
from app.db.session import get_db
from app.findings import ingest_findings, summarize_findings

router = APIRouter()


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


class FindingStatusRequest(BaseModel):
    status: str


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
    }


@router.get("/")
async def list_findings(
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    asset_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(Finding).order_by(Finding.last_seen.desc())
    if severity:
        stmt = stmt.where(Finding.severity == severity.lower())
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter.lower())
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    result = await db.execute(stmt)
    return [_serialize_finding(finding) for finding in result.scalars().all()]


@router.get("/summary")
async def get_findings_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return await summarize_findings(db)


@router.post("/ingest")
async def ingest_findings_route(
    payload: FindingIngestRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    return await ingest_findings(
        db,
        [item.model_dump(mode="json") for item in payload.findings],
        source_default=payload.source_tool,
    )


@router.patch("/{finding_id}")
async def update_finding_status(
    finding_id: int,
    payload: FindingStatusRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.status = payload.status.lower()
    await db.commit()
    await db.refresh(finding)
    return _serialize_finding(finding)
