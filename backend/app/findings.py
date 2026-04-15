from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Finding, Port
from app.services.identity import AssetIdentityResolver


async def ingest_findings(db: AsyncSession, findings: list[dict], *, source_default: str = "import") -> dict[str, int]:
    created = 0
    updated = 0
    skipped = 0

    for item in findings:
        asset = await _resolve_asset(db, item)
        if asset is None:
            skipped += 1
            continue

        port = await _resolve_port(db, asset, item)
        source_tool = (item.get("source_tool") or source_default).strip() or source_default
        external_id = item.get("external_id")
        title = (item.get("title") or "").strip()
        if not title:
            skipped += 1
            continue

        finding = await _resolve_existing_finding(db, asset, item, source_tool, title, external_id)
        now = datetime.now(timezone.utc)
        if finding is None:
            finding = _build_finding(asset, port, item, source_tool, external_id, title, now)
            db.add(finding)
            created += 1
        else:
            _update_finding(finding, port, item, now)
            updated += 1

    await db.commit()
    return {"created": created, "updated": updated, "skipped": skipped}


async def _resolve_existing_finding(
    db: AsyncSession,
    asset: Asset,
    item: dict,
    source_tool: str,
    title: str,
    external_id: str | None,
) -> Finding | None:
    stmt = select(Finding).where(
        Finding.asset_id == asset.id,
        Finding.source_tool == source_tool,
        Finding.title == title,
    )
    if external_id:
        stmt = stmt.where(Finding.external_id == external_id)
    elif item.get("cve"):
        stmt = stmt.where(Finding.cve == item["cve"])
    return (await db.execute(stmt)).scalar_one_or_none()


def _build_finding(
    asset: Asset,
    port: Port | None,
    item: dict,
    source_tool: str,
    external_id: str | None,
    title: str,
    now: datetime,
) -> Finding:
    return Finding(
        asset_id=asset.id,
        port_id=port.id if port else None,
        source_tool=source_tool,
        external_id=external_id,
        title=title,
        description=item.get("description"),
        severity=(item.get("severity") or "info").lower(),
        status=(item.get("status") or "open").lower(),
        cve=item.get("cve"),
        service=item.get("service"),
        port_number=item.get("port_number"),
        protocol=item.get("protocol"),
        finding_metadata=item.get("metadata") or {},
        first_seen=now,
        last_seen=now,
    )


def _update_finding(finding: Finding, port: Port | None, item: dict, now: datetime) -> None:
    finding.port_id = port.id if port else finding.port_id
    finding.description = item.get("description") or finding.description
    finding.severity = (item.get("severity") or finding.severity).lower()
    finding.status = (item.get("status") or finding.status).lower()
    finding.cve = item.get("cve") or finding.cve
    finding.service = item.get("service") or finding.service
    finding.port_number = item.get("port_number") or finding.port_number
    finding.protocol = item.get("protocol") or finding.protocol
    finding.finding_metadata = {**(finding.finding_metadata or {}), **(item.get("metadata") or {})}
    finding.last_seen = now


async def summarize_findings(db: AsyncSession) -> dict:
    result = await db.execute(select(Finding))
    findings = result.scalars().all()
    severity_counts: dict[str, int] = {}
    open_count = 0
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        if finding.status == "open":
            open_count += 1
    return {
        "total": len(findings),
        "open": open_count,
        "severity_counts": severity_counts,
    }


async def _resolve_asset(db: AsyncSession, payload: dict) -> Asset | None:
    asset_id = payload.get("asset_id")
    if asset_id:
        return await db.get(Asset, asset_id)

    resolver = AssetIdentityResolver(db, source="finding")
    return await resolver.resolve_asset(
        mac=payload.get("mac_address"),
        ip=payload.get("ip_address"),
        hostname=payload.get("hostname"),
        create_if_missing=False,
        lookup_order=("ip", "mac", "hostname"),
    )


async def _resolve_port(db: AsyncSession, asset: Asset, payload: dict) -> Port | None:
    port_number = payload.get("port_number")
    if port_number is None:
        return None
    protocol = payload.get("protocol") or "tcp"
    stmt = select(Port).where(
        and_(Port.asset_id == asset.id, Port.port_number == port_number, Port.protocol == protocol)
    )
    return (await db.execute(stmt)).scalar_one_or_none()
