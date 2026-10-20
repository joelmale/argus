from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, Finding, Port
from app.services.identity import AssetIdentityResolver


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(severity: str | None) -> int:
    return SEVERITY_RANK.get((severity or "").lower(), 0)


def finding_state(finding: Finding, now: datetime | None = None) -> str:
    """open | acknowledged | resolved | ignored."""
    now = now or datetime.now(timezone.utc)
    if finding.status == "open" and finding.ack_until is not None and finding.ack_until > now:
        return "acknowledged"
    return finding.status


async def ingest_findings(
    db: AsyncSession,
    findings: list[dict],
    *,
    source_default: str = "import",
    created_out: list[dict] | None = None,
    resolved_external_ids: list[str] | None = None,
) -> dict[str, int]:
    """Upsert findings with lifecycle rules.

    - new: created open.
    - seen again: occurrences +1; a resolved finding reopens; a finding whose severity
      rises is "escalated" and loses its acknowledgement; ignored stays ignored.
    - `resolved_external_ids`: open findings from `source_default` with these external
      ids are resolved (the source reports the problem has gone away).
    If `created_out` is given, a summary of each newly created finding is appended to it.
    """
    created = 0
    updated = 0
    skipped = 0
    reopened = 0
    escalated = 0

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
            if created_out is not None:
                created_out.append({
                    "asset_id": str(asset.id),
                    "ip": asset.ip_address,
                    "source_tool": source_tool,
                    "external_id": external_id,
                    "title": title,
                    "severity": finding.severity,
                })
        else:
            change = _update_finding(finding, port, item, now)
            updated += 1
            reopened += change == "reopened"
            escalated += change == "escalated"

    resolved = await _resolve_missing(db, source_default, resolved_external_ids or [])
    await db.commit()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "reopened": reopened,
        "escalated": escalated,
        "resolved": resolved,
    }


async def _resolve_missing(db: AsyncSession, source_tool: str, external_ids: list[str]) -> int:
    ids = [i for i in {str(x) for x in external_ids} if i]
    if not ids:
        return 0
    rows = (await db.execute(
        select(Finding).where(
            Finding.source_tool == source_tool,
            Finding.external_id.in_(ids),
            Finding.status == "open",
        )
    )).scalars().all()
    now = datetime.now(timezone.utc)
    for finding in rows:
        finding.status = "resolved"
        finding.resolved_at = now
        finding.ack_until = None
        finding.ack_note = None
        finding.acked_by = None
    return len(rows)


def acknowledge(finding: Finding, *, until: datetime, note: str | None, by: str | None) -> None:
    finding.ack_until = until
    finding.ack_note = note
    finding.acked_by = by


def unacknowledge(finding: Finding) -> None:
    finding.ack_until = None
    finding.ack_note = None
    finding.acked_by = None


async def _resolve_existing_finding(
    db: AsyncSession,
    asset: Asset,
    item: dict,
    source_tool: str,
    title: str,
    external_id: str | None,
) -> Finding | None:
    if external_id:
        # A stable key identifies the finding on this asset even if its wording changes.
        # Keep the asset in the match: keys such as scanner plugin ids repeat across hosts.
        stmt = select(Finding).where(
            Finding.asset_id == asset.id,
            Finding.source_tool == source_tool,
            Finding.external_id == external_id,
        )
        return (await db.execute(stmt.order_by(Finding.id.desc()).limit(1))).scalar_one_or_none()
    stmt = select(Finding).where(
        Finding.asset_id == asset.id,
        Finding.source_tool == source_tool,
        Finding.title == title,
    )
    if item.get("cve"):
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


def _update_finding(finding: Finding, port: Port | None, item: dict, now: datetime) -> str | None:
    """Apply a repeat sighting. Returns "reopened", "escalated" or None."""
    change = None
    new_severity = (item.get("severity") or finding.severity).lower()
    requested = (item.get("status") or "").lower()
    if requested == "resolved":
        if finding.status != "resolved":
            finding.resolved_at = now
        finding.status = "resolved"
    elif finding.status == "resolved":
        finding.status = "open"
        finding.resolved_at = None
        unacknowledge(finding)
        change = "reopened"
    elif finding.status == "open" and severity_rank(new_severity) > severity_rank(finding.severity):
        unacknowledge(finding)
        change = "escalated"
    finding.occurrences = (finding.occurrences or 1) + 1
    if item.get("title"):
        finding.title = item["title"].strip() or finding.title
    finding.port_id = port.id if port else finding.port_id
    finding.description = item.get("description") or finding.description
    finding.severity = new_severity
    finding.cve = item.get("cve") or finding.cve
    finding.service = item.get("service") or finding.service
    finding.port_number = item.get("port_number") or finding.port_number
    finding.protocol = item.get("protocol") or finding.protocol
    finding.finding_metadata = {**(finding.finding_metadata or {}), **(item.get("metadata") or {})}
    finding.last_seen = now
    return change


async def summarize_findings(db: AsyncSession) -> dict:
    result = await db.execute(select(Finding))
    findings = result.scalars().all()
    severity_counts: dict[str, int] = {}
    open_count = 0
    acknowledged = 0
    now = datetime.now(timezone.utc)
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        state = finding_state(finding, now)
        if state == "open":
            open_count += 1
        elif state == "acknowledged":
            acknowledged += 1
    return {
        "total": len(findings),
        "open": open_count,
        "acknowledged": acknowledged,
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
