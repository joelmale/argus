from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import (
    Asset,
    ConfigBackupSnapshot,
    Finding,
    FirewallaSyncRun,
    LifecycleRecord,
    PfsenseSyncRun,
    ScanJob,
    TplinkDecoSyncRun,
    TopologyLink,
    UnifiSyncRun,
)

MAX_SECTION_ITEMS = 6
STALE_ASSET_DAYS = 7
HIGH_RISK_PORTS = {
    21: "FTP exposed",
    23: "Telnet exposed",
    445: "SMB exposed",
    3389: "RDP exposed",
    5900: "VNC exposed",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _asset_label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address


def _asset_route(asset_id: object) -> str:
    return f"/assets/{asset_id}"


def _action(
    label: str,
    route: str,
    *,
    requires_admin: bool = False,
    kind: str = "navigate",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "label": label,
        "route": route,
        "kind": kind,
        "requires_admin": requires_admin,
        "payload": payload,
    }


def _item(
    *,
    key: str,
    title: str,
    reason: str,
    severity: str = "info",
    target_type: str | None = None,
    target_id: str | None = None,
    target_label: str | None = None,
    route: str | None = None,
    action: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "key": key,
        "title": title,
        "reason": reason,
        "severity": severity,
        "target_type": target_type,
        "target_id": target_id,
        "target_label": target_label,
        "route": route,
        "action": action,
        "occurred_at": _iso(occurred_at),
        "metadata": metadata or {},
    }


def _section(key: str, title: str, question: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "key": key,
        "title": title,
        "question": question,
        "items": items[:MAX_SECTION_ITEMS],
        "total": len(items),
    }


def _severity_rank(value: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get((value or "info").lower(), 0)


def _asset_has_low_confidence_ai(asset: Asset) -> bool:
    analysis = getattr(asset, "ai_analysis", None)
    return bool(analysis and analysis.confidence is not None and analysis.confidence < 0.6)


def _asset_is_unknown(asset: Asset) -> bool:
    device_type = (asset.effective_device_type or "unknown").lower()
    return device_type == "unknown" or not asset.vendor or not asset.hostname or _asset_has_low_confidence_ai(asset)


def _open_ports(asset: Asset) -> set[int]:
    return {port.port_number for port in getattr(asset, "ports", []) if port.state == "open"}


def _changed_items(assets: list[Asset], scans: list[ScanJob], since: datetime) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for asset in sorted(assets, key=lambda row: row.first_seen or since, reverse=True):
        if asset.first_seen and asset.first_seen >= since:
            label = _asset_label(asset)
            items.append(
                _item(
                    key=f"asset-new:{asset.id}",
                    title=f"New asset: {label}",
                    reason=f"{asset.ip_address} first appeared in inventory.",
                    severity="info",
                    target_type="asset",
                    target_id=str(asset.id),
                    target_label=label,
                    route=_asset_route(asset.id),
                    action=_action("Open asset", _asset_route(asset.id)),
                    occurred_at=asset.first_seen,
                )
            )

    for scan in scans:
        if scan.status == "done" and scan.finished_at and scan.finished_at >= since:
            summary = scan.result_summary or {}
            created = int(summary.get("new_assets") or summary.get("assets_created") or 0)
            changed = int(summary.get("changed_assets") or summary.get("assets_updated") or 0)
            if created or changed:
                items.append(
                    _item(
                        key=f"scan-changed:{scan.id}",
                        title="Scan changed inventory",
                        reason=f"{created} new assets and {changed} updated assets.",
                        severity="info",
                        target_type="scan",
                        target_id=str(scan.id),
                        route="/scans",
                        action=_action("Open scans", "/scans"),
                        occurred_at=scan.finished_at,
                        metadata={"new_assets": created, "changed_assets": changed},
                    )
                )
    return sorted(items, key=lambda item: item["occurred_at"] or "", reverse=True)


def _attention_items(
    assets: list[Asset],
    scans: list[ScanJob],
    backup_failures: list[ConfigBackupSnapshot],
    failed_syncs: list[tuple[str, Any]],
    now: datetime,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    stale_before = now - timedelta(days=STALE_ASSET_DAYS)

    for scan in scans:
        if scan.status in {"failed", "paused"}:
            severity = "high" if scan.status == "failed" else "medium"
            items.append(
                _item(
                    key=f"scan-attention:{scan.id}",
                    title=f"Scan {scan.status}",
                    reason=f"{scan.scan_type} scan for {scan.targets} is {scan.status}.",
                    severity=severity,
                    target_type="scan",
                    target_id=str(scan.id),
                    route="/scans",
                    action=_action("Open scan history", "/scans"),
                    occurred_at=scan.finished_at or scan.started_at or scan.created_at,
                )
            )

    for asset in assets:
        if asset.status == "offline":
            label = _asset_label(asset)
            items.append(
                _item(
                    key=f"asset-offline:{asset.id}",
                    title=f"Offline asset: {label}",
                    reason=f"{asset.ip_address} is currently marked offline.",
                    severity="medium",
                    target_type="asset",
                    target_id=str(asset.id),
                    target_label=label,
                    route=_asset_route(asset.id),
                    action=_action("Review asset", _asset_route(asset.id)),
                    occurred_at=asset.last_seen,
                )
            )
        elif asset.last_seen and asset.last_seen < stale_before:
            label = _asset_label(asset)
            items.append(
                _item(
                    key=f"asset-stale:{asset.id}",
                    title=f"Stale asset: {label}",
                    reason=f"{asset.ip_address} has not been seen in more than {STALE_ASSET_DAYS} days.",
                    severity="low",
                    target_type="asset",
                    target_id=str(asset.id),
                    target_label=label,
                    route=_asset_route(asset.id),
                    action=_action("Review asset", _asset_route(asset.id)),
                    occurred_at=asset.last_seen,
                )
            )

    for snapshot in backup_failures:
        items.append(
            _item(
                key=f"backup-failed:{snapshot.id}",
                title="Config backup failed",
                reason=snapshot.error or f"{snapshot.driver} backup did not complete.",
                severity="medium",
                target_type="asset",
                target_id=str(snapshot.asset_id),
                route=_asset_route(snapshot.asset_id),
                action=_action("Open backup target", _asset_route(snapshot.asset_id)),
                occurred_at=snapshot.captured_at,
            )
        )

    for source, run in failed_syncs:
        items.append(
            _item(
                key=f"sync-failed:{source}:{run.id}",
                title=f"{source} sync failed",
                reason=run.error or "Integration sync did not complete.",
                severity="medium",
                target_type="integration",
                target_id=str(run.id),
                route="/settings",
                action=_action("Open settings", "/settings", requires_admin=True),
                occurred_at=run.finished_at or run.started_at,
            )
        )

    return sorted(items, key=lambda item: (_severity_rank(item["severity"]), item["occurred_at"] or ""), reverse=True)


def _unknown_items(assets: list[Asset], topology_links: list[TopologyLink]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for asset in assets:
        if not _asset_is_unknown(asset):
            continue
        label = _asset_label(asset)
        missing = []
        if (asset.effective_device_type or "unknown").lower() == "unknown":
            missing.append("device type")
        if not asset.vendor:
            missing.append("vendor")
        if not asset.hostname:
            missing.append("hostname")
        if _asset_has_low_confidence_ai(asset):
            missing.append("high-confidence AI classification")
        items.append(
            _item(
                key=f"asset-unknown:{asset.id}",
                title=f"Unresolved asset: {label}",
                reason=f"Missing {', '.join(missing) or 'strong identity evidence'}.",
                severity="low",
                target_type="asset",
                target_id=str(asset.id),
                target_label=label,
                route=_asset_route(asset.id),
                action=_action("Open evidence", _asset_route(asset.id)),
                occurred_at=asset.last_seen,
                metadata={"missing": missing},
            )
        )

    for link in topology_links:
        if link.suppressed or link.observed or link.confidence >= 0.6:
            continue
        items.append(
            _item(
                key=f"topology-low-confidence:{link.id}",
                title="Low-confidence topology link",
                reason=f"{link.relationship_type.replace('_', ' ')} is inferred with {round(link.confidence * 100)}% confidence.",
                severity="low",
                target_type="topology_link",
                target_id=str(link.id),
                route="/topology",
                action=_action("Review topology", "/topology"),
                occurred_at=link.last_seen,
            )
        )

    return sorted(items, key=lambda item: item["occurred_at"] or "", reverse=True)


def _risk_items(
    assets: list[Asset],
    findings: list[Finding],
    lifecycle_records: list[LifecycleRecord],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    for finding in findings:
        items.append(
            _item(
                key=f"finding-risk:{finding.id}",
                title=f"{finding.severity.title()} finding: {finding.title}",
                reason=finding.description or f"{finding.source_tool} reported an open finding.",
                severity=finding.severity,
                target_type="finding",
                target_id=str(finding.id),
                route="/findings",
                action=_action("Review finding", "/findings"),
                occurred_at=finding.last_seen,
                metadata={"asset_id": str(finding.asset_id), "cve": finding.cve},
            )
        )

    for asset in assets:
        risky_ports = sorted(_open_ports(asset) & set(HIGH_RISK_PORTS))
        for port in risky_ports[:2]:
            label = _asset_label(asset)
            items.append(
                _item(
                    key=f"port-risk:{asset.id}:{port}",
                    title=HIGH_RISK_PORTS[port],
                    reason=f"{label} has TCP/{port} open.",
                    severity="medium",
                    target_type="asset",
                    target_id=str(asset.id),
                    target_label=label,
                    route=_asset_route(asset.id),
                    action=_action("Review ports", _asset_route(asset.id)),
                    occurred_at=asset.last_seen,
                    metadata={"port": port},
                )
            )

    for record in lifecycle_records:
        if record.support_status not in {"eol", "unsupported", "expired"}:
            continue
        items.append(
            _item(
                key=f"lifecycle-risk:{record.id}",
                title=f"Unsupported lifecycle: {record.product}",
                reason=f"{record.product} {record.version or ''} is marked {record.support_status}.",
                severity="medium",
                target_type="asset",
                target_id=str(record.asset_id),
                route=_asset_route(record.asset_id),
                action=_action("Open lifecycle", _asset_route(record.asset_id)),
                occurred_at=record.observed_at,
            )
        )

    return sorted(items, key=lambda item: (_severity_rank(item["severity"]), item["occurred_at"] or ""), reverse=True)


def _recommended_actions(
    changed: list[dict[str, Any]],
    attention: list[dict[str, Any]],
    unknowns: list[dict[str, Any]],
    risk: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []

    high_risk = next((item for item in risk if item["severity"] in {"critical", "high"}), None)
    if high_risk:
        actions.append(
            _item(
                key="recommendation:review-high-risk",
                title="Review high-risk findings first",
                reason=high_risk["title"],
                severity="high",
                route=high_risk["route"],
                action=high_risk["action"],
                metadata={"source_item": high_risk["key"]},
            )
        )

    failed_scan = next((item for item in attention if item["target_type"] == "scan" and item["severity"] == "high"), None)
    if failed_scan:
        actions.append(
            _item(
                key="recommendation:repair-scan",
                title="Repair failed scan workflow",
                reason=failed_scan["reason"],
                severity="high",
                route="/scans",
                action=_action("Open scans", "/scans"),
                metadata={"source_item": failed_scan["key"]},
            )
        )

    unknown_asset = next((item for item in unknowns if item["target_type"] == "asset"), None)
    if unknown_asset:
        route = unknown_asset["route"] or "/assets"
        actions.append(
            _item(
                key="recommendation:resolve-unknown",
                title="Resolve unknown devices",
                reason=unknown_asset["reason"],
                severity="medium",
                route=route,
                action=_action("Open asset evidence", route),
                metadata={"source_item": unknown_asset["key"]},
            )
        )

    topology_unknown = next((item for item in unknowns if item["target_type"] == "topology_link"), None)
    if topology_unknown:
        actions.append(
            _item(
                key="recommendation:review-topology",
                title="Review weak topology evidence",
                reason=topology_unknown["reason"],
                severity="medium",
                route="/topology",
                action=_action("Open topology", "/topology"),
                metadata={"source_item": topology_unknown["key"]},
            )
        )

    if changed and not actions:
        actions.append(
            _item(
                key="recommendation:review-changes",
                title="Review recent inventory changes",
                reason=changed[0]["reason"],
                severity="info",
                route=changed[0]["route"] or "/assets",
                action=changed[0]["action"],
                metadata={"source_item": changed[0]["key"]},
            )
        )

    if not actions:
        actions.append(
            _item(
                key="recommendation:run-scan",
                title="Run or review a fresh scan",
                reason="No urgent work is queued; a current scan keeps inventory evidence fresh.",
                severity="info",
                route="/scans",
                action=_action("Open scans", "/scans", requires_admin=True),
            )
        )

    return actions


async def _recent_failed_syncs(db: AsyncSession) -> list[tuple[str, Any]]:
    failed: list[tuple[str, Any]] = []
    for label, model in (
        ("TP-Link Deco", TplinkDecoSyncRun),
        ("UniFi", UnifiSyncRun),
        ("pfSense", PfsenseSyncRun),
        ("Firewalla", FirewallaSyncRun),
    ):
        rows = (
            await db.execute(
                select(model)
                .where(model.status == "failed")
                .order_by(model.started_at.desc())
                .limit(2)
            )
        ).scalars().all()
        failed.extend((label, row) for row in rows)
    return failed


async def build_operator_brief(db: AsyncSession, *, window_hours: int = 24) -> dict[str, Any]:
    now = _now()
    since = now - timedelta(hours=max(1, min(window_hours, 24 * 30)))

    assets = list(
        (
            await db.execute(
                select(Asset)
                .options(
                    selectinload(Asset.ports),
                    selectinload(Asset.tags),
                    selectinload(Asset.ai_analysis),
                )
                .order_by(Asset.last_seen.desc())
            )
        )
        .scalars()
        .all()
    )
    scans = list(
        (
            await db.execute(
                select(ScanJob)
                .where(ScanJob.parent_id.is_(None))
                .order_by(ScanJob.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    findings = list(
        (
            await db.execute(
                select(Finding)
                .where(Finding.status == "open", Finding.severity.in_(["critical", "high"]))
                .order_by(Finding.last_seen.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    backup_failures = list(
        (
            await db.execute(
                select(ConfigBackupSnapshot)
                .where(ConfigBackupSnapshot.status == "failed")
                .order_by(ConfigBackupSnapshot.captured_at.desc())
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    lifecycle_records = list(
        (
            await db.execute(
                select(LifecycleRecord)
                .where(LifecycleRecord.support_status.in_(["eol", "unsupported", "expired"]))
                .order_by(LifecycleRecord.observed_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    topology_links = list(
        (
            await db.execute(
                select(TopologyLink)
                .where(TopologyLink.suppressed.is_(False))
                .order_by(TopologyLink.last_seen.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    failed_syncs = await _recent_failed_syncs(db)

    changed = _changed_items(assets, scans, since)
    attention = _attention_items(assets, scans, backup_failures, failed_syncs, now)
    unknowns = _unknown_items(assets, topology_links)
    risk = _risk_items(assets, findings, lifecycle_records)
    recommendations = _recommended_actions(changed, attention, unknowns, risk)

    sections = [
        _section("changed", "Changed", "What changed?", changed),
        _section("attention", "Needs Attention", "What needs attention?", attention),
        _section("unknowns", "Unknowns", "What is unknown?", unknowns),
        _section("risk", "Risk", "What is risky?", risk),
        _section("recommendations", "Recommended Actions", "What should I do next?", recommendations),
    ]

    return {
        "generated_at": now.isoformat(),
        "window": {
            "hours": window_hours,
            "started_at": since.isoformat(),
            "ended_at": now.isoformat(),
        },
        "summary": {
            "changed": len(changed),
            "attention": len(attention),
            "unknowns": len(unknowns),
            "risk": len(risk),
            "recommendations": len(recommendations),
        },
        "sections": sections,
    }
