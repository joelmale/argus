"""
Asset Upsert — Scan Result → Database

Takes a HostScanResult and merges it into the database:
  - New IP → INSERT Asset + write AssetHistory("discovered")
  - Existing IP → diff old vs new → UPDATE changed fields + write AssetHistory per change
  - IP not seen in scan → mark status=offline + write AssetHistory("offline")

This is the Terraform apply pattern applied to network inventory:
compute the delta, apply only what changed, record every change.

Also handles Port upsert (open ports may appear/disappear between scans).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetAIAnalysis, AssetEvidence, AssetHistory, FingerprintHypothesis, Port, ProbeRun
from app.fingerprinting.evidence import derive_detected_device_type, extract_evidence
from app.fingerprinting.llm import synthesize_fingerprint
from app.scanner.config import get_or_create_scanner_config
from app.scanner.models import HostScanResult

log = logging.getLogger(__name__)

_AI_PERSIST_CONFIDENCE = 0.8
_PASSIVE_EVIDENCE_SOURCES = {"passive_arp", "dhcp_log", "mdns_passive"}


def _has_probe_evidence(result: HostScanResult) -> bool:
    return any(probe.success and probe.probe_type != "dns" and probe.data for probe in result.probes)


def _should_persist_os_name(result: HostScanResult) -> bool:
    if not result.os_fingerprint.os_name:
        return False
    if result.open_ports:
        return True
    if result.host.mac_address or result.reverse_hostname or _has_probe_evidence(result):
        return True
    return False


def _should_persist_ai_fields(result: HostScanResult) -> bool:
    ai = result.ai_analysis
    if ai is None or ai.device_class.value == "unknown":
        return False
    if ai.confidence >= _AI_PERSIST_CONFIDENCE:
        return True
    if _has_probe_evidence(result):
        return True
    if result.mac_vendor and result.open_ports:
        return True
    return False


async def upsert_scan_result(
    db: AsyncSession,
    result: HostScanResult,
) -> tuple[Asset, str]:
    """
    Upsert a single HostScanResult into the database.
    Returns (Asset, change_type) where change_type is one of:
    "discovered" | "updated" | "unchanged" | "online" | "offline"
    """
    ip = result.host.ip_address

    # ── Look up existing asset ────────────────────────────────────────────────
    stmt = select(Asset).where(Asset.ip_address == ip)
    existing = (await db.execute(stmt)).scalar_one_or_none()

    # ── Determine new field values ────────────────────────────────────────────
    new_hostname = result.reverse_hostname
    new_os = None
    new_vendor = result.mac_vendor
    evidence = extract_evidence(result)
    new_device_type, new_device_type_source = derive_detected_device_type(evidence)

    if _should_persist_os_name(result):
        new_os = result.os_fingerprint.os_name

    if result.ai_analysis and _should_persist_ai_fields(result):
        ai = result.ai_analysis
        if ai.os_guess:
            new_os = ai.os_guess
        if ai.vendor:
            new_vendor = ai.vendor

    now = datetime.now(timezone.utc)

    # ── New asset ─────────────────────────────────────────────────────────────
    if existing is None:
        asset = Asset(
            ip_address=ip,
            mac_address=result.host.mac_address,
            hostname=new_hostname,
            vendor=new_vendor,
            os_name=new_os,
            device_type=new_device_type,
            device_type_source=new_device_type_source,
            status="online",
            first_seen=now,
            last_seen=now,
        )
        db.add(asset)
        await db.flush()  # Get the generated ID

        await _refresh_fingerprint_snapshot(db, asset, result, evidence)
        await _upsert_ai_analysis(db, asset, result)
        await _upsert_fingerprint_hypothesis(db, asset, evidence)

        await _upsert_ports(db, asset, result)

        db.add(AssetHistory(
            asset_id=asset.id,
            change_type="discovered",
            diff={"ip_address": ip, "mac": result.host.mac_address, "discovery_method": result.host.discovery_method},
        ))

        log.info("NEW asset: %s", ip)
        return asset, "discovered"

    # ── Existing asset — compute diff ─────────────────────────────────────────
    changes: dict[str, dict] = {}

    def _check(field: str, new_val, current_val=None):
        """Record a field change if new_val is set and differs from current."""
        if new_val is None:
            return
        cur = current_val if current_val is not None else getattr(existing, field)
        if cur != new_val:
            changes[field] = {"old": cur, "new": new_val}
            setattr(existing, field, new_val)

    # Status change: offline → online
    if existing.status == "offline":
        changes["status"] = {"old": "offline", "new": "online"}
        existing.status = "online"

    _check("hostname", new_hostname)
    _check("vendor", new_vendor)
    _check("os_name", new_os)
    if not existing.device_type_override:
        _check("device_type", new_device_type)
        if new_device_type is not None:
            _check("device_type_source", new_device_type_source)

    if result.host.mac_address and not existing.mac_address:
        _check("mac_address", result.host.mac_address)

    existing.last_seen = now

    await _refresh_fingerprint_snapshot(db, existing, result, evidence)
    await _upsert_ai_analysis(db, existing, result)
    await _upsert_fingerprint_hypothesis(db, existing, evidence)

    # ── Upsert ports ──────────────────────────────────────────────────────────
    port_changes = await _upsert_ports(db, existing, result)
    changes.update(port_changes)

    if not changes:
        return existing, "unchanged"

    # Write history entries for each changed field
    for field, diff in changes.items():
        change_type = "status_change" if field == "status" else f"{field}_changed"
        db.add(AssetHistory(
            asset_id=existing.id,
            change_type=change_type,
            diff={field: diff},
        ))

    await db.flush()
    log.info("UPDATED asset %s: %s", ip, list(changes.keys()))
    return existing, "updated"


async def _refresh_fingerprint_snapshot(
    db: AsyncSession,
    asset: Asset,
    result: HostScanResult,
    evidence_items,
) -> None:
    evidence_stmt = select(AssetEvidence).where(AssetEvidence.asset_id == asset.id)
    for row in (await db.execute(evidence_stmt)).scalars().all():
        if row.source in _PASSIVE_EVIDENCE_SOURCES or row.source.startswith("passive_"):
            continue
        await db.delete(row)

    probe_stmt = select(ProbeRun).where(ProbeRun.asset_id == asset.id)
    for row in (await db.execute(probe_stmt)).scalars().all():
        await db.delete(row)

    for item in evidence_items:
        db.add(
            AssetEvidence(
                asset_id=asset.id,
                source=item.source,
                category=item.category,
                key=item.key,
                value=item.value,
                confidence=item.confidence,
                details=item.details,
                observed_at=result.scanned_at,
            )
        )

    for probe in result.probes:
        details = dict(probe.data or {})
        summary = None
        if probe.success:
            summary = details.get("title") or details.get("sys_descr") or details.get("friendly_name") or details.get("banner")
            if summary is not None:
                summary = str(summary)[:512]
        db.add(
            ProbeRun(
                asset_id=asset.id,
                probe_type=probe.probe_type,
                target_port=probe.target_port,
                success=probe.success,
                duration_ms=probe.duration_ms,
                summary=summary,
                details=details,
                raw_excerpt=probe.raw[:4000] if probe.raw else None,
                observed_at=result.scanned_at,
            )
        )


def _best_device_type_confidence(evidence_items) -> float:
    return max((item.confidence for item in evidence_items if item.category == "device_type"), default=0.0)


async def _upsert_fingerprint_hypothesis(db: AsyncSession, asset: Asset, evidence_items) -> None:
    config = await get_or_create_scanner_config(db)
    if not config.fingerprint_ai_enabled:
        return

    if len(evidence_items) < 3:
        return

    if _best_device_type_confidence(evidence_items) >= config.fingerprint_ai_min_confidence:
        return

    asset_payload = {
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "device_type": asset.effective_device_type,
    }
    evidence_payload = [
        {
            "source": item.source,
            "category": item.category,
            "key": item.key,
            "value": item.value,
            "confidence": item.confidence,
        }
        for item in evidence_items
    ]
    try:
        synthesized = await synthesize_fingerprint(
            asset=asset_payload,
            evidence=evidence_payload,
            model=config.fingerprint_ai_model or "qwen2.5:7b",
            prompt_suffix=config.fingerprint_ai_prompt_suffix,
        )
    except Exception as exc:
        log.debug("Fingerprint synthesis skipped for %s: %s", asset.ip_address, exc)
        return

    if not synthesized.get("summary"):
        return

    db.add(
        FingerprintHypothesis(
            asset_id=asset.id,
            source="ollama",
            device_type=synthesized.get("device_type"),
            vendor=synthesized.get("vendor"),
            model=synthesized.get("model"),
            os_guess=synthesized.get("os_guess"),
            confidence=float(synthesized.get("confidence", 0.0)),
            summary=synthesized["summary"],
            supporting_evidence=synthesized.get("supporting_evidence") or [],
            prompt_version=synthesized.get("prompt_version", "v1"),
            model_used=synthesized.get("model_used"),
            raw_response=synthesized.get("raw_response"),
        )
    )


async def _upsert_ports(db: AsyncSession, asset: Asset, result: HostScanResult) -> dict:
    """Upsert port records, return dict of changes."""
    changes: dict = {}

    # Get existing ports
    stmt = select(Port).where(Port.asset_id == asset.id)
    existing_ports = {
        (p.port_number, p.protocol): p
        for p in (await db.execute(stmt)).scalars().all()
    }

    new_port_keys = set()
    for port_result in result.open_ports:
        key = (port_result.port, port_result.protocol)
        new_port_keys.add(key)

        if key not in existing_ports:
            db.add(Port(
                asset_id=asset.id,
                port_number=port_result.port,
                protocol=port_result.protocol,
                service=port_result.service,
                version=port_result.version,
                state="open",
            ))
            changes[f"port_{port_result.port}/{port_result.protocol}"] = {"old": None, "new": "open"}
        else:
            # Update service/version if enriched
            p = existing_ports[key]
            if port_result.version and p.version != port_result.version:
                changes[f"port_{port_result.port}_version"] = {"old": p.version, "new": port_result.version}
                p.version = port_result.version
            if port_result.service and p.service != port_result.service:
                p.service = port_result.service

    # Mark ports not seen this scan as closed
    for key, port_obj in existing_ports.items():
        if key not in new_port_keys and port_obj.state == "open":
            port_obj.state = "closed"
            changes[f"port_{port_obj.port_number}/{port_obj.protocol}"] = {"old": "open", "new": "closed"}

    return changes


async def mark_offline(db: AsyncSession, ip_addresses: list[str]) -> int:
    """
    Mark assets not seen in a scan as offline.
    Returns count of assets marked offline.
    """
    count = 0
    offline_assets: list[Asset] = []
    for ip in ip_addresses:
        stmt = select(Asset).where(Asset.ip_address == ip, Asset.status == "online")
        asset = (await db.execute(stmt)).scalar_one_or_none()
        if asset:
            asset.status = "offline"
            db.add(AssetHistory(
                asset_id=asset.id,
                change_type="offline",
                diff={"status": {"old": "online", "new": "offline"}},
            ))
            count += 1
            offline_assets.append(asset)
    return count, offline_assets


async def _upsert_ai_analysis(db: AsyncSession, asset: Asset, result: HostScanResult) -> None:
    if result.ai_analysis is None:
        return

    stmt = select(AssetAIAnalysis).where(AssetAIAnalysis.asset_id == asset.id)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    analysis = result.ai_analysis

    if existing is None:
        db.add(
            AssetAIAnalysis(
                asset_id=asset.id,
                device_class=analysis.device_class.value,
                confidence=analysis.confidence,
                vendor=analysis.vendor,
                model=analysis.model,
                os_guess=analysis.os_guess,
                device_role=analysis.device_role,
                open_services_summary=analysis.open_services_summary,
                security_findings=[finding.model_dump() for finding in analysis.security_findings],
                investigation_notes=analysis.investigation_notes,
                suggested_tags=analysis.suggested_tags,
                ai_backend=analysis.ai_backend,
                model_used=analysis.model_used,
                agent_steps=analysis.agent_steps,
                analyzed_at=result.scanned_at,
            )
        )
        return

    existing.device_class = analysis.device_class.value
    existing.confidence = analysis.confidence
    existing.vendor = analysis.vendor
    existing.model = analysis.model
    existing.os_guess = analysis.os_guess
    existing.device_role = analysis.device_role
    existing.open_services_summary = analysis.open_services_summary
    existing.security_findings = [finding.model_dump() for finding in analysis.security_findings]
    existing.investigation_notes = analysis.investigation_notes
    existing.suggested_tags = analysis.suggested_tags
    existing.ai_backend = analysis.ai_backend
    existing.model_used = analysis.model_used
    existing.agent_steps = analysis.agent_steps
    existing.analyzed_at = result.scanned_at
