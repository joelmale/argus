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

from app.db.models import Asset, AssetAIAnalysis, AssetAutopsy, AssetEvidence, AssetHistory, FingerprintHypothesis, InternetLookupResult, Port, ProbeRun
from app.fingerprinting.evidence import derive_detected_device_type, extract_evidence
from app.fingerprinting.internet_lookup import build_lookup_query, normalize_allowed_domains, search_lookup
from app.fingerprinting.llm import synthesize_fingerprint
from app.fingerprinting.risk import refresh_risk_and_lifecycle
from app.services.identity import AssetIdentityResolver
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


def _os_fingerprint_confidence(result: HostScanResult) -> float:
    if not _should_persist_os_name(result):
        return 0.0
    accuracy = result.os_fingerprint.os_accuracy
    if accuracy is not None:
        return min(max(float(accuracy) / 100.0, 0.0), 0.95)
    return 0.70


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
    resolver = AssetIdentityResolver(db, source="scan")
    existing = await resolver.resolve_asset(
        mac=result.host.mac_address,
        ip=ip,
        hostname=result.reverse_hostname,
        create_if_missing=True,
        lookup_order=("ip", "mac", "hostname"),
    )

    new_hostname, new_os, new_vendor, evidence, new_device_type, new_device_type_source = _derive_asset_fields(result)

    now = datetime.now(timezone.utc)

    # ── New asset ─────────────────────────────────────────────────────────────
    if existing is None:
        asset = await _create_asset(
            db,
            result,
            now,
            new_hostname,
            new_vendor,
            new_os,
            new_device_type,
            new_device_type_source,
        )
        await _persist_asset_context(
            db,
            asset,
            result,
            evidence,
            new_hostname,
            new_vendor,
            new_os,
            new_device_type,
            new_device_type_source,
        )
        await _upsert_ports(db, asset, result)
        _record_discovery_history(db, asset, result)
        log.info("NEW asset: %s", ip)
        return asset, "discovered"

    # ── Existing asset — compute diff ─────────────────────────────────────────
    changes: dict[str, dict] = {}

    _apply_asset_updates(existing, result, changes, new_hostname, new_vendor, new_os, new_device_type, new_device_type_source)

    existing.last_seen = now
    existing.heartbeat_missed_count = 0
    existing.heartbeat_last_checked_at = now

    selected_device_type = existing.effective_device_type if existing.device_type_override else new_device_type
    selected_device_type_source = existing.effective_device_type_source if existing.device_type_override else new_device_type_source
    await _persist_asset_context(
        db,
        existing,
        result,
        evidence,
        new_hostname,
        new_vendor,
        new_os,
        selected_device_type,
        selected_device_type_source,
    )

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


def _derive_asset_fields(
    result: HostScanResult,
) -> tuple[str | None, str | None, str | None, list, str | None, str]:
    new_hostname = result.reverse_hostname
    new_os = result.os_fingerprint.os_name if _should_persist_os_name(result) else None
    os_confidence = _os_fingerprint_confidence(result)
    new_vendor = result.mac_vendor
    evidence = extract_evidence(result)
    new_device_type, new_device_type_source = derive_detected_device_type(evidence)

    if result.ai_analysis and _should_persist_ai_fields(result):
        ai = result.ai_analysis
        if ai.os_guess and _should_apply_ai_os_guess(ai.confidence, new_os, os_confidence):
            new_os = ai.os_guess
        if ai.vendor:
            new_vendor = ai.vendor
    return new_hostname, new_os, new_vendor, evidence, new_device_type, new_device_type_source


def _should_apply_ai_os_guess(ai_confidence: float, heuristic_os: str | None, heuristic_confidence: float) -> bool:
    if heuristic_os is None:
        return True
    return ai_confidence > heuristic_confidence


async def _create_asset(
    db: AsyncSession,
    result: HostScanResult,
    now: datetime,
    new_hostname: str | None,
    new_vendor: str | None,
    new_os: str | None,
    new_device_type: str | None,
    new_device_type_source: str,
) -> Asset:
    asset = Asset(
        ip_address=result.host.ip_address,
        mac_address=result.host.mac_address,
        hostname=new_hostname,
        vendor=new_vendor,
        os_name=new_os,
        device_type=new_device_type,
        device_type_source=new_device_type_source,
        status="online",
        heartbeat_missed_count=0,
        heartbeat_last_checked_at=now,
        avg_latency_ms=_normalize_latency_ms(result.host.response_time_ms),
        ttl_distance=_infer_ttl_distance(result.host.ttl),
        first_seen=now,
        last_seen=now,
    )
    db.add(asset)
    await db.flush()
    return asset


async def _persist_asset_context(
    db: AsyncSession,
    asset: Asset,
    result: HostScanResult,
    evidence: list,
    new_hostname: str | None,
    new_vendor: str | None,
    new_os: str | None,
    selected_device_type: str | None,
    selected_device_type_source: str,
) -> None:
    await _refresh_fingerprint_snapshot(db, asset, result, evidence)
    await _upsert_ai_analysis(db, asset, result)
    await _upsert_fingerprint_hypothesis(db, asset, evidence)
    await _upsert_internet_lookup(db, asset, evidence)
    await refresh_risk_and_lifecycle(db, asset, evidence)
    await _upsert_autopsy(
        db,
        asset,
        _build_autopsy_trace(
            asset,
            result,
            evidence,
            new_hostname,
            new_vendor,
            new_os,
            selected_device_type,
            selected_device_type_source,
        ),
    )


def _apply_asset_updates(
    existing: Asset,
    result: HostScanResult,
    changes: dict[str, dict],
    new_hostname: str | None,
    new_vendor: str | None,
    new_os: str | None,
    new_device_type: str | None,
    new_device_type_source: str,
) -> None:
    def _check(field: str, new_val, current_val=None):
        if new_val is None:
            return
        cur = current_val if current_val is not None else getattr(existing, field)
        if cur != new_val:
            changes[field] = {"old": cur, "new": new_val}
            setattr(existing, field, new_val)

    if existing.status == "offline":
        changes["status"] = {"old": "offline", "new": "online"}
        existing.status = "online"

    _check("hostname", new_hostname)
    _check("vendor", new_vendor)
    _check("os_name", new_os)
    _check("avg_latency_ms", _normalize_latency_ms(result.host.response_time_ms))
    _check("ttl_distance", _infer_ttl_distance(result.host.ttl))
    if not existing.device_type_override:
        _check("device_type", new_device_type)
        if new_device_type is not None:
            _check("device_type_source", new_device_type_source)
    if result.host.mac_address and not existing.mac_address:
        _check("mac_address", result.host.mac_address)


def _normalize_latency_ms(value: float | None) -> float | None:
    if value is None or value < 0:
        return None
    return round(float(value), 2)


def _infer_ttl_distance(ttl: int | None) -> int | None:
    if ttl is None or ttl <= 0:
        return None
    for initial_ttl in (64, 128, 255):
        if ttl <= initial_ttl:
            return max(initial_ttl - ttl, 0)
    return None


def _record_discovery_history(db: AsyncSession, asset: Asset, result: HostScanResult) -> None:
    db.add(AssetHistory(
        asset_id=asset.id,
        change_type="discovered",
        diff={
            "ip_address": asset.ip_address,
            "mac": result.host.mac_address,
            "discovery_method": result.host.discovery_method,
        },
    ))


async def _refresh_fingerprint_snapshot(
    db: AsyncSession,
    asset: Asset,
    result: HostScanResult,
    evidence_items,
) -> None:
    await _delete_existing_evidence_snapshot(db, asset)
    _store_evidence_items(db, asset, result, evidence_items)
    _store_probe_runs(db, asset, result)


async def _delete_existing_evidence_snapshot(db: AsyncSession, asset: Asset) -> None:
    evidence_stmt = select(AssetEvidence).where(AssetEvidence.asset_id == asset.id)
    for row in (await db.execute(evidence_stmt)).scalars().all():
        if row.source in _PASSIVE_EVIDENCE_SOURCES or row.source.startswith("passive_"):
            continue
        await db.delete(row)

    probe_stmt = select(ProbeRun).where(ProbeRun.asset_id == asset.id)
    for row in (await db.execute(probe_stmt)).scalars().all():
        await db.delete(row)


def _store_evidence_items(db: AsyncSession, asset: Asset, result: HostScanResult, evidence_items) -> None:
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


def _store_probe_runs(db: AsyncSession, asset: Asset, result: HostScanResult) -> None:
    for probe in result.probes:
        details = dict(probe.data or {})
        if probe.error and "error" not in details:
            details["error"] = probe.error
        db.add(
            ProbeRun(
                asset_id=asset.id,
                probe_type=probe.probe_type,
                target_port=probe.target_port,
                success=probe.success,
                duration_ms=probe.duration_ms,
                summary=_probe_run_summary(details, probe.success),
                details=details,
                raw_excerpt=probe.raw[:4000] if probe.raw else None,
                observed_at=result.scanned_at,
            )
        )


def _probe_run_summary(details: dict, probe_success: bool) -> str | None:
    if not probe_success:
        error = details.get("error")
        return str(error)[:512] if error is not None else None
    summary = details.get("title") or details.get("sys_descr") or details.get("friendly_name") or details.get("banner")
    return str(summary)[:512] if summary is not None else None


def _best_device_type_confidence(evidence_items) -> float:
    return max((item.confidence for item in evidence_items if item.category == "device_type"), default=0.0)


def _build_device_type_candidate_trace(evidence_items) -> list[dict]:
    candidates: dict[str, dict] = {}
    for item in evidence_items:
        if item.category != "device_type":
            continue
        candidate = candidates.setdefault(
            item.value,
            {
                "value": item.value,
                "total_score": 0.0,
                "max_confidence": 0.0,
                "sources": set(),
                "supporting_evidence": [],
            },
        )
        candidate["total_score"] += float(item.confidence)
        candidate["max_confidence"] = max(candidate["max_confidence"], float(item.confidence))
        candidate["sources"].add(item.source)
        candidate["supporting_evidence"].append(
            {
                "source": item.source,
                "key": item.key,
                "value": item.value,
                "confidence": item.confidence,
                "details": item.details,
            }
        )

    ranked: list[dict] = []
    for candidate in candidates.values():
        sources = sorted(candidate["sources"])
        accepted = candidate["max_confidence"] >= 0.8 or (
            candidate["max_confidence"] >= 0.65
            and candidate["total_score"] >= 1.3
            and len(sources) >= 2
        )
        ranked.append(
            {
                "value": candidate["value"],
                "total_score": round(candidate["total_score"], 3),
                "max_confidence": round(candidate["max_confidence"], 3),
                "distinct_sources": len(sources),
                "sources": sources,
                "accepted": accepted,
                "supporting_evidence": candidate["supporting_evidence"][:8],
            }
        )
    ranked.sort(key=lambda item: (item["accepted"], item["total_score"], item["max_confidence"]), reverse=True)
    return ranked


def _build_autopsy_trace(
    asset: Asset,
    result: HostScanResult,
    evidence_items,
    new_hostname: str | None,
    new_vendor: str | None,
    new_os: str | None,
    selected_device_type: str | None,
    selected_device_type_source: str,
) -> dict:
    top_evidence = _top_evidence_snapshot(evidence_items)
    return {
        "asset_identity": {
            "ip_address": asset.ip_address,
            "hostname": new_hostname or asset.hostname,
            "mac_address": result.host.mac_address or asset.mac_address,
        },
        "scan_context": {
            "scanned_at": result.scanned_at.isoformat(),
            "scan_profile": result.scan_profile.value,
            "scan_duration_ms": result.scan_duration_ms,
        },
        "pipeline": _build_autopsy_pipeline(
            asset,
            result,
            evidence_items,
            top_evidence,
            new_hostname,
            new_vendor,
            new_os,
            selected_device_type,
            selected_device_type_source,
        ),
        "weak_points": _autopsy_weak_points(result, selected_device_type),
    }


def _autopsy_weak_points(result: HostScanResult, selected_device_type: str | None) -> list[str]:
    weak_points: list[str] = []
    if not result.open_ports:
        weak_points.append("No open ports were confirmed during this scan.")
    if not result.host.mac_address:
        weak_points.append("No MAC address was captured, so vendor recognition had less evidence.")
    if not any(probe.success for probe in result.probes):
        weak_points.append("No deep probes succeeded, so banner and protocol-specific evidence was limited.")
    if selected_device_type is None:
        weak_points.append("No device type candidate crossed the acceptance threshold.")
    if result.ai_analysis is None:
        weak_points.append("No AI investigation was attached to this host result.")
    elif result.ai_analysis.device_class.value == "unknown":
        weak_points.append("AI investigation ran but did not produce a confident device class.")
    return weak_points


def _top_evidence_snapshot(evidence_items) -> list[dict]:
    return [
        {
            "source": item.source,
            "category": item.category,
            "key": item.key,
            "value": item.value,
            "confidence": item.confidence,
            "details": item.details,
        }
        for item in sorted(evidence_items, key=lambda row: row.confidence, reverse=True)[:12]
    ]


def _build_autopsy_pipeline(
    asset: Asset,
    result: HostScanResult,
    evidence_items,
    top_evidence: list[dict],
    new_hostname: str | None,
    new_vendor: str | None,
    new_os: str | None,
    selected_device_type: str | None,
    selected_device_type_source: str,
) -> list[dict]:
    return [
        _discovery_stage_trace(result),
        _port_scan_stage_trace(result),
        _deep_probe_stage_trace(result),
        _evidence_stage_trace(evidence_items, top_evidence),
        _classification_stage_trace(evidence_items, selected_device_type, selected_device_type_source),
        _ai_stage_trace(result),
        _persistence_stage_trace(asset, new_hostname, new_vendor, new_os),
    ]


def _discovery_stage_trace(result: HostScanResult) -> dict:
    return {
        "stage": "discovery",
        "status": "ok",
        "summary": f"Host discovered via {result.host.discovery_method}.",
        "outputs": {
            "discovery_method": result.host.discovery_method,
            "response_time_ms": result.host.response_time_ms,
            "ttl": result.host.ttl,
            "nmap_hostname": result.host.nmap_hostname,
        },
    }


def _port_scan_stage_trace(result: HostScanResult) -> dict:
    return {
        "stage": "port_scan",
        "status": "ok" if result.ports else "limited",
        "summary": f"{len(result.open_ports)} open ports identified.",
        "outputs": {
            "open_port_count": len(result.open_ports),
            "ports": [
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "service": port.service,
                    "product": port.product,
                    "version": port.version,
                    "cpe": port.cpe,
                }
                for port in result.open_ports[:20]
            ],
            "os_fingerprint": result.os_fingerprint.model_dump(),
        },
    }


def _deep_probe_stage_trace(result: HostScanResult) -> dict:
    successful_probes = [probe for probe in result.probes if probe.success]
    failed_probes = [probe for probe in result.probes if not probe.success]
    return {
        "stage": "deep_probes",
        "status": "ok" if successful_probes else "limited",
        "summary": f"{len(successful_probes)} of {len(result.probes)} probes succeeded.",
        "outputs": {
            "successful_probes": [
                {
                    "probe_type": probe.probe_type,
                    "target_port": probe.target_port,
                    "details": probe.data or {},
                }
                for probe in successful_probes[:10]
            ],
            "failed_probes": [
                {
                    "probe_type": probe.probe_type,
                    "target_port": probe.target_port,
                    "error": probe.error,
                }
                for probe in failed_probes[:10]
            ],
        },
    }


def _evidence_stage_trace(evidence_items, top_evidence: list[dict]) -> dict:
    return {
        "stage": "evidence_normalization",
        "status": "ok",
        "summary": f"{len(evidence_items)} evidence items normalized.",
        "outputs": {
            "evidence_count": len(evidence_items),
            "top_evidence": top_evidence,
        },
    }


def _classification_stage_trace(evidence_items, selected_device_type: str | None, selected_device_type_source: str) -> dict:
    return {
        "stage": "classification",
        "status": "ok" if selected_device_type else "limited",
        "summary": f"Resolved device type to {selected_device_type or 'unknown'} via {selected_device_type_source}.",
        "outputs": {
            "device_type_candidates": _build_device_type_candidate_trace(evidence_items),
            "selected_device_type": selected_device_type,
            "selected_device_type_source": selected_device_type_source,
        },
    }


def _ai_stage_trace(result: HostScanResult) -> dict:
    if result.ai_analysis is None:
        return {
            "stage": "ai_investigation",
            "status": "skipped",
            "summary": "No AI investigation data was present.",
            "outputs": {},
        }
    return {
        "stage": "ai_investigation",
        "status": "ok",
        "summary": f"AI classified the asset as {result.ai_analysis.device_class.value} at {result.ai_analysis.confidence:.0%} confidence.",
        "outputs": result.ai_analysis.model_dump(),
    }


def _persistence_stage_trace(asset: Asset, new_hostname: str | None, new_vendor: str | None, new_os: str | None) -> dict:
    return {
        "stage": "persistence",
        "status": "ok",
        "summary": "Applied precedence rules and persisted final fields.",
        "outputs": {
            "precedence": [
                "manual override",
                "high-confidence AI/probe classification",
                "rule-based classification",
                "unknown",
            ],
            "manual_override_present": bool(asset.device_type_override),
            "final_fields": {
                "hostname": new_hostname,
                "vendor": new_vendor,
                "os_name": new_os,
                "device_type": asset.effective_device_type,
                "device_type_source": asset.effective_device_type_source,
            },
        },
    }


async def _upsert_autopsy(db: AsyncSession, asset: Asset, trace: dict) -> None:
    stmt = select(AssetAutopsy).where(AssetAutopsy.asset_id == asset.id)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is None:
        db.add(AssetAutopsy(asset_id=asset.id, trace=trace))
        return
    existing.trace = trace


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
            backend=config.fingerprint_ai_backend,
            model=config.fingerprint_ai_model or "qwen2.5:7b",
            prompt_suffix=config.fingerprint_ai_prompt_suffix,
            base_url=config.ollama_base_url if config.fingerprint_ai_backend == "ollama" else config.openai_base_url,
            api_key=(
                config.anthropic_api_key
                if config.fingerprint_ai_backend == "anthropic"
                else ("ollama" if config.fingerprint_ai_backend == "ollama" else config.openai_api_key)
            ),
        )
    except Exception as exc:
        log.debug("Fingerprint synthesis skipped for %s: %s", asset.ip_address, exc)
        return

    if not synthesized.get("summary"):
        return

    db.add(
        FingerprintHypothesis(
            asset_id=asset.id,
            source=config.fingerprint_ai_backend,
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


async def _upsert_internet_lookup(db: AsyncSession, asset: Asset, evidence_items) -> None:
    config = await get_or_create_scanner_config(db)
    if not config.internet_lookup_enabled:
        return
    if _best_device_type_confidence(evidence_items) >= config.fingerprint_ai_min_confidence:
        return

    query = build_lookup_query(
        {
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "vendor": asset.vendor,
            "device_type": asset.effective_device_type,
        },
        [
            {
                "source": item.source,
                "category": item.category,
                "key": item.key,
                "value": item.value,
                "confidence": item.confidence,
            }
            for item in evidence_items
        ],
    )
    allowed_domains = normalize_allowed_domains(config.internet_lookup_allowed_domains)
    if not query or not allowed_domains:
        return

    try:
        results = await search_lookup(
            query,
            allowed_domains=allowed_domains,
            timeout_seconds=config.internet_lookup_timeout_seconds,
            budget=config.internet_lookup_budget,
        )
    except Exception as exc:
        log.debug("Internet lookup skipped for %s: %s", asset.ip_address, exc)
        return

    for result in results:
        db.add(
            InternetLookupResult(
                asset_id=asset.id,
                query=query,
                domain=result["domain"],
                url=result["url"],
                title=result["title"],
                snippet=result.get("snippet"),
                confidence=0.58,
            )
        )
        db.add(
            FingerprintHypothesis(
                asset_id=asset.id,
                source="internet_lookup",
                confidence=0.58,
                summary=f"Matched external reference '{result['title']}' on {result['domain']}. {result.get('snippet') or ''}".strip(),
                supporting_evidence=[query, result["title"]],
                prompt_version="web-v1",
                model_used=result["domain"],
                raw_response=result["url"],
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
        _upsert_single_port(db, asset, existing_ports, changes, key, port_result)

    # Mark ports not seen this scan as closed
    for key, port_obj in existing_ports.items():
        if key not in new_port_keys and port_obj.state == "open":
            port_obj.state = "closed"
            changes[f"port_{port_obj.port_number}/{port_obj.protocol}"] = {"old": "open", "new": "closed"}

    return changes


def _upsert_single_port(
    db: AsyncSession,
    asset: Asset,
    existing_ports: dict[tuple[int, str], Port],
    changes: dict,
    key: tuple[int, str],
    port_result,
) -> None:
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
        return

    existing_port = existing_ports[key]
    if port_result.version and existing_port.version != port_result.version:
        changes[f"port_{port_result.port}_version"] = {"old": existing_port.version, "new": port_result.version}
        existing_port.version = port_result.version
    if port_result.service and existing_port.service != port_result.service:
        existing_port.service = port_result.service


async def mark_offline(db: AsyncSession, ip_addresses: list[str]) -> tuple[int, list[Asset]]:
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
