from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.db.models import Asset, AssetAIAnalysis, Port, ProbeRun

SUPPORTED_ASSET_INCLUDES = {"ports", "tags", "ai", "probe_runs"}


class AssetTagSummary(BaseModel):
    tag: str


class AssetPortSummary(BaseModel):
    id: int
    port_number: int
    protocol: str
    service: str | None
    version: str | None
    state: str


class AssetAiSummary(BaseModel):
    device_class: str
    confidence: float
    vendor: str | None
    model: str | None
    os_guess: str | None
    device_role: str | None
    open_services_summary: list[Any]
    security_findings: list[Any]
    investigation_notes: str
    suggested_tags: list[Any]
    ai_backend: str
    model_used: str | None
    agent_steps: int
    analyzed_at: str


class AssetNoteSummary(BaseModel):
    id: int
    content: str
    created_at: str
    updated_at: str
    user: dict[str, str] | None


class AssetEvidenceResponse(BaseModel):
    id: int
    source: str
    category: str
    key: str
    value: str
    confidence: float
    details: dict[str, Any] | None
    observed_at: str


class ProbeRunResponse(BaseModel):
    id: int
    probe_type: str
    target_port: int | None
    success: bool
    duration_ms: float | None
    summary: str | None
    details: dict[str, Any] | None
    raw_excerpt: str | None
    observed_at: str


class PassiveObservationResponse(BaseModel):
    id: int
    source: str
    event_type: str
    summary: str
    details: dict[str, Any] | None
    observed_at: str


class FingerprintHypothesisResponse(BaseModel):
    id: int
    source: str
    device_type: str | None
    vendor: str | None
    model: str | None
    os_guess: str | None
    confidence: float
    summary: str
    supporting_evidence: list[Any]
    prompt_version: str
    model_used: str | None
    raw_response: str | None
    created_at: str


class InternetLookupResponse(BaseModel):
    id: int
    query: str
    domain: str
    url: str
    title: str
    snippet: str | None
    confidence: float
    looked_up_at: str


class LifecycleRecordResponse(BaseModel):
    id: int
    product: str
    version: str | None
    support_status: str
    eol_date: str | None
    reference: str | None
    details: dict[str, Any] | None
    observed_at: str


class AssetAutopsyResponse(BaseModel):
    id: int
    trace: dict[str, Any]
    created_at: str
    updated_at: str


class AssetSummary(BaseModel):
    id: str
    ip_address: str
    mac_address: str | None
    hostname: str | None
    vendor: str | None
    os_name: str | None
    os_version: str | None
    device_type: str
    device_type_source: str
    device_type_override: str | None
    status: str
    heartbeat_missed_count: int
    heartbeat_last_checked_at: str | None
    first_seen: str
    last_seen: str
    open_ports_count: int
    ports: list[AssetPortSummary] | None = None
    tags: list[AssetTagSummary] | None = None
    ai_analysis: AssetAiSummary | None = None
    probe_runs: list[ProbeRunResponse] | None = None


class AssetDetail(AssetSummary):
    notes: str | None
    custom_fields: dict[str, Any] | None
    ports: list[AssetPortSummary]
    tags: list[AssetTagSummary]
    note_entries: list[AssetNoteSummary]
    evidence: list[AssetEvidenceResponse]
    probe_runs: list[ProbeRunResponse]
    observations: list[PassiveObservationResponse]
    fingerprint_hypotheses: list[FingerprintHypothesisResponse]
    internet_lookup_results: list[InternetLookupResponse]
    lifecycle_records: list[LifecycleRecordResponse]
    autopsy: AssetAutopsyResponse | None


class AssetStats(BaseModel):
    total: int
    online: int
    offline: int
    unknown: int
    new_today: int


def serialize_ai_analysis(ai: AssetAIAnalysis | None) -> dict | None:
    if ai is None:
        return None
    return {
        "device_class": ai.device_class,
        "confidence": ai.confidence,
        "vendor": ai.vendor,
        "model": ai.model,
        "os_guess": ai.os_guess,
        "device_role": ai.device_role,
        "open_services_summary": ai.open_services_summary or [],
        "security_findings": ai.security_findings or [],
        "investigation_notes": ai.investigation_notes or "",
        "suggested_tags": ai.suggested_tags or [],
        "ai_backend": ai.ai_backend,
        "model_used": ai.model_used,
        "agent_steps": ai.agent_steps,
        "analyzed_at": ai.analyzed_at.isoformat(),
    }


def serialize_port(port: Port) -> dict:
    return {
        "id": port.id,
        "port_number": port.port_number,
        "protocol": port.protocol,
        "service": port.service,
        "version": port.version,
        "state": port.state,
    }


def serialize_probe_run(row: ProbeRun) -> dict:
    return {
        "id": row.id,
        "probe_type": row.probe_type,
        "target_port": row.target_port,
        "success": row.success,
        "duration_ms": row.duration_ms,
        "summary": row.summary,
        "details": row.details,
        "raw_excerpt": row.raw_excerpt,
        "observed_at": row.observed_at.isoformat(),
    }


def serialize_asset_summary(
    asset: Asset,
    *,
    includes: set[str] | None = None,
    open_ports_count: int | None = None,
) -> dict:
    requested = includes or set()
    return {
        "id": str(asset.id),
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address,
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "device_type": asset.effective_device_type,
        "device_type_source": asset.effective_device_type_source,
        "device_type_override": asset.device_type_override,
        "status": asset.status,
        "heartbeat_missed_count": asset.heartbeat_missed_count,
        "heartbeat_last_checked_at": asset.heartbeat_last_checked_at.isoformat() if asset.heartbeat_last_checked_at else None,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "open_ports_count": open_ports_count if open_ports_count is not None else sum(1 for port in asset.ports if port.state == "open"),
        "ports": [serialize_port(port) for port in asset.ports] if "ports" in requested else None,
        "tags": [{"tag": tag.tag} for tag in asset.tags] if "tags" in requested else None,
        "ai_analysis": serialize_ai_analysis(asset.ai_analysis) if "ai" in requested else None,
        "probe_runs": [serialize_probe_run(row) for row in asset.probe_runs] if "probe_runs" in requested else None,
    }


def serialize_asset(asset: Asset) -> dict:
    return {
        "id": str(asset.id),
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address,
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "device_type": asset.effective_device_type,
        "device_type_source": asset.effective_device_type_source,
        "device_type_override": asset.device_type_override,
        "status": asset.status,
        "heartbeat_missed_count": asset.heartbeat_missed_count,
        "heartbeat_last_checked_at": asset.heartbeat_last_checked_at.isoformat() if asset.heartbeat_last_checked_at else None,
        "notes": asset.notes,
        "custom_fields": asset.custom_fields,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "open_ports_count": sum(1 for port in asset.ports if port.state == "open"),
        "ports": [serialize_port(port) for port in asset.ports],
        "tags": [{"tag": tag.tag} for tag in asset.tags],
        "note_entries": [
            {
                "id": row.id,
                "content": row.content,
                "created_at": row.created_at.isoformat(),
                "updated_at": row.updated_at.isoformat(),
                "user": (
                    {
                        "id": str(row.user.id),
                        "username": row.user.username,
                    }
                    if row.user
                    else None
                ),
            }
            for row in asset.note_entries
        ],
        "ai_analysis": serialize_ai_analysis(asset.ai_analysis),
        "evidence": [
            {
                "id": row.id,
                "source": row.source,
                "category": row.category,
                "key": row.key,
                "value": row.value,
                "confidence": row.confidence,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in asset.evidence
        ],
        "probe_runs": [serialize_probe_run(row) for row in asset.probe_runs],
        "observations": [
            {
                "id": row.id,
                "source": row.source,
                "event_type": row.event_type,
                "summary": row.summary,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in asset.observations
        ],
        "fingerprint_hypotheses": [
            {
                "id": row.id,
                "source": row.source,
                "device_type": row.device_type,
                "vendor": row.vendor,
                "model": row.model,
                "os_guess": row.os_guess,
                "confidence": row.confidence,
                "summary": row.summary,
                "supporting_evidence": row.supporting_evidence or [],
                "prompt_version": row.prompt_version,
                "model_used": row.model_used,
                "raw_response": row.raw_response,
                "created_at": row.created_at.isoformat(),
            }
            for row in asset.fingerprint_hypotheses
        ],
        "internet_lookup_results": [
            {
                "id": row.id,
                "query": row.query,
                "domain": row.domain,
                "url": row.url,
                "title": row.title,
                "snippet": row.snippet,
                "confidence": row.confidence,
                "looked_up_at": row.looked_up_at.isoformat(),
            }
            for row in asset.internet_lookup_results
        ],
        "lifecycle_records": [
            {
                "id": row.id,
                "product": row.product,
                "version": row.version,
                "support_status": row.support_status,
                "eol_date": row.eol_date,
                "reference": row.reference,
                "details": row.details,
                "observed_at": row.observed_at.isoformat(),
            }
            for row in asset.lifecycle_records
        ],
        "autopsy": {
            "id": asset.autopsy.id,
            "trace": asset.autopsy.trace,
            "created_at": asset.autopsy.created_at.isoformat(),
            "updated_at": asset.autopsy.updated_at.isoformat(),
        } if asset.autopsy else None,
    }
