from __future__ import annotations

import asyncio
from urllib.parse import urlsplit, urlunsplit
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
import anthropic
import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin
from app.audit import log_audit_event
from app.backups import get_backup_policy, list_backup_drivers, update_backup_policy
from app.db.models import Asset, User
from app.db.session import get_db
from app.exporters import build_inventory_snapshot
from app.fingerprinting.datasets import list_datasets, refresh_dataset
from app.integrations import build_home_assistant_entities, list_integration_events
from app.modules.tplink_deco import (
    audit_tplink_config_change,
    get_or_create_tplink_deco_config,
    list_recent_tplink_deco_sync_runs,
    serialize_tplink_deco_config,
    serialize_tplink_deco_sync_run,
    sync_tplink_deco_module,
    test_tplink_deco_connection,
    update_tplink_deco_config,
)
from app.modules.unifi import (
    audit_unifi_config_change,
    get_or_create_unifi_config,
    list_recent_unifi_sync_runs,
    serialize_unifi_config,
    serialize_unifi_sync_run,
    sync_unifi_module,
    test_unifi_connection,
    update_unifi_config,
)
from app.modules.pfsense import (
    audit_pfsense_config_change,
    get_or_create_pfsense_config,
    list_recent_pfsense_sync_runs,
    serialize_pfsense_config,
    serialize_pfsense_sync_run,
    sync_pfsense_module,
    test_pfsense_connection,
    update_pfsense_config,
)
from app.modules.firewalla import (
    audit_firewalla_config_change,
    get_or_create_firewalla_config,
    list_recent_firewalla_sync_runs,
    serialize_firewalla_config,
    serialize_firewalla_sync_run,
    sync_firewalla_module,
    test_firewalla_connection,
    update_firewalla_config,
)
from app.plugins import list_plugins
from app.scanner.config import ScannerConfigUpdateInput, clear_inventory, read_effective_scanner_config, update_scanner_config

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
FINGERPRINT_REFRESH_RESPONSES = {404: {"description": "Fingerprint dataset not found"}}
TPLINK_MODULE_RESPONSES = {
    400: {"description": "Module configuration is invalid"},
    502: {"description": "Module connection failed"},
}
SCANNER_CONFIG_RESPONSES = {400: {"description": "Scanner configuration is invalid"}}
RESET_INVENTORY_RESPONSES = {400: {"description": "Inventory reset confirmation text is invalid"}}


class BackupPolicyUpdateRequest(BaseModel):
    enabled: bool
    interval_minutes: int
    tag_filter: str
    retention_count: int


class ScannerConfigUpdateRequest(BaseModel):
    enabled: bool
    scheduled_scans_enabled: bool
    default_targets: str | None = None
    auto_detect_targets: bool
    default_profile: str
    interval_minutes: int
    concurrent_hosts: int
    host_chunk_size: int = 64
    top_ports_count: int = 1000
    deep_probe_timeout_seconds: int = 6
    ai_after_scan_enabled: bool = True
    ai_backend: str = "ollama"
    ai_model: str | None = None
    fingerprint_ai_backend: str = "ollama"
    ollama_base_url: str | None = None
    openai_base_url: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    passive_arp_enabled: bool = True
    passive_arp_interface: str = "auto"
    topology_default_segment_prefix_v4: int = 24
    snmp_enabled: bool = True
    snmp_version: str = "2c"
    snmp_community: str | None = None
    snmp_timeout: int = 5
    snmp_v3_username: str | None = None
    snmp_v3_auth_key: str | None = None
    snmp_v3_priv_key: str | None = None
    snmp_v3_auth_protocol: str = "sha"
    snmp_v3_priv_protocol: str = "aes"
    fingerprint_ai_enabled: bool = False
    fingerprint_ai_model: str | None = None
    fingerprint_ai_min_confidence: float = 0.75
    fingerprint_ai_prompt_suffix: str | None = None
    internet_lookup_enabled: bool = False
    internet_lookup_allowed_domains: str | None = None
    internet_lookup_budget: int = 3
    internet_lookup_timeout_seconds: int = 5


class ResetInventoryRequest(BaseModel):
    include_scan_history: bool = False
    confirm: str


class OllamaPullRequest(BaseModel):
    model: str
    base_url: str | None = None


class TplinkDecoConfigUpdateRequest(BaseModel):
    enabled: bool
    base_url: str = "http://tplinkdeco.net"
    owner_username: str | None = None
    owner_password: str | None = None
    fetch_connected_clients: bool = True
    fetch_portal_logs: bool = True
    request_timeout_seconds: int = 10
    verify_tls: bool = False


class UnifiConfigUpdateRequest(BaseModel):
    enabled: bool
    controller_url: str = "https://192.168.1.1"
    username: str | None = None
    password: str | None = None
    site_id: str = "default"
    verify_tls: bool = False
    request_timeout_seconds: int = 15
    fetch_clients: bool = True
    fetch_devices: bool = True


class PfsenseConfigUpdateRequest(BaseModel):
    enabled: bool
    base_url: str = "http://192.168.1.1"
    flavor: str = "opnsense"
    api_key: str | None = None
    api_secret: str | None = None
    fauxapi_token: str | None = None
    verify_tls: bool = False
    request_timeout_seconds: int = 15
    fetch_dhcp_leases: bool = True
    fetch_arp_table: bool = True
    fetch_interfaces: bool = True


class FirewallaConfigUpdateRequest(BaseModel):
    enabled: bool
    base_url: str = "http://firewalla.lan"
    api_token: str | None = None
    verify_tls: bool = False
    request_timeout_seconds: int = 15
    fetch_devices: bool = True
    fetch_alarms: bool = True


def _serialize_dataset(row) -> dict:
    return {
        "id": row.id,
        "key": row.key,
        "name": row.name,
        "category": row.category,
        "description": row.description,
        "upstream_url": row.upstream_url,
        "local_path": row.local_path,
        "update_mode": row.update_mode,
        "enabled": row.enabled,
        "status": row.status,
        "last_checked_at": row.last_checked_at.isoformat() if row.last_checked_at else None,
        "last_updated_at": row.last_updated_at.isoformat() if row.last_updated_at else None,
        "upstream_last_modified": row.upstream_last_modified,
        "etag": row.etag,
        "sha256": row.sha256,
        "record_count": row.record_count,
        "error": row.error,
        "notes": row.notes,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


def _serialize_scanner_config(config, effective) -> dict:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "scheduled_scans_enabled": config.scheduled_scans_enabled,
        "default_targets": config.default_targets,
        "auto_detect_targets": config.auto_detect_targets,
        "detected_targets": effective.detected_targets,
        "effective_targets": effective.effective_targets,
        "default_profile": config.default_profile,
        "interval_minutes": config.interval_minutes,
        "concurrent_hosts": config.concurrent_hosts,
        "host_chunk_size": config.host_chunk_size,
        "top_ports_count": config.top_ports_count,
        "deep_probe_timeout_seconds": config.deep_probe_timeout_seconds,
        "ai_after_scan_enabled": config.ai_after_scan_enabled,
        "ai_backend": effective.ai_backend,
        "ai_model": effective.ai_model,
        "fingerprint_ai_backend": effective.fingerprint_ai_backend,
        "ollama_base_url": effective.ollama_base_url,
        "openai_base_url": effective.openai_base_url,
        "openai_api_key": "***" if effective.openai_api_key else "",
        "anthropic_api_key": "***" if effective.anthropic_api_key else "",
        "passive_arp_enabled": config.passive_arp_enabled,
        "passive_arp_interface": config.passive_arp_interface,
        "passive_arp_effective_interface": effective.passive_arp_effective_interface,
        "passive_arp_interface_auto": effective.passive_arp_interface_auto,
        "topology_default_segment_prefix_v4": effective.topology_default_segment_prefix_v4,
        "snmp_enabled": config.snmp_enabled,
        "snmp_version": config.snmp_version,
        "snmp_community": config.snmp_community,
        "snmp_timeout": config.snmp_timeout,
        "snmp_v3_username": config.snmp_v3_username,
        "snmp_v3_auth_key": "***" if config.snmp_v3_auth_key else "",
        "snmp_v3_priv_key": "***" if config.snmp_v3_priv_key else "",
        "snmp_v3_auth_protocol": config.snmp_v3_auth_protocol,
        "snmp_v3_priv_protocol": config.snmp_v3_priv_protocol,
        "fingerprint_ai_enabled": config.fingerprint_ai_enabled,
        "fingerprint_ai_model": effective.fingerprint_ai_model,
        "fingerprint_ai_min_confidence": config.fingerprint_ai_min_confidence,
        "fingerprint_ai_prompt_suffix": config.fingerprint_ai_prompt_suffix,
        "internet_lookup_enabled": config.internet_lookup_enabled,
        "internet_lookup_allowed_domains": config.internet_lookup_allowed_domains,
        "internet_lookup_budget": config.internet_lookup_budget,
        "internet_lookup_timeout_seconds": config.internet_lookup_timeout_seconds,
        "last_scheduled_scan_at": config.last_scheduled_scan_at.isoformat() if config.last_scheduled_scan_at else None,
        "next_scheduled_scan_at": effective.next_scheduled_scan_at.isoformat() if effective.next_scheduled_scan_at else None,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


def _ollama_api_root(base_url: str) -> str:
    normalized = (base_url or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="Ollama base URL is required.")
    parsed = urlsplit(normalized)
    path = parsed.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[:-3]
    return urlunsplit((parsed.scheme, parsed.netloc, path or "", "", ""))


async def _list_ollama_models(base_url: str) -> dict:
    api_root = _ollama_api_root(base_url)
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(f"{api_root}/api/tags")
        response.raise_for_status()
    payload = response.json()
    models = [
        {
            "name": item.get("name") or item.get("model"),
            "size": item.get("size"),
            "modified_at": item.get("modified_at"),
            "family": (item.get("details") or {}).get("family"),
        }
        for item in payload.get("models", [])
        if item.get("name") or item.get("model")
    ]
    return {"base_url": base_url, "api_root": api_root, "models": models}


async def _pull_ollama_model(base_url: str, model: str) -> dict:
    api_root = _ollama_api_root(base_url)
    requested_model = model.strip()
    if not requested_model:
        raise HTTPException(status_code=400, detail="Model name is required.")
    async with httpx.AsyncClient(timeout=600) as client:
        response = await client.post(
            f"{api_root}/api/pull",
            json={"name": requested_model, "stream": False},
        )
        response.raise_for_status()
    payload = response.json()
    return {
        "base_url": base_url,
        "api_root": api_root,
        "model": requested_model,
        "status": payload.get("status", "ok"),
        "digest": payload.get("digest"),
    }


async def _test_openai_compatible_provider(*, base_url: str, api_key: str, model: str, timeout_seconds: int = 15) -> dict:
    client = AsyncOpenAI(base_url=base_url, api_key=api_key)
    async with asyncio.timeout(timeout_seconds):
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with OK"}],
            temperature=0,
            max_tokens=5,
        )
    content = response.choices[0].message.content or ""
    return {
        "ok": True,
        "model": model,
        "message": (content or "Connection OK").strip(),
    }


async def _test_anthropic_provider(*, api_key: str, model: str, timeout_seconds: int = 15) -> dict:
    client = anthropic.AsyncAnthropic(api_key=api_key)
    async with asyncio.timeout(timeout_seconds):
        response = await client.messages.create(
            model=model,
            max_tokens=5,
            messages=[{"role": "user", "content": "Reply with OK"}],
        )
    content_parts = [block.text for block in response.content if getattr(block, "type", "") == "text"]
    return {
        "ok": True,
        "model": model,
        "message": ("\n".join(content_parts) or "Connection OK").strip(),
    }


async def _test_ai_provider_connection(provider: str, effective) -> dict:
    normalized = (provider or "none").lower()
    if normalized == "none":
        return {"ok": True, "provider": "none", "message": "Rule-based fallback selected."}
    if normalized == "ollama":
        return {
            "provider": "ollama",
            **await _test_openai_compatible_provider(
                base_url=effective.ollama_base_url,
                api_key="ollama",
                model=effective.ai_model if effective.ai_backend == "ollama" else effective.fingerprint_ai_model,
            ),
        }
    if normalized == "openai":
        if not effective.openai_api_key:
            return {"ok": False, "provider": "openai", "message": "OpenAI API key is not configured."}
        return {
            "provider": "openai",
            **await _test_openai_compatible_provider(
                base_url=effective.openai_base_url,
                api_key=effective.openai_api_key,
                model=effective.ai_model if effective.ai_backend == "openai" else effective.fingerprint_ai_model,
            ),
        }
    if normalized == "anthropic":
        if not effective.anthropic_api_key:
            return {"ok": False, "provider": "anthropic", "message": "Anthropic API key is not configured."}
        return {
            "provider": "anthropic",
            **await _test_anthropic_provider(
                api_key=effective.anthropic_api_key,
                model=effective.ai_model if effective.ai_backend == "anthropic" else effective.fingerprint_ai_model,
            ),
        }
    return {"ok": False, "provider": normalized, "message": f"Unsupported AI provider '{normalized}'."}


@router.get("/backup-drivers")
async def get_backup_drivers(_: AdminUser):
    return list_backup_drivers()


@router.get("/plugins")
async def get_plugins(_: AdminUser):
    return list_plugins()


@router.get("/integration-events")
async def get_integration_events(_: AdminUser):
    return list_integration_events()


@router.get("/fingerprint-datasets")
async def get_fingerprint_datasets(
    _: AdminUser,
    db: DBSession,
):
    rows = await list_datasets(db)
    await db.commit()
    return [_serialize_dataset(row) for row in rows]


@router.post("/ai/test")
async def test_ai_configuration(
    _: AdminUser,
    db: DBSession,
):
    _, effective = await read_effective_scanner_config(db)
    try:
        analyst = await _test_ai_provider_connection(effective.ai_backend, effective)
        fingerprint = await _test_ai_provider_connection(effective.fingerprint_ai_backend, effective)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI connection test failed: {exc}") from exc
    return {
        "analyst": analyst,
        "fingerprint": fingerprint,
    }


@router.get("/ai/ollama/models")
async def get_ollama_models(
    _: AdminUser,
    db: DBSession,
    base_url: str | None = None,
):
    _, effective = await read_effective_scanner_config(db)
    resolved_base_url = (base_url or effective.ollama_base_url or "").strip()
    try:
        return await _list_ollama_models(resolved_base_url)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama model listing failed with HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama model listing failed: {exc}") from exc


@router.post("/ai/ollama/pull")
async def pull_ollama_model(
    payload: OllamaPullRequest,
    user: AdminUser,
    db: DBSession,
):
    _, effective = await read_effective_scanner_config(db)
    resolved_base_url = (payload.base_url or effective.ollama_base_url or "").strip()
    try:
        result = await _pull_ollama_model(resolved_base_url, payload.model)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama model pull failed with HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama model pull failed: {exc}") from exc
    await log_audit_event(
        db,
        action="ai.ollama_model_pull",
        user=user,
        target_type="ollama_model",
        target_id=payload.model.strip(),
        details={"base_url": resolved_base_url, "status": result["status"], "digest": result.get("digest")},
    )
    await db.commit()
    return result


@router.post("/fingerprint-datasets/{dataset_key}/refresh", responses=FINGERPRINT_REFRESH_RESPONSES)
async def refresh_fingerprint_dataset(
    dataset_key: str,
    user: AdminUser,
    db: DBSession,
):
    try:
        row = await refresh_dataset(db, dataset_key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="fingerprint.dataset.refreshed",
        user=user,
        target_type="fingerprint_dataset",
        target_id=dataset_key,
        details={"status": row.status, "record_count": row.record_count, "error": row.error},
    )
    await db.commit()
    return _serialize_dataset(row)


@router.get("/integrations/home-assistant/entities")
async def get_home_assistant_entities(
    _: AdminUser,
    db: DBSession,
):
    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.tags), selectinload(Asset.ports))
        .where(Asset.status != "unknown")
        .order_by(Asset.hostname.asc())
    )
    assets = result.scalars().all()
    return build_home_assistant_entities(assets)


@router.get("/integrations/inventory-sync")
async def get_inventory_sync_export(
    _: AdminUser,
    db: DBSession,
):
    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.tags), selectinload(Asset.ports))
        .order_by(Asset.ip_address.asc())
    )
    assets = result.scalars().all()
    return {
        "mode": "read_only_export",
        "description": "Use this normalized snapshot to sync Argus inventory into external systems.",
        "snapshot": build_inventory_snapshot(assets),
    }


@router.get("/backup-policy")
async def read_backup_policy(
    _: AdminUser,
    db: DBSession,
):
    policy = await get_backup_policy(db)
    return {
        "id": policy.id,
        "enabled": policy.enabled,
        "interval_minutes": policy.interval_minutes,
        "tag_filter": policy.tag_filter,
        "retention_count": policy.retention_count,
        "last_run_at": policy.last_run_at.isoformat() if policy.last_run_at else None,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }


@router.get("/scanner-config")
async def get_scanner_config(
    _: AdminUser,
    db: DBSession,
):
    config, effective = await read_effective_scanner_config(db)
    return _serialize_scanner_config(config, effective)


@router.get("/modules/tplink-deco")
async def get_tplink_deco_module(
    _: AdminUser,
    db: DBSession,
):
    config = await get_or_create_tplink_deco_config(db)
    runs = await list_recent_tplink_deco_sync_runs(db)
    return {
        "config": serialize_tplink_deco_config(config),
        "recent_runs": [serialize_tplink_deco_sync_run(row) for row in runs],
    }


@router.put("/modules/tplink-deco")
async def write_tplink_deco_module(
    payload: TplinkDecoConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    config = await update_tplink_deco_config(
        db,
        enabled=payload.enabled,
        base_url=payload.base_url,
        owner_username=payload.owner_username,
        owner_password=payload.owner_password,
        fetch_connected_clients=payload.fetch_connected_clients,
        fetch_portal_logs=payload.fetch_portal_logs,
        request_timeout_seconds=payload.request_timeout_seconds,
        verify_tls=payload.verify_tls,
    )
    await audit_tplink_config_change(db, user=user, config=config)
    await db.commit()
    return serialize_tplink_deco_config(config)


@router.post("/modules/tplink-deco/test", responses=TPLINK_MODULE_RESPONSES)
async def test_tplink_deco_module(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await test_tplink_deco_connection(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.tplink_deco.tested",
        user=user,
        target_type="tplink_deco_config",
        details=result,
    )
    await db.commit()
    return result


@router.post("/modules/tplink-deco/sync", responses=TPLINK_MODULE_RESPONSES)
async def run_tplink_deco_module_sync(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await sync_tplink_deco_module(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.tplink_deco.synced",
        user=user,
        target_type="tplink_deco_sync",
        target_id=str(result.get("run_id")),
        details=result,
    )
    await db.commit()
    return result


@router.get("/modules/unifi")
async def get_unifi_module(
    _: AdminUser,
    db: DBSession,
):
    config = await get_or_create_unifi_config(db)
    runs = await list_recent_unifi_sync_runs(db)
    return {
        "config": serialize_unifi_config(config),
        "recent_runs": [serialize_unifi_sync_run(row) for row in runs],
    }


@router.put("/modules/unifi")
async def write_unifi_module(
    payload: UnifiConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    config = await update_unifi_config(
        db,
        enabled=payload.enabled,
        controller_url=payload.controller_url,
        username=payload.username,
        password=payload.password,
        site_id=payload.site_id,
        verify_tls=payload.verify_tls,
        request_timeout_seconds=payload.request_timeout_seconds,
        fetch_clients=payload.fetch_clients,
        fetch_devices=payload.fetch_devices,
    )
    await audit_unifi_config_change(db, user=user, config=config)
    await db.commit()
    return serialize_unifi_config(config)


@router.post("/modules/unifi/test", responses=TPLINK_MODULE_RESPONSES)
async def test_unifi_module(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await test_unifi_connection(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.unifi.tested",
        user=user,
        target_type="unifi_config",
        details=result,
    )
    await db.commit()
    return result


@router.post("/modules/unifi/sync", responses=TPLINK_MODULE_RESPONSES)
async def run_unifi_module_sync(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await sync_unifi_module(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.unifi.synced",
        user=user,
        target_type="unifi_sync",
        target_id=str(result.get("run_id")),
        details=result,
    )
    await db.commit()
    return result


@router.get("/modules/pfsense")
async def get_pfsense_module(
    _: AdminUser,
    db: DBSession,
):
    config = await get_or_create_pfsense_config(db)
    runs = await list_recent_pfsense_sync_runs(db)
    return {
        "config": serialize_pfsense_config(config),
        "recent_runs": [serialize_pfsense_sync_run(row) for row in runs],
    }


@router.put("/modules/pfsense")
async def write_pfsense_module(
    payload: PfsenseConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    config = await update_pfsense_config(
        db,
        enabled=payload.enabled,
        base_url=payload.base_url,
        flavor=payload.flavor,
        api_key=payload.api_key,
        api_secret=payload.api_secret,
        fauxapi_token=payload.fauxapi_token,
        verify_tls=payload.verify_tls,
        request_timeout_seconds=payload.request_timeout_seconds,
        fetch_dhcp_leases=payload.fetch_dhcp_leases,
        fetch_arp_table=payload.fetch_arp_table,
        fetch_interfaces=payload.fetch_interfaces,
    )
    await audit_pfsense_config_change(db, user=user, config=config)
    await db.commit()
    return serialize_pfsense_config(config)


@router.post("/modules/pfsense/test", responses=TPLINK_MODULE_RESPONSES)
async def test_pfsense_module(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await test_pfsense_connection(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.pfsense.tested",
        user=user,
        target_type="pfsense_config",
        details=result,
    )
    await db.commit()
    return result


@router.post("/modules/pfsense/sync", responses=TPLINK_MODULE_RESPONSES)
async def run_pfsense_module_sync(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await sync_pfsense_module(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.pfsense.synced",
        user=user,
        target_type="pfsense_sync",
        target_id=str(result.get("run_id")),
        details=result,
    )
    await db.commit()
    return result


@router.get("/modules/firewalla")
async def get_firewalla_module(
    _: AdminUser,
    db: DBSession,
):
    config = await get_or_create_firewalla_config(db)
    runs = await list_recent_firewalla_sync_runs(db)
    return {
        "config": serialize_firewalla_config(config),
        "recent_runs": [serialize_firewalla_sync_run(row) for row in runs],
    }


@router.put("/modules/firewalla")
async def write_firewalla_module(
    payload: FirewallaConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    config = await update_firewalla_config(
        db,
        enabled=payload.enabled,
        base_url=payload.base_url,
        api_token=payload.api_token,
        verify_tls=payload.verify_tls,
        request_timeout_seconds=payload.request_timeout_seconds,
        fetch_devices=payload.fetch_devices,
        fetch_alarms=payload.fetch_alarms,
    )
    await audit_firewalla_config_change(db, user=user, config=config)
    await db.commit()
    return serialize_firewalla_config(config)


@router.post("/modules/firewalla/test", responses=TPLINK_MODULE_RESPONSES)
async def test_firewalla_module(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await test_firewalla_connection(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.firewalla.tested",
        user=user,
        target_type="firewalla_config",
        details=result,
    )
    await db.commit()
    return result


@router.post("/modules/firewalla/sync", responses=TPLINK_MODULE_RESPONSES)
async def run_firewalla_module_sync(
    user: AdminUser,
    db: DBSession,
):
    try:
        result = await sync_firewalla_module(db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="module.firewalla.synced",
        user=user,
        target_type="firewalla_sync",
        target_id=str(result.get("run_id")),
        details=result,
    )
    await db.commit()
    return result


@router.put("/scanner-config", responses=SCANNER_CONFIG_RESPONSES)
async def write_scanner_config(
    payload: ScannerConfigUpdateRequest,
    user: AdminUser,
    db: DBSession,
):
    try:
        config, effective = await update_scanner_config(
            db,
            ScannerConfigUpdateInput(
                enabled=payload.enabled,
                scheduled_scans_enabled=payload.scheduled_scans_enabled,
                default_targets=payload.default_targets,
                auto_detect_targets=payload.auto_detect_targets,
                default_profile=payload.default_profile,
                interval_minutes=payload.interval_minutes,
                concurrent_hosts=payload.concurrent_hosts,
                host_chunk_size=payload.host_chunk_size,
                top_ports_count=payload.top_ports_count,
                deep_probe_timeout_seconds=payload.deep_probe_timeout_seconds,
                ai_after_scan_enabled=payload.ai_after_scan_enabled,
                ai_backend=payload.ai_backend,
                ai_model=payload.ai_model,
                fingerprint_ai_backend=payload.fingerprint_ai_backend,
                ollama_base_url=payload.ollama_base_url,
                openai_base_url=payload.openai_base_url,
                openai_api_key=payload.openai_api_key,
                anthropic_api_key=payload.anthropic_api_key,
                passive_arp_enabled=payload.passive_arp_enabled,
                passive_arp_interface=payload.passive_arp_interface,
                topology_default_segment_prefix_v4=payload.topology_default_segment_prefix_v4,
                snmp_enabled=payload.snmp_enabled,
                snmp_version=payload.snmp_version,
                snmp_community=payload.snmp_community,
                snmp_timeout=payload.snmp_timeout,
                snmp_v3_username=payload.snmp_v3_username,
                snmp_v3_auth_key=payload.snmp_v3_auth_key,
                snmp_v3_priv_key=payload.snmp_v3_priv_key,
                snmp_v3_auth_protocol=payload.snmp_v3_auth_protocol,
                snmp_v3_priv_protocol=payload.snmp_v3_priv_protocol,
                fingerprint_ai_enabled=payload.fingerprint_ai_enabled,
                fingerprint_ai_model=payload.fingerprint_ai_model,
                fingerprint_ai_min_confidence=payload.fingerprint_ai_min_confidence,
                fingerprint_ai_prompt_suffix=payload.fingerprint_ai_prompt_suffix,
                internet_lookup_enabled=payload.internet_lookup_enabled,
                internet_lookup_allowed_domains=payload.internet_lookup_allowed_domains,
                internet_lookup_budget=payload.internet_lookup_budget,
                internet_lookup_timeout_seconds=payload.internet_lookup_timeout_seconds,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await log_audit_event(
        db,
        action="scanner.config.updated",
        user=user,
        target_type="scanner_config",
        target_id=str(config.id),
        details={"effective_targets": effective.effective_targets},
    )
    await db.commit()
    return _serialize_scanner_config(config, effective)


@router.post("/inventory/reset", responses=RESET_INVENTORY_RESPONSES)
async def reset_inventory(
    payload: ResetInventoryRequest,
    user: AdminUser,
    db: DBSession,
):
    if payload.confirm.strip().lower() != "reset inventory":
        raise HTTPException(status_code=400, detail="Confirmation text must be 'reset inventory'")
    result = await clear_inventory(db, include_scan_history=payload.include_scan_history, actor=user)
    await db.commit()
    return result


@router.put("/backup-policy")
async def write_backup_policy(
    payload: BackupPolicyUpdateRequest,
    _: AdminUser,
    db: DBSession,
):
    policy = await update_backup_policy(
        db,
        enabled=payload.enabled,
        interval_minutes=payload.interval_minutes,
        tag_filter=payload.tag_filter,
        retention_count=payload.retention_count,
    )
    return {
        "id": policy.id,
        "enabled": policy.enabled,
        "interval_minutes": policy.interval_minutes,
        "tag_filter": policy.tag_filter,
        "retention_count": policy.retention_count,
        "last_run_at": policy.last_run_at.isoformat() if policy.last_run_at else None,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }
