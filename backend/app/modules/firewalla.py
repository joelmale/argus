from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_audit_event
from app.db.models import Asset, AssetTag, Finding, FirewallaConfig, FirewallaSyncRun, User
from app.fingerprinting.passive import record_passive_observation
from app.services.identity import AssetIdentityResolver


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_base_url(value: str | None, default: str = "http://firewalla.lan") -> str:
    raw = (value or default).strip()
    if not raw:
        raw = default
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    return raw.rstrip("/")


_ALARM_SEVERITY_MAP: dict[str, str] = {
    "ALARM_LARGE_UPLOAD": "medium",
    "ALARM_NEW_DEVICE": "info",
    "ALARM_DEVICE_BACK_ONLINE": "info",
    "ALARM_ABNORMAL_BANDWIDTH_USAGE": "medium",
    "ALARM_VULNERABILITY": "high",
    "ALARM_UPNP": "medium",
    "ALARM_OPENPORT": "medium",
    "ALARM_INTEL": "high",
}

_DTYPE_MAP: dict[str, str] = {
    "Phone": "iot_device",
    "Computer": "workstation",
    "Tablet": "iot_device",
    "TV": "smart_tv",
    "Game Console": "game_console",
    "Router": "router",
    "NAS": "nas",
    "IP Camera": "ip_camera",
    "Printer": "printer",
    "Speaker": "iot_device",
    "Switch": "switch",
}


@dataclass(slots=True)
class FirewallaDeviceRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    device_name: str | None
    device_type: str | None
    vendor: str | None
    online: bool
    raw: dict


@dataclass(slots=True)
class FirewallaAlarmRecord:
    alarm_id: str
    alarm_type: str
    severity: str
    title: str
    device_mac: str | None
    description: str | None


def normalize_firewalla_device(record: dict[str, Any]) -> FirewallaDeviceRecord:
    return FirewallaDeviceRecord(
        mac=record.get("mac"),
        ip=record.get("ipv4") or record.get("ip"),
        hostname=record.get("bname") or record.get("name"),
        device_name=record.get("name"),
        device_type=record.get("dtype"),
        vendor=record.get("macVendor"),
        online=bool(record.get("online", True)),
        raw=record,
    )


def normalize_firewalla_alarm(record: dict[str, Any]) -> FirewallaAlarmRecord:
    alarm_type = record.get("type", "")
    severity = _ALARM_SEVERITY_MAP.get(alarm_type, "info")
    title = record.get("message") or alarm_type
    device_mac = (record.get("device") or {}).get("mac") or record.get("p", {}).get("mac")
    return FirewallaAlarmRecord(
        alarm_id=str(record.get("aid") or record.get("id", "")),
        alarm_type=alarm_type,
        severity=severity,
        title=title,
        device_mac=device_mac,
        description=record.get("info"),
    )


class FirewallaApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        timeout_seconds: int = 15,
        verify_tls: bool = False,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=max(5, timeout_seconds),
            verify=verify_tls,
            headers={"Authorization": f"Bearer {api_token}"},
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "FirewallaApiClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def test(self) -> dict[str, Any]:
        response = await self._client.get("/v1/box")
        response.raise_for_status()
        return response.json()

    async def fetch_devices(self) -> list[FirewallaDeviceRecord]:
        response = await self._client.get("/v1/hosts")
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return [normalize_firewalla_device(r) for r in data if isinstance(r, dict)]
        return []

    async def fetch_alarms(self) -> list[FirewallaAlarmRecord]:
        response = await self._client.get("/v1/alarms", params={"state": "active"})
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return [normalize_firewalla_alarm(r) for r in data if isinstance(r, dict)]
        return []


async def get_or_create_firewalla_config(db: AsyncSession) -> FirewallaConfig:
    config = (await db.execute(select(FirewallaConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config
    config = FirewallaConfig()
    db.add(config)
    await db.flush()
    return config


def serialize_firewalla_config(config: FirewallaConfig) -> dict[str, Any]:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "base_url": config.base_url,
        "api_token": "****" if config.api_token else None,
        "verify_tls": config.verify_tls,
        "request_timeout_seconds": config.request_timeout_seconds,
        "fetch_devices": config.fetch_devices,
        "fetch_alarms": config.fetch_alarms,
        "last_tested_at": config.last_tested_at.isoformat() if config.last_tested_at else None,
        "last_sync_at": config.last_sync_at.isoformat() if config.last_sync_at else None,
        "last_status": config.last_status,
        "last_error": config.last_error,
        "last_device_count": config.last_device_count,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


def serialize_firewalla_sync_run(run: FirewallaSyncRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "status": run.status,
        "device_count": run.device_count,
        "alarm_count": run.alarm_count,
        "error": run.error,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


async def list_recent_firewalla_sync_runs(db: AsyncSession, limit: int = 5) -> list[FirewallaSyncRun]:
    result = await db.execute(select(FirewallaSyncRun).order_by(desc(FirewallaSyncRun.started_at)).limit(limit))
    return list(result.scalars().all())


async def update_firewalla_config(
    db: AsyncSession,
    *,
    enabled: bool,
    base_url: str,
    api_token: str | None,
    verify_tls: bool,
    request_timeout_seconds: int,
    fetch_devices: bool,
    fetch_alarms: bool,
) -> FirewallaConfig:
    config = await get_or_create_firewalla_config(db)
    config.enabled = enabled
    config.base_url = _normalize_base_url(base_url)
    config.api_token = (api_token or "").strip() or None
    config.verify_tls = verify_tls
    config.request_timeout_seconds = max(5, request_timeout_seconds)
    config.fetch_devices = fetch_devices
    config.fetch_alarms = fetch_alarms
    await db.flush()
    return config


async def _existing_asset_tags(db: AsyncSession, asset: Asset) -> set[str]:
    result = await db.execute(select(AssetTag).where(AssetTag.asset_id == asset.id))
    return {tag.tag for tag in result.scalars().all()}


def _ensure_asset_tag(db: AsyncSession, asset: Asset, tag: str, tag_names: set[str]) -> None:
    if tag in tag_names:
        return
    db.add(AssetTag(asset_id=asset.id, tag=tag))
    tag_names.add(tag)


def _merge_custom_fields(
    custom_fields: dict[str, Any] | None,
    key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(custom_fields or {})
    merged[key] = payload
    return merged


async def _resolve_asset(db: AsyncSession, *, mac: str | None, ip: str | None, hostname: str | None) -> Asset | None:
    resolver = AssetIdentityResolver(db, source="firewalla")
    return await resolver.resolve_asset(mac=mac, ip=ip, hostname=hostname, lookup_order=("mac", "ip", "hostname"))


async def _enrich_asset_from_firewalla_device(db: AsyncSession, asset: Asset, device: FirewallaDeviceRecord) -> None:
    if device.mac and not asset.mac_address:
        asset.mac_address = device.mac
    hostname = device.hostname or device.device_name
    if hostname and not asset.hostname:
        asset.hostname = hostname
    if device.vendor and not asset.vendor:
        asset.vendor = device.vendor
    asset.status = "online"
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "firewalla_device",
        {"device_type": device.device_type, "online": device.online},
    )

    if device.device_type:
        mapped_type = _DTYPE_MAP.get(device.device_type)
        if mapped_type and (asset.device_type is None or asset.device_type == "unknown"):
            asset.device_type = mapped_type

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "firewalla", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="firewalla",
        event_type="device_seen",
        summary=f"Firewalla observed {hostname or device.ip or device.mac or asset.ip_address}",
        details={
            "ip": device.ip or asset.ip_address,
            "mac": device.mac or asset.mac_address,
            "hostname": hostname,
            "device_type": device.device_type,
            "vendor": device.vendor,
            "online": device.online,
        },
    )


async def _ingest_firewalla_alarm(db: AsyncSession, alarm: FirewallaAlarmRecord) -> bool:
    """Upsert a Firewalla alarm as a Finding. Returns True if alarm was ingested."""
    # Resolve asset by device_mac
    asset: Asset | None = None
    if alarm.device_mac:
        result = await db.execute(
            select(Asset).where(func.lower(Asset.mac_address) == alarm.device_mac.lower()).limit(1)
        )
        asset = result.scalar_one_or_none()
    if asset is None:
        return False

    # Look up existing Finding
    if alarm.alarm_id:
        result = await db.execute(
            select(Finding).where(
                Finding.source_tool == "firewalla",
                Finding.external_id == alarm.alarm_id,
                Finding.asset_id == asset.id,
            ).limit(1)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.last_seen = _utcnow()
            await db.flush()
            return True

    finding = Finding(
        asset_id=asset.id,
        source_tool="firewalla",
        external_id=alarm.alarm_id or None,
        title=alarm.title or alarm.alarm_type,
        description=alarm.description,
        severity=alarm.severity,
        status="open",
    )
    db.add(finding)
    await db.flush()
    return True


async def test_firewalla_connection(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_firewalla_config(db)
    if not config.api_token:
        raise ValueError("Set the Firewalla API token before testing the module.")

    async with FirewallaApiClient(
        base_url=config.base_url,
        api_token=config.api_token,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=config.verify_tls,
    ) as client:
        box_info = await client.test()
        devices: list[FirewallaDeviceRecord] = []
        if config.fetch_devices:
            devices = await client.fetch_devices()

    config.last_tested_at = _utcnow()
    config.last_status = "healthy"
    config.last_error = None
    config.last_device_count = len(devices)
    await db.flush()
    return {
        "status": "healthy",
        "device_count": len(devices),
        "box_name": (box_info or {}).get("name"),
    }


async def sync_firewalla_module(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_firewalla_config(db)
    if not config.enabled:
        raise ValueError("Enable the Firewalla module before syncing.")
    if not config.api_token:
        raise ValueError("Set the Firewalla API token before syncing.")

    run = FirewallaSyncRun(status="running", started_at=_utcnow())
    db.add(run)
    await db.flush()

    try:
        async with FirewallaApiClient(
            base_url=config.base_url,
            api_token=config.api_token,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
        ) as client:
            devices: list[FirewallaDeviceRecord] = []
            alarms: list[FirewallaAlarmRecord] = []
            if config.fetch_devices:
                devices = await client.fetch_devices()
            if config.fetch_alarms:
                alarms = await client.fetch_alarms()

        for device in devices:
            asset = await _resolve_asset(db, mac=device.mac, ip=device.ip, hostname=device.hostname or device.device_name)
            if asset is None:
                continue
            await _enrich_asset_from_firewalla_device(db, asset, device)

        alarm_ingested = 0
        for alarm in alarms:
            ok = await _ingest_firewalla_alarm(db, alarm)
            if ok:
                alarm_ingested += 1

        run.status = "done"
        run.device_count = len(devices)
        run.alarm_count = alarm_ingested
        run.devices_payload = [d.raw for d in devices]
        run.alarms_payload = [
            {
                "alarm_id": a.alarm_id,
                "alarm_type": a.alarm_type,
                "severity": a.severity,
                "title": a.title,
                "device_mac": a.device_mac,
            }
            for a in alarms
        ]
        run.finished_at = _utcnow()
        config.last_sync_at = run.finished_at
        config.last_status = "healthy"
        config.last_error = None
        config.last_device_count = len(devices)
        await db.flush()

        return {
            "status": "done",
            "device_count": len(devices),
            "alarm_count": alarm_ingested,
            "run_id": run.id,
        }
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = _utcnow()
        config.last_status = "error"
        config.last_error = str(exc)
        await db.flush()
        raise


async def audit_firewalla_config_change(db: AsyncSession, *, user: User, config: FirewallaConfig) -> None:
    await log_audit_event(
        db,
        action="module.firewalla.updated",
        user=user,
        target_type="firewalla_config",
        target_id=str(config.id),
        details={"enabled": config.enabled, "base_url": config.base_url},
    )
