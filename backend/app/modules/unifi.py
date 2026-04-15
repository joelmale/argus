from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_audit_event
from app.db.models import Asset, AssetTag, UnifiConfig, UnifiSyncRun, User
from app.fingerprinting.passive import record_passive_observation
from app.services.identity import AssetIdentityResolver
from app.scanner.topology import _upsert_topology_link
from app.topology.segments import ensure_segment_for_asset


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_base_url(value: str | None, default: str = "https://192.168.1.1") -> str:
    raw = (value or default).strip()
    if not raw:
        raw = default
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    return raw.rstrip("/")


@dataclass(slots=True)
class UnifiClientRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    ap_mac: str | None
    ssid: str | None
    is_wired: bool
    raw: dict


@dataclass(slots=True)
class UnifiDeviceRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    model: str | None
    device_type: str | None  # 'uap' | 'usw' | 'ugw' | 'udm'
    version: str | None
    raw: dict


def _normalize_unifi_client(record: dict[str, Any]) -> UnifiClientRecord:
    return UnifiClientRecord(
        mac=record.get("mac"),
        ip=record.get("ip"),
        hostname=record.get("hostname") or record.get("name"),
        ap_mac=record.get("ap_mac"),
        ssid=record.get("essid"),
        is_wired=bool(record.get("is_wired", False)),
        raw=record,
    )


def _normalize_unifi_device(record: dict[str, Any]) -> UnifiDeviceRecord:
    model = record.get("model", "")
    ip = (record.get("config_network") or {}).get("ip") or record.get("ip")
    if model.startswith(("UAP", "U6")):
        device_type = "uap"
    elif model.startswith("USW"):
        device_type = "usw"
    elif model.startswith(("UGW", "USG")):
        device_type = "ugw"
    elif model.startswith("UDM"):
        device_type = "udm"
    else:
        device_type = "unknown"
    return UnifiDeviceRecord(
        mac=record.get("mac"),
        ip=ip,
        hostname=record.get("name"),
        model=model,
        device_type=device_type,
        version=record.get("version"),
        raw=record,
    )


_UNIFI_DEVICE_TYPE_MAP: dict[str, str] = {
    "uap": "access_point",
    "usw": "switch",
    "ugw": "router",
    "udm": "router",
}


class UnifiApiClient:
    def __init__(
        self,
        *,
        controller_url: str,
        username: str,
        password: str,
        site_id: str = "default",
        timeout_seconds: int = 15,
        verify_tls: bool = False,
    ) -> None:
        self.controller_url = _normalize_base_url(controller_url)
        self.username = username
        self.password = password
        self.site_id = site_id
        self.timeout_seconds = max(5, timeout_seconds)
        self._client = httpx.AsyncClient(
            base_url=self.controller_url,
            timeout=self.timeout_seconds,
            verify=verify_tls,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "UnifiApiClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def login(self) -> None:
        payload = {"username": self.username, "password": self.password}
        # Try UniFi OS path first (UDM/UDM-Pro)
        try:
            response = await self._client.post("/api/auth/login", json=payload)
            if response.status_code not in (400, 404):
                response.raise_for_status()
                return
        except httpx.HTTPStatusError:
            pass

        # Fall back to classic controller path
        response = await self._client.post("/api/login", json=payload)
        response.raise_for_status()

    async def fetch_clients(self) -> list[UnifiClientRecord]:
        response = await self._client.get(f"/api/s/{self.site_id}/stat/sta")
        response.raise_for_status()
        data = response.json().get("data", [])
        return [_normalize_unifi_client(r) for r in data if isinstance(r, dict)]

    async def fetch_devices(self) -> list[UnifiDeviceRecord]:
        response = await self._client.get(f"/api/s/{self.site_id}/stat/device")
        response.raise_for_status()
        data = response.json().get("data", [])
        return [_normalize_unifi_device(r) for r in data if isinstance(r, dict)]


async def get_or_create_unifi_config(db: AsyncSession) -> UnifiConfig:
    config = (await db.execute(select(UnifiConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config
    config = UnifiConfig()
    db.add(config)
    await db.flush()
    return config


def serialize_unifi_config(config: UnifiConfig) -> dict[str, Any]:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "controller_url": config.controller_url,
        "username": config.username,
        "password": "****" if config.password else None,
        "site_id": config.site_id,
        "verify_tls": config.verify_tls,
        "request_timeout_seconds": config.request_timeout_seconds,
        "fetch_clients": config.fetch_clients,
        "fetch_devices": config.fetch_devices,
        "last_tested_at": config.last_tested_at.isoformat() if config.last_tested_at else None,
        "last_sync_at": config.last_sync_at.isoformat() if config.last_sync_at else None,
        "last_status": config.last_status,
        "last_error": config.last_error,
        "last_client_count": config.last_client_count,
        "last_device_count": config.last_device_count,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


def serialize_unifi_sync_run(run: UnifiSyncRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "status": run.status,
        "client_count": run.client_count,
        "device_count": run.device_count,
        "error": run.error,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


async def list_recent_unifi_sync_runs(db: AsyncSession, limit: int = 5) -> list[UnifiSyncRun]:
    result = await db.execute(select(UnifiSyncRun).order_by(desc(UnifiSyncRun.started_at)).limit(limit))
    return list(result.scalars().all())


async def update_unifi_config(
    db: AsyncSession,
    *,
    enabled: bool,
    controller_url: str,
    username: str | None,
    password: str | None,
    site_id: str,
    verify_tls: bool,
    request_timeout_seconds: int,
    fetch_clients: bool,
    fetch_devices: bool,
) -> UnifiConfig:
    config = await get_or_create_unifi_config(db)
    config.enabled = enabled
    config.controller_url = _normalize_base_url(controller_url)
    config.username = (username or "").strip() or None
    config.password = (password or "").strip() or None
    config.site_id = (site_id or "default").strip() or "default"
    config.verify_tls = verify_tls
    config.request_timeout_seconds = max(5, request_timeout_seconds)
    config.fetch_clients = fetch_clients
    config.fetch_devices = fetch_devices
    await db.flush()
    return config


async def _resolve_asset(db: AsyncSession, *, mac: str | None, ip: str | None, hostname: str | None) -> Asset | None:
    resolver = AssetIdentityResolver(db, source="unifi")
    return await resolver.resolve_asset(mac=mac, ip=ip, hostname=hostname, lookup_order=("mac", "ip", "hostname"))


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


async def _enrich_asset_from_unifi_client(db: AsyncSession, asset: Asset, client: UnifiClientRecord) -> None:
    if client.mac and not asset.mac_address:
        asset.mac_address = client.mac
    if client.hostname and not asset.hostname:
        asset.hostname = client.hostname
    asset.status = "online"
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "unifi_client",
        {"ssid": client.ssid, "ap_mac": client.ap_mac, "is_wired": client.is_wired},
    )

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "unifi", tag_names)
    if not client.is_wired:
        _ensure_asset_tag(db, asset, "wifi", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="unifi",
        event_type="client_seen",
        summary=f"UniFi controller observed {client.hostname or client.ip or client.mac or asset.ip_address}",
        details={
            "ip": client.ip or asset.ip_address,
            "mac": client.mac or asset.mac_address,
            "hostname": client.hostname,
            "ssid": client.ssid,
            "ap_mac": client.ap_mac,
            "is_wired": client.is_wired,
        },
    )


async def _upsert_unifi_client_topology_link(db: AsyncSession, client_asset: Asset, client: UnifiClientRecord) -> int:
    if not client.ap_mac:
        return 0
    if (client_asset.mac_address or "").lower() == client.ap_mac.lower():
        return 0
    access_point = await _resolve_asset(db, mac=client.ap_mac, ip=None, hostname=None)
    if access_point is None or access_point.id == client_asset.id:
        return 0

    segment = await ensure_segment_for_asset(db, access_point, source="unifi")
    metadata = {
        "source": "unifi",
        "relationship_type": "wireless_ap_for",
        "observed": True,
        "confidence": 0.98,
        "segment_id": segment.id if segment else None,
        "ap_mac": client.ap_mac,
        "client_mac": client.mac or client_asset.mac_address,
        "client_ip": client.ip or client_asset.ip_address,
        "ssid": client.ssid,
    }
    return await _upsert_topology_link(db, access_point.id, client_asset.id, "wifi", metadata)


async def _enrich_asset_from_unifi_device(db: AsyncSession, asset: Asset, device: UnifiDeviceRecord) -> None:
    if device.mac and not asset.mac_address:
        asset.mac_address = device.mac
    if device.hostname and not asset.hostname:
        asset.hostname = device.hostname
    asset.vendor = asset.vendor or "Ubiquiti"
    asset.status = "online"
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "unifi_device",
        {"model": device.model, "version": device.version, "device_type": device.device_type},
    )

    if device.device_type and device.device_type != "unknown":
        if asset.device_type is None or asset.device_type == "unknown":
            asset.device_type = _UNIFI_DEVICE_TYPE_MAP.get(device.device_type)

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "unifi", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="unifi",
        event_type="device_seen",
        summary=f"UniFi controller observed device {device.hostname or device.ip or device.mac or asset.ip_address}",
        details={
            "ip": device.ip or asset.ip_address,
            "mac": device.mac or asset.mac_address,
            "hostname": device.hostname,
            "model": device.model,
            "version": device.version,
            "device_type": device.device_type,
        },
    )


async def test_unifi_connection(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_unifi_config(db)
    if not config.username or not config.password:
        raise ValueError("Set the UniFi controller username and password before testing the module.")

    async with UnifiApiClient(
        controller_url=config.controller_url,
        username=config.username,
        password=config.password,
        site_id=config.site_id,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=config.verify_tls,
    ) as client:
        await client.login()
        clients: list[UnifiClientRecord] = []
        devices: list[UnifiDeviceRecord] = []
        if config.fetch_clients:
            clients = await client.fetch_clients()
        if config.fetch_devices:
            devices = await client.fetch_devices()

    config.last_tested_at = _utcnow()
    config.last_status = "healthy"
    config.last_error = None
    config.last_client_count = len(clients)
    config.last_device_count = len(devices)
    await db.flush()
    return {
        "status": "healthy",
        "client_count": len(clients),
        "device_count": len(devices),
    }


async def sync_unifi_module(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_unifi_config(db)
    if not config.enabled:
        raise ValueError("Enable the UniFi module before syncing.")
    if not config.username or not config.password:
        raise ValueError("Set the UniFi controller username and password before syncing.")

    run = UnifiSyncRun(status="running", started_at=_utcnow())
    db.add(run)
    await db.flush()

    try:
        async with UnifiApiClient(
            controller_url=config.controller_url,
            username=config.username,
            password=config.password,
            site_id=config.site_id,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
        ) as api_client:
            await api_client.login()
            clients: list[UnifiClientRecord] = []
            devices: list[UnifiDeviceRecord] = []
            if config.fetch_clients:
                clients = await api_client.fetch_clients()
            if config.fetch_devices:
                devices = await api_client.fetch_devices()

        for device in devices:
            asset = await _resolve_asset(db, mac=device.mac, ip=device.ip, hostname=device.hostname)
            if asset is None:
                continue
            await _enrich_asset_from_unifi_device(db, asset, device)

        ingested = 0
        topology_links = 0
        for client in clients:
            asset = await _resolve_asset(db, mac=client.mac, ip=client.ip, hostname=client.hostname)
            if asset is None:
                continue
            await _enrich_asset_from_unifi_client(db, asset, client)
            topology_links += await _upsert_unifi_client_topology_link(db, asset, client)
            ingested += 1

        run.status = "done"
        run.client_count = len(clients)
        run.device_count = len(devices)
        run.clients_payload = [c.raw for c in clients]
        run.devices_payload = [d.raw for d in devices]
        run.finished_at = _utcnow()
        config.last_sync_at = run.finished_at
        config.last_status = "healthy"
        config.last_error = None
        config.last_client_count = len(clients)
        config.last_device_count = len(devices)
        await db.flush()

        return {
            "status": "done",
            "client_count": len(clients),
            "device_count": len(devices),
            "ingested_assets": ingested,
            "topology_links": topology_links,
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


async def audit_unifi_config_change(db: AsyncSession, *, user: User, config: UnifiConfig) -> None:
    await log_audit_event(
        db,
        action="module.unifi.updated",
        user=user,
        target_type="unifi_config",
        target_id=str(config.id),
        details={"enabled": config.enabled, "controller_url": config.controller_url},
    )
