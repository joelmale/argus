from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_audit_event
from app.db.models import Asset, AssetTag, PfsenseConfig, PfsenseSyncRun, User
from app.fingerprinting.passive import record_passive_observation


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_base_url(value: str | None, default: str = "http://192.168.1.1") -> str:
    raw = (value or default).strip()
    if not raw:
        raw = default
    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    return raw.rstrip("/")


@dataclass(slots=True)
class DhcpLeaseRecord:
    mac: str | None
    ip: str | None
    hostname: str | None
    interface: str | None
    state: str | None


@dataclass(slots=True)
class ArpRecord:
    mac: str | None
    ip: str | None
    interface: str | None


@dataclass(slots=True)
class InterfaceRecord:
    name: str
    description: str | None
    ip: str | None
    network: str | None
    vlan_id: int | None


def normalize_dhcp_lease(record: dict[str, Any], flavor: str, interface: str | None = None) -> DhcpLeaseRecord:
    if flavor == "opnsense":
        return DhcpLeaseRecord(
            mac=record.get("mac"),
            ip=record.get("address"),
            hostname=record.get("hostname"),
            interface=record.get("if"),
            state=record.get("state"),
        )
    # fauxapi staticmap
    return DhcpLeaseRecord(
        mac=record.get("mac"),
        ip=record.get("ipaddr"),
        hostname=record.get("hostname", ""),
        interface=interface,
        state="static",
    )


def normalize_arp_record(record: dict[str, Any]) -> ArpRecord:
    return ArpRecord(
        mac=record.get("mac"),
        ip=record.get("ip"),
        interface=record.get("intf"),
    )


def normalize_interface(name: str, record: dict[str, Any], flavor: str) -> InterfaceRecord:
    if flavor == "opnsense":
        ip = record.get("ipaddr")
        network: str | None = None
        if ip and record.get("subnetmask"):
            network = f"{ip}/{record['subnetmask']}"
        vlan_id: int | None = None
        if "vlan" in name.lower():
            try:
                vlan_id = int("".join(c for c in name if c.isdigit()) or "0") or None
            except ValueError:
                vlan_id = None
        return InterfaceRecord(
            name=name,
            description=record.get("description"),
            ip=ip,
            network=network,
            vlan_id=vlan_id,
        )
    # fauxapi config structure
    ip = record.get("ipaddr")
    vlan_id = None
    if "vlan" in name.lower():
        try:
            vlan_id = int("".join(c for c in name if c.isdigit()) or "0") or None
        except ValueError:
            vlan_id = None
    return InterfaceRecord(
        name=name,
        description=record.get("descr"),
        ip=ip,
        network=None,
        vlan_id=vlan_id,
    )


def _fauxapi_auth_header(apikey: str, apisecret: str) -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%dZ%H%M%S")
    nonce = uuid4().hex[:8]
    hash_input = f"{apikey}{timestamp}{nonce}".encode()
    digest = hmac.new(apisecret.encode(), hash_input, hashlib.sha256).hexdigest()
    return f"APITOKEN {apikey}:{timestamp}:{nonce}:{digest}"


class PfsenseApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        flavor: str,
        api_key: str | None = None,
        api_secret: str | None = None,
        fauxapi_token: str | None = None,
        timeout_seconds: int = 15,
        verify_tls: bool = False,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self.flavor = flavor
        self.api_key = api_key
        self.api_secret = api_secret
        self.fauxapi_token = fauxapi_token
        self.timeout_seconds = max(5, timeout_seconds)
        self.verify_tls = verify_tls
        auth = None
        if flavor == "opnsense" and api_key and api_secret:
            auth = (api_key, api_secret)
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
            auth=auth,
            follow_redirects=True,
        )

    def _fauxapi_headers(self) -> dict[str, str]:
        if not self.fauxapi_token:
            raise ValueError("fauxapi_token is required for pfsense_fauxapi flavor")
        parts = self.fauxapi_token.split(":", 1)
        if len(parts) != 2:
            raise ValueError("fauxapi_token must be in APIKEY:APISECRET format")
        apikey, apisecret = parts[0].strip(), parts[1].strip()
        return {"fauxapi-auth": _fauxapi_auth_header(apikey, apisecret)}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "PfsenseApiClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def test(self) -> dict[str, Any]:
        if self.flavor == "opnsense":
            response = await self._client.get("/api/core/firmware/status")
            response.raise_for_status()
            return response.json()
        else:
            headers = self._fauxapi_headers()
            response = await self._client.get(
                "/fauxapi/v1/",
                params={"action": "function_call", "args": "system_get_version"},
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    async def fetch_dhcp_leases(self) -> list[DhcpLeaseRecord]:
        if self.flavor == "opnsense":
            response = await self._client.post(
                "/api/dhcpv4/leases/searchLease",
                json={"current": 1, "rowCount": 500, "searchPhrase": ""},
            )
            response.raise_for_status()
            rows = response.json().get("rows", [])
            return [normalize_dhcp_lease(r, self.flavor) for r in rows if isinstance(r, dict)]
        else:
            headers = self._fauxapi_headers()
            response = await self._client.get(
                "/fauxapi/v1/",
                params={"action": "config_get"},
                headers=headers,
            )
            response.raise_for_status()
            dhcpd = response.json().get("data", {}).get("config", {}).get("dhcpd", {})
            leases: list[DhcpLeaseRecord] = []
            for iface_name, iface_data in dhcpd.items():
                if not isinstance(iface_data, dict):
                    continue
                for staticmap in iface_data.get("staticmap", []):
                    if isinstance(staticmap, dict):
                        leases.append(normalize_dhcp_lease(staticmap, self.flavor, interface=iface_name))
            return leases

    async def fetch_arp_table(self) -> list[ArpRecord]:
        if self.flavor != "opnsense":
            return []
        response = await self._client.get("/api/diagnostics/interface/getArp")
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return [normalize_arp_record(r) for r in data if isinstance(r, dict)]
        return []

    async def fetch_interfaces(self) -> list[InterfaceRecord]:
        if self.flavor == "opnsense":
            response = await self._client.get("/api/interfaces/overview/interfacesInfo")
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return [normalize_interface(name, record, self.flavor) for name, record in data.items() if isinstance(record, dict)]
            return []
        else:
            headers = self._fauxapi_headers()
            response = await self._client.get(
                "/fauxapi/v1/",
                params={"action": "config_get"},
                headers=headers,
            )
            response.raise_for_status()
            interfaces = response.json().get("data", {}).get("config", {}).get("interfaces", {})
            if isinstance(interfaces, dict):
                return [normalize_interface(name, record, self.flavor) for name, record in interfaces.items() if isinstance(record, dict)]
            return []


async def get_or_create_pfsense_config(db: AsyncSession) -> PfsenseConfig:
    config = (await db.execute(select(PfsenseConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config
    config = PfsenseConfig()
    db.add(config)
    await db.flush()
    return config


def serialize_pfsense_config(config: PfsenseConfig) -> dict[str, Any]:
    return {
        "id": config.id,
        "enabled": config.enabled,
        "base_url": config.base_url,
        "flavor": config.flavor,
        "api_key": "****" if config.api_key else None,
        "api_secret": "****" if config.api_secret else None,
        "fauxapi_token": "****" if config.fauxapi_token else None,
        "verify_tls": config.verify_tls,
        "request_timeout_seconds": config.request_timeout_seconds,
        "fetch_dhcp_leases": config.fetch_dhcp_leases,
        "fetch_arp_table": config.fetch_arp_table,
        "fetch_interfaces": config.fetch_interfaces,
        "last_tested_at": config.last_tested_at.isoformat() if config.last_tested_at else None,
        "last_sync_at": config.last_sync_at.isoformat() if config.last_sync_at else None,
        "last_status": config.last_status,
        "last_error": config.last_error,
        "last_lease_count": config.last_lease_count,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }


def serialize_pfsense_sync_run(run: PfsenseSyncRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "status": run.status,
        "lease_count": run.lease_count,
        "arp_count": run.arp_count,
        "interface_count": run.interface_count,
        "error": run.error,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


async def list_recent_pfsense_sync_runs(db: AsyncSession, limit: int = 5) -> list[PfsenseSyncRun]:
    result = await db.execute(select(PfsenseSyncRun).order_by(desc(PfsenseSyncRun.started_at)).limit(limit))
    return list(result.scalars().all())


async def update_pfsense_config(
    db: AsyncSession,
    *,
    enabled: bool,
    base_url: str,
    flavor: str,
    api_key: str | None,
    api_secret: str | None,
    fauxapi_token: str | None,
    verify_tls: bool,
    request_timeout_seconds: int,
    fetch_dhcp_leases: bool,
    fetch_arp_table: bool,
    fetch_interfaces: bool,
) -> PfsenseConfig:
    config = await get_or_create_pfsense_config(db)
    config.enabled = enabled
    config.base_url = _normalize_base_url(base_url)
    config.flavor = flavor
    config.api_key = (api_key or "").strip() or None
    config.api_secret = (api_secret or "").strip() or None
    config.fauxapi_token = (fauxapi_token or "").strip() or None
    config.verify_tls = verify_tls
    config.request_timeout_seconds = max(5, request_timeout_seconds)
    config.fetch_dhcp_leases = fetch_dhcp_leases
    config.fetch_arp_table = fetch_arp_table
    config.fetch_interfaces = fetch_interfaces
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


async def _resolve_asset_by_mac_or_ip(
    db: AsyncSession,
    *,
    mac: str | None,
    ip: str | None,
    hostname: str | None,
    create_if_missing: bool = True,
) -> Asset | None:
    if mac:
        result = await db.execute(select(Asset).where(func.lower(Asset.mac_address) == mac.lower()).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if ip:
        result = await db.execute(select(Asset).where(Asset.ip_address == ip).limit(1))
        asset = result.scalar_one_or_none()
        if asset is not None:
            return asset
    if not ip or not create_if_missing:
        return None
    asset = Asset(ip_address=ip, mac_address=mac, hostname=hostname, status="online")
    db.add(asset)
    await db.flush()
    return asset


async def _enrich_asset_from_dhcp_lease(db: AsyncSession, asset: Asset, lease: DhcpLeaseRecord) -> None:
    if lease.mac and not asset.mac_address:
        asset.mac_address = lease.mac
    if lease.hostname and not asset.hostname:
        asset.hostname = lease.hostname
    asset.status = "online"
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "pfsense_dhcp",
        {"interface": lease.interface, "state": lease.state},
    )

    tag_names = await _existing_asset_tags(db, asset)
    _ensure_asset_tag(db, asset, "pfsense", tag_names)
    if lease.state == "static":
        _ensure_asset_tag(db, asset, "static-dhcp", tag_names)

    await record_passive_observation(
        db,
        asset=asset,
        source="pfsense",
        event_type="dhcp_lease",
        summary=f"pfSense/OPNsense DHCP lease observed {lease.hostname or lease.ip or lease.mac or asset.ip_address}",
        details={
            "ip": lease.ip or asset.ip_address,
            "mac": lease.mac or asset.mac_address,
            "hostname": lease.hostname,
            "interface": lease.interface,
            "state": lease.state,
        },
    )


async def _enrich_asset_from_arp(db: AsyncSession, asset: Asset, arp: ArpRecord) -> None:
    if arp.mac and not asset.mac_address:
        asset.mac_address = arp.mac
    asset.custom_fields = _merge_custom_fields(
        asset.custom_fields,
        "pfsense_arp",
        {"interface": arp.interface},
    )


async def test_pfsense_connection(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_pfsense_config(db)
    if config.flavor == "opnsense" and (not config.api_key or not config.api_secret):
        raise ValueError("Set OPNsense API key and secret before testing the module.")
    if config.flavor == "pfsense_fauxapi" and not config.fauxapi_token:
        raise ValueError("Set the fauxapi token before testing the module.")

    async with PfsenseApiClient(
        base_url=config.base_url,
        flavor=config.flavor,
        api_key=config.api_key,
        api_secret=config.api_secret,
        fauxapi_token=config.fauxapi_token,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=config.verify_tls,
    ) as client:
        await client.test()
        leases = await client.fetch_dhcp_leases() if config.fetch_dhcp_leases else []

    config.last_tested_at = _utcnow()
    config.last_status = "healthy"
    config.last_error = None
    config.last_lease_count = len(leases)
    await db.flush()
    return {
        "status": "healthy",
        "lease_count": len(leases),
        "flavor": config.flavor,
    }


async def sync_pfsense_module(db: AsyncSession) -> dict[str, Any]:
    config = await get_or_create_pfsense_config(db)
    if not config.enabled:
        raise ValueError("Enable the pfSense/OPNsense module before syncing.")
    if config.flavor == "opnsense" and (not config.api_key or not config.api_secret):
        raise ValueError("Set OPNsense API key and secret before syncing.")
    if config.flavor == "pfsense_fauxapi" and not config.fauxapi_token:
        raise ValueError("Set the fauxapi token before syncing.")

    run = PfsenseSyncRun(status="running", started_at=_utcnow())
    db.add(run)
    await db.flush()

    try:
        async with PfsenseApiClient(
            base_url=config.base_url,
            flavor=config.flavor,
            api_key=config.api_key,
            api_secret=config.api_secret,
            fauxapi_token=config.fauxapi_token,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
        ) as client:
            leases: list[DhcpLeaseRecord] = []
            arp_records: list[ArpRecord] = []
            interfaces: list[InterfaceRecord] = []

            if config.fetch_dhcp_leases:
                leases = await client.fetch_dhcp_leases()
            if config.fetch_arp_table:
                arp_records = await client.fetch_arp_table()
            if config.fetch_interfaces:
                interfaces = await client.fetch_interfaces()

        for lease in leases:
            asset = await _resolve_asset_by_mac_or_ip(db, mac=lease.mac, ip=lease.ip, hostname=lease.hostname)
            if asset is None:
                continue
            await _enrich_asset_from_dhcp_lease(db, asset, lease)

        for arp in arp_records:
            if not arp.ip:
                continue
            result = await db.execute(select(Asset).where(Asset.ip_address == arp.ip).limit(1))
            asset = result.scalar_one_or_none()
            if asset is None:
                continue
            await _enrich_asset_from_arp(db, asset, arp)

        run.status = "done"
        run.lease_count = len(leases)
        run.arp_count = len(arp_records)
        run.interface_count = len(interfaces)
        run.leases_payload = [
            {"mac": lease.mac, "ip": lease.ip, "hostname": lease.hostname, "interface": lease.interface, "state": lease.state}
            for lease in leases
        ]
        run.arp_payload = [
            {"mac": a.mac, "ip": a.ip, "interface": a.interface}
            for a in arp_records
        ]
        run.interfaces_payload = {
            iface.name: {"description": iface.description, "ip": iface.ip, "network": iface.network, "vlan_id": iface.vlan_id}
            for iface in interfaces
        }
        run.finished_at = _utcnow()
        config.last_sync_at = run.finished_at
        config.last_status = "healthy"
        config.last_error = None
        config.last_lease_count = len(leases)
        await db.flush()

        return {
            "status": "done",
            "lease_count": len(leases),
            "arp_count": len(arp_records),
            "interface_count": len(interfaces),
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


async def audit_pfsense_config_change(db: AsyncSession, *, user: User, config: PfsenseConfig) -> None:
    await log_audit_event(
        db,
        action="module.pfsense.updated",
        user=user,
        target_type="pfsense_config",
        target_id=str(config.id),
        details={"enabled": config.enabled, "base_url": config.base_url, "flavor": config.flavor},
    )
