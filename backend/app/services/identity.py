from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetHistory

_MAC_PATTERN = re.compile(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}")


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().replace("-", ":").upper()
    return cleaned if _MAC_PATTERN.fullmatch(cleaned) else None


def is_locally_administered_mac(value: str | None) -> bool:
    mac = normalize_mac(value)
    if mac is None:
        return False
    try:
        first_octet = int(mac.split(":", 1)[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


class AssetIdentityResolver:
    """Resolve or create an Asset from any observed identity evidence."""

    def __init__(self, db: AsyncSession, *, source: str = "identity") -> None:
        self.db = db
        self.source = source

    async def resolve_asset(
        self,
        *,
        mac: str | None = None,
        ip: str | None = None,
        hostname: str | None = None,
        create_if_missing: bool = True,
        lookup_order: tuple[str, ...] = ("ip", "mac", "hostname"),
    ) -> Asset | None:
        normalized_mac = normalize_mac(mac)
        candidates: list[Asset | None] = []

        for key in lookup_order:
            if key == "ip" and ip:
                candidates.append(await self._find_by_ip(ip))
            elif key == "mac" and normalized_mac and not is_locally_administered_mac(normalized_mac):
                candidates.append(await self._find_by_mac(normalized_mac))
            elif key == "hostname" and hostname:
                candidates.append(await self._find_by_hostname(hostname))

        asset = next((candidate for candidate in candidates if candidate is not None), None)
        if asset is not None:
            await self._reconcile_identity(asset, mac=normalized_mac, ip=ip, hostname=hostname)
            return asset

        if not create_if_missing or not ip:
            return None

        asset = Asset(
            ip_address=ip,
            mac_address=normalized_mac if normalized_mac and not is_locally_administered_mac(normalized_mac) else None,
            hostname=hostname,
            status="online",
        )
        self.db.add(asset)
        await self.db.flush()
        if normalized_mac and is_locally_administered_mac(normalized_mac):
            await self._record_history(
                asset,
                "identity_observed",
                {
                    "source": self.source,
                    "mac": {"new": normalized_mac, "randomized": True},
                    "ip": {"new": ip},
                    "hostname": {"new": hostname},
                    "action": "stored_without_mac_primary_key",
                },
            )
        return asset

    async def _find_by_ip(self, ip: str) -> Asset | None:
        return (await self.db.execute(select(Asset).where(Asset.ip_address == ip).limit(1))).scalar_one_or_none()

    async def _find_by_mac(self, mac: str) -> Asset | None:
        return (
            await self.db.execute(select(Asset).where(func.lower(Asset.mac_address) == mac.lower()).limit(1))
        ).scalar_one_or_none()

    async def _find_by_hostname(self, hostname: str) -> Asset | None:
        return (await self.db.execute(select(Asset).where(Asset.hostname == hostname).limit(1))).scalar_one_or_none()

    async def _reconcile_identity(
        self,
        asset: Asset,
        *,
        mac: str | None,
        ip: str | None,
        hostname: str | None,
    ) -> None:
        diff: dict[str, dict[str, object]] = {}

        if hostname and not asset.hostname:
            asset.hostname = hostname
            diff["hostname"] = {"old": None, "new": hostname}
        elif hostname and asset.hostname and asset.hostname != hostname:
            diff["hostname"] = {"old": asset.hostname, "new": hostname}

        if ip and asset.ip_address != ip:
            duplicate_ip = await self._find_by_ip(ip)
            if duplicate_ip is None or duplicate_ip.id == asset.id:
                diff["ip_address"] = {"old": asset.ip_address, "new": ip}
                asset.ip_address = ip
            else:
                diff["ip_address"] = {
                    "old": asset.ip_address,
                    "new": ip,
                    "conflict": str(duplicate_ip.id),
                }

        if mac:
            if asset.mac_address is None and not is_locally_administered_mac(mac):
                asset.mac_address = mac
                diff["mac_address"] = {"old": None, "new": mac}
            elif asset.mac_address and asset.mac_address.lower() != mac.lower():
                diff["mac_address"] = {
                    "old": asset.mac_address,
                    "new": mac,
                    "randomized": is_locally_administered_mac(mac),
                }
            elif not asset.mac_address and is_locally_administered_mac(mac):
                diff["mac_address"] = {"old": None, "new": mac, "randomized": True}

        if diff:
            has_conflict = any("conflict" in item for item in diff.values())
            await self._record_history(
                asset,
                "identity_conflict" if has_conflict else "identity_observed",
                {
                    "source": self.source,
                    **diff,
                },
            )

    async def _record_history(self, asset: Asset, change_type: str, diff: dict) -> None:
        self.db.add(AssetHistory(asset_id=asset.id, change_type=change_type, diff=diff))
        await self.db.flush()
