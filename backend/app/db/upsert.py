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

from app.db.models import Asset, AssetHistory, Port
from app.scanner.models import HostScanResult

log = logging.getLogger(__name__)


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
    new_device_type = None

    if result.os_fingerprint.os_name:
        new_os = result.os_fingerprint.os_name

    if result.ai_analysis:
        ai = result.ai_analysis
        if ai.os_guess:
            new_os = ai.os_guess
        if ai.vendor:
            new_vendor = ai.vendor
        if ai.device_class and ai.device_class.value != "unknown":
            new_device_type = ai.device_class.value

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
            status="online",
            first_seen=now,
            last_seen=now,
        )
        db.add(asset)
        await db.flush()  # Get the generated ID

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

    _check("hostname",    new_hostname)
    _check("vendor",      new_vendor)
    _check("os_name",     new_os)
    _check("device_type", new_device_type)

    if result.host.mac_address and not existing.mac_address:
        _check("mac_address", result.host.mac_address)

    existing.last_seen = now

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
    return count
