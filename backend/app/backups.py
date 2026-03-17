from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from uuid import UUID

import asyncssh
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, ConfigBackupSnapshot, ConfigBackupTarget


@dataclass(frozen=True)
class BackupDriver:
    name: str
    label: str
    commands: tuple[str, ...]
    description: str


BACKUP_DRIVERS: dict[str, BackupDriver] = {
    "cisco_ios": BackupDriver(
        name="cisco_ios",
        label="Cisco IOS",
        commands=("terminal length 0", "show running-config"),
        description="Collects the running configuration from Cisco IOS and IOS-XE style CLIs.",
    ),
    "juniper_junos": BackupDriver(
        name="juniper_junos",
        label="Juniper Junos",
        commands=('cli -c "show configuration | display set | no-more"',),
        description="Exports Junos configuration in set-style format.",
    ),
    "mikrotik_routeros": BackupDriver(
        name="mikrotik_routeros",
        label="MikroTik RouterOS",
        commands=("/export terse",),
        description="Runs RouterOS export in terse mode for reproducible diffs.",
    ),
    "openwrt": BackupDriver(
        name="openwrt",
        label="OpenWRT",
        commands=("uci export",),
        description="Exports OpenWRT UCI configuration.",
    ),
}


def list_backup_drivers() -> list[dict[str, str]]:
    return [
        {
            "name": driver.name,
            "label": driver.label,
            "description": driver.description,
        }
        for driver in BACKUP_DRIVERS.values()
    ]


async def upsert_backup_target(
    db: AsyncSession,
    *,
    asset_id: UUID,
    driver: str,
    username: str,
    password_env_var: str | None,
    port: int = 22,
    host_override: str | None = None,
    enabled: bool = True,
) -> ConfigBackupTarget:
    if driver not in BACKUP_DRIVERS:
        raise ValueError(f"Unsupported backup driver: {driver}")

    target = (
        await db.execute(select(ConfigBackupTarget).where(ConfigBackupTarget.asset_id == asset_id))
    ).scalar_one_or_none()

    if target is None:
        target = ConfigBackupTarget(
            asset_id=asset_id,
            driver=driver,
            username=username,
            password_env_var=password_env_var,
            port=port,
            host_override=host_override,
            enabled=enabled,
        )
        db.add(target)
    else:
        target.driver = driver
        target.username = username
        target.password_env_var = password_env_var
        target.port = port
        target.host_override = host_override
        target.enabled = enabled

    await db.commit()
    await db.refresh(target)
    return target


async def list_backup_snapshots(db: AsyncSession, asset_id: UUID) -> list[ConfigBackupSnapshot]:
    result = await db.execute(
        select(ConfigBackupSnapshot)
        .where(ConfigBackupSnapshot.asset_id == asset_id)
        .order_by(ConfigBackupSnapshot.captured_at.desc())
        .limit(20)
    )
    return result.scalars().all()


async def get_backup_target(db: AsyncSession, asset_id: UUID) -> ConfigBackupTarget | None:
    result = await db.execute(select(ConfigBackupTarget).where(ConfigBackupTarget.asset_id == asset_id))
    return result.scalar_one_or_none()


async def capture_backup_for_asset(db: AsyncSession, asset_id: UUID) -> ConfigBackupSnapshot:
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise LookupError("Asset not found")

    target = await get_backup_target(db, asset_id)
    if target is None or not target.enabled:
        raise LookupError("Config backup target is not configured")

    snapshot = ConfigBackupSnapshot(
        asset_id=asset.id,
        target_id=target.id,
        status="running",
        driver=target.driver,
        command="\n".join(BACKUP_DRIVERS[target.driver].commands),
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)

    try:
        snapshot.content = await _run_backup(asset, target)
        snapshot.status = "done"
        snapshot.error = None
    except Exception as exc:
        snapshot.status = "failed"
        snapshot.error = str(exc)[:1000]

    await db.commit()
    await db.refresh(snapshot)
    return snapshot


async def _run_backup(asset: Asset, target: ConfigBackupTarget) -> str:
    driver = BACKUP_DRIVERS[target.driver]
    host = target.host_override or asset.ip_address
    password = os.getenv(target.password_env_var or "")

    if not target.password_env_var:
        raise RuntimeError("password_env_var is required for SSH config backups")
    if not password:
        raise RuntimeError(f"Environment variable {target.password_env_var} is not set")

    conn = await asyncssh.connect(
        host,
        port=target.port,
        username=target.username,
        password=password,
        known_hosts=None,
        connect_timeout=10,
    )
    try:
        process = await conn.create_process(term_type="vt100")
        chunks: list[str] = []
        for command in driver.commands:
            process.stdin.write(f"{command}\n")
            await process.stdin.drain()
            await asyncio.sleep(0.75)
            chunks.append(await _read_available(process))

        process.stdin.write("exit\n")
        await process.stdin.drain()
        try:
            await asyncio.wait_for(process.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            process.terminate()
        chunks.append(await _read_available(process))
    finally:
        conn.close()
        await conn.wait_closed()

    content = "\n".join(chunk.strip("\r\n") for chunk in chunks if chunk.strip())
    if not content:
        raise RuntimeError("Device returned empty backup output")
    return content


async def _read_available(process: asyncssh.SSHClientProcess) -> str:
    chunks: list[str] = []
    while True:
        try:
            chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=0.25)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        if len(chunk) < 4096:
            break
    return "".join(chunks)
