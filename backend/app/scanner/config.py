from __future__ import annotations

import ipaddress
import fcntl
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_audit_event
from app.core.config import settings
from app.db.models import (
    Asset,
    AssetHistory,
    ConfigBackupSnapshot,
    ConfigBackupTarget,
    Finding,
    ScanJob,
    ScannerConfig,
    TopologyLink,
    User,
    WirelessAssociation,
)
from app.scanner.models import HostScanResult

DEFAULT_TARGET_PLACEHOLDER = "192.168.1.0/24"
AUTO_TARGET_SENTINEL = "auto"
_IGNORED_INTERFACE_PREFIXES = ("lo", "docker", "veth", "br-", "cni", "virbr")
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891b


@dataclass(slots=True)
class EffectiveScannerConfig:
    enabled: bool
    default_targets: str | None
    auto_detect_targets: bool
    detected_targets: str | None
    effective_targets: str | None
    default_profile: str
    interval_minutes: int
    concurrent_hosts: int
    fingerprint_ai_enabled: bool
    fingerprint_ai_model: str
    fingerprint_ai_min_confidence: float
    fingerprint_ai_prompt_suffix: str | None
    internet_lookup_enabled: bool
    internet_lookup_allowed_domains: str | None
    internet_lookup_budget: int
    internet_lookup_timeout_seconds: int
    last_scheduled_scan_at: datetime | None


def _ioctl_ipv4(ifname: str, request: int) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = fcntl.ioctl(
            sock.fileno(),
            request,
            struct.pack("256s", ifname[:15].encode("utf-8")),
        )
        return socket.inet_ntoa(data[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _get_ipv4_network(ifname: str) -> str | None:
    address = _ioctl_ipv4(ifname, _SIOCGIFADDR)
    netmask = _ioctl_ipv4(ifname, _SIOCGIFNETMASK)
    if not address or not netmask:
        return None

    try:
        iface = ipaddress.IPv4Interface(f"{address}/{netmask}")
    except ipaddress.AddressValueError:
        return None

    if not iface.ip.is_private:
        return None

    network = iface.network
    if network.prefixlen < 8 or network.prefixlen > 30:
        return None

    return str(network)


def detect_local_ipv4_cidr() -> str | None:
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as handle:
            next(handle, None)
            for line in handle:
                fields = line.strip().split()
                if len(fields) < 11:
                    continue
                iface, destination, _, flags = fields[:4]
                if destination != "00000000":
                    continue
                try:
                    if not int(flags, 16) & 0x2:
                        continue
                except ValueError:
                    continue
                if iface.startswith(_IGNORED_INTERFACE_PREFIXES):
                    continue
                network = _get_ipv4_network(iface)
                if network:
                    return network
    except OSError:
        pass

    for _, ifname in socket.if_nameindex():
        if ifname.startswith(_IGNORED_INTERFACE_PREFIXES):
            continue
        network = _get_ipv4_network(ifname)
        if network:
            return network
    return None


def _bootstrap_targets_from_env() -> tuple[str | None, bool]:
    configured = (settings.SCANNER_DEFAULT_TARGETS or "").strip()
    if configured and configured != DEFAULT_TARGET_PLACEHOLDER:
        return configured, False
    return None, True


async def get_or_create_scanner_config(db: AsyncSession) -> ScannerConfig:
    config = (await db.execute(select(ScannerConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config

    default_targets, auto_detect_targets = _bootstrap_targets_from_env()
    config = ScannerConfig(
        enabled=True,
        default_targets=default_targets,
        auto_detect_targets=auto_detect_targets,
        default_profile=settings.SCANNER_DEFAULT_PROFILE,
        interval_minutes=settings.SCANNER_INTERVAL_MINUTES,
        concurrent_hosts=settings.SCANNER_CONCURRENT_HOSTS,
        fingerprint_ai_enabled=False,
        fingerprint_ai_model=settings.OLLAMA_MODEL,
        fingerprint_ai_min_confidence=0.75,
        internet_lookup_enabled=False,
        internet_lookup_allowed_domains=None,
        internet_lookup_budget=3,
        internet_lookup_timeout_seconds=5,
    )
    db.add(config)
    await db.flush()
    return config


def build_effective_scanner_config(config: ScannerConfig) -> EffectiveScannerConfig:
    detected_targets = detect_local_ipv4_cidr() if config.auto_detect_targets else None
    effective_targets = (config.default_targets or "").strip() or detected_targets
    return EffectiveScannerConfig(
        enabled=config.enabled,
        default_targets=config.default_targets,
        auto_detect_targets=config.auto_detect_targets,
        detected_targets=detected_targets,
        effective_targets=effective_targets,
        default_profile=config.default_profile,
        interval_minutes=config.interval_minutes,
        concurrent_hosts=config.concurrent_hosts,
        fingerprint_ai_enabled=config.fingerprint_ai_enabled,
        fingerprint_ai_model=config.fingerprint_ai_model or settings.OLLAMA_MODEL,
        fingerprint_ai_min_confidence=config.fingerprint_ai_min_confidence,
        fingerprint_ai_prompt_suffix=config.fingerprint_ai_prompt_suffix,
        internet_lookup_enabled=config.internet_lookup_enabled,
        internet_lookup_allowed_domains=config.internet_lookup_allowed_domains,
        internet_lookup_budget=config.internet_lookup_budget,
        internet_lookup_timeout_seconds=config.internet_lookup_timeout_seconds,
        last_scheduled_scan_at=config.last_scheduled_scan_at,
    )


async def read_effective_scanner_config(db: AsyncSession) -> tuple[ScannerConfig, EffectiveScannerConfig]:
    config = await get_or_create_scanner_config(db)
    return config, build_effective_scanner_config(config)


async def update_scanner_config(
    db: AsyncSession,
    *,
    enabled: bool,
    default_targets: str | None,
    auto_detect_targets: bool,
    default_profile: str,
    interval_minutes: int,
    concurrent_hosts: int,
    fingerprint_ai_enabled: bool,
    fingerprint_ai_model: str | None,
    fingerprint_ai_min_confidence: float,
    fingerprint_ai_prompt_suffix: str | None,
    internet_lookup_enabled: bool,
    internet_lookup_allowed_domains: str | None,
    internet_lookup_budget: int,
    internet_lookup_timeout_seconds: int,
) -> tuple[ScannerConfig, EffectiveScannerConfig]:
    normalized_targets = default_targets.strip() if default_targets and default_targets.strip() else None
    if not auto_detect_targets and not normalized_targets:
        raise ValueError("Explicit scanner targets are required when auto-detect is disabled.")

    config = await get_or_create_scanner_config(db)
    config.enabled = enabled
    config.default_targets = normalized_targets
    config.auto_detect_targets = auto_detect_targets
    config.default_profile = default_profile
    config.interval_minutes = interval_minutes
    config.concurrent_hosts = concurrent_hosts
    config.fingerprint_ai_enabled = fingerprint_ai_enabled
    config.fingerprint_ai_model = (fingerprint_ai_model or "").strip() or settings.OLLAMA_MODEL
    config.fingerprint_ai_min_confidence = max(0.0, min(1.0, fingerprint_ai_min_confidence))
    config.fingerprint_ai_prompt_suffix = fingerprint_ai_prompt_suffix.strip() if fingerprint_ai_prompt_suffix and fingerprint_ai_prompt_suffix.strip() else None
    config.internet_lookup_enabled = internet_lookup_enabled
    config.internet_lookup_allowed_domains = internet_lookup_allowed_domains.strip() if internet_lookup_allowed_domains and internet_lookup_allowed_domains.strip() else None
    config.internet_lookup_budget = max(1, internet_lookup_budget)
    config.internet_lookup_timeout_seconds = max(1, internet_lookup_timeout_seconds)
    await db.flush()
    return config, build_effective_scanner_config(config)


def resolve_scan_targets(config: ScannerConfig, requested_targets: str | None) -> str:
    explicit = (requested_targets or "").strip()
    if explicit:
        return explicit
    if config.default_targets and config.default_targets.strip():
        return config.default_targets.strip()
    if config.auto_detect_targets:
        return AUTO_TARGET_SENTINEL
    raise ValueError("No scan targets configured. Set scanner defaults in Settings or provide explicit targets.")


def materialize_scan_targets(targets: str) -> str:
    if targets != AUTO_TARGET_SENTINEL:
        return targets
    detected = detect_local_ipv4_cidr()
    if not detected:
        raise RuntimeError("Unable to auto-detect a local private IPv4 subnet. Configure scanner targets explicitly.")
    return detected


def should_enqueue_scheduled_scan(config: ScannerConfig, now: datetime | None = None) -> bool:
    if not config.enabled:
        return False
    if config.interval_minutes <= 0:
        return False
    if config.last_scheduled_scan_at is None:
        return True
    current_time = now or datetime.now(timezone.utc)
    return current_time >= config.last_scheduled_scan_at + timedelta(minutes=config.interval_minutes)


def has_meaningful_scan_evidence(result: HostScanResult) -> bool:
    if result.host.mac_address:
        return True
    if result.reverse_hostname:
        return True
    if result.mac_vendor:
        return True
    if result.open_ports:
        return True
    for probe in result.probes:
        if probe.success and probe.probe_type != "dns" and probe.data:
            return True
    if result.ai_analysis and result.ai_analysis.device_class.value != "unknown" and result.ai_analysis.confidence >= 0.7:
        return True
    return False


async def clear_inventory(
    db: AsyncSession,
    *,
    include_scan_history: bool,
    actor: User | None = None,
) -> dict[str, int]:
    assets_deleted = await db.scalar(select(func.count()).select_from(Asset)) or 0
    scans_deleted = 0

    await db.execute(delete(TopologyLink))
    await db.execute(delete(WirelessAssociation))
    await db.execute(delete(Finding))
    await db.execute(delete(ConfigBackupSnapshot))
    await db.execute(delete(ConfigBackupTarget))
    await db.execute(delete(AssetHistory))
    await db.execute(delete(Asset))

    if include_scan_history:
        scans_deleted = await db.scalar(select(func.count()).select_from(ScanJob)) or 0
        await db.execute(delete(ScanJob))

    await log_audit_event(
        db,
        action="inventory.reset",
        user=actor,
        target_type="inventory",
        details={"include_scan_history": include_scan_history, "assets_deleted": assets_deleted, "scans_deleted": scans_deleted},
    )
    await db.flush()

    return {"assets_deleted": assets_deleted, "scans_deleted": scans_deleted}
