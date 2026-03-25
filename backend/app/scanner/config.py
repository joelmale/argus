from __future__ import annotations

import ipaddress
import fcntl
import socket
import struct
from collections.abc import Iterable
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
    scheduled_scans_enabled: bool
    default_targets: str | None
    auto_detect_targets: bool
    detected_targets: str | None
    effective_targets: str | None
    default_profile: str
    interval_minutes: int
    concurrent_hosts: int
    host_chunk_size: int
    top_ports_count: int
    deep_probe_timeout_seconds: int
    ai_after_scan_enabled: bool
    ai_backend: str
    ai_model: str
    fingerprint_ai_backend: str
    ollama_base_url: str
    openai_base_url: str
    openai_api_key: str
    anthropic_api_key: str
    passive_arp_enabled: bool
    passive_arp_interface: str
    snmp_enabled: bool
    snmp_version: str
    snmp_community: str
    snmp_timeout: int
    snmp_v3_username: str
    snmp_v3_auth_key: str
    snmp_v3_priv_key: str
    snmp_v3_auth_protocol: str
    snmp_v3_priv_protocol: str
    fingerprint_ai_enabled: bool
    fingerprint_ai_model: str
    fingerprint_ai_min_confidence: float
    fingerprint_ai_prompt_suffix: str | None
    internet_lookup_enabled: bool
    internet_lookup_allowed_domains: str | None
    internet_lookup_budget: int
    internet_lookup_timeout_seconds: int
    last_scheduled_scan_at: datetime | None
    next_scheduled_scan_at: datetime | None


@dataclass(slots=True)
class ScannerConfigUpdateInput:
    enabled: bool
    scheduled_scans_enabled: bool
    default_targets: str | None
    auto_detect_targets: bool
    default_profile: str
    interval_minutes: int
    concurrent_hosts: int
    host_chunk_size: int
    top_ports_count: int
    deep_probe_timeout_seconds: int
    ai_after_scan_enabled: bool
    ai_backend: str
    ai_model: str | None
    fingerprint_ai_backend: str
    ollama_base_url: str | None
    openai_base_url: str | None
    openai_api_key: str | None
    anthropic_api_key: str | None
    passive_arp_enabled: bool
    passive_arp_interface: str
    snmp_enabled: bool
    snmp_version: str
    snmp_community: str | None
    snmp_timeout: int
    snmp_v3_username: str | None
    snmp_v3_auth_key: str | None
    snmp_v3_priv_key: str | None
    snmp_v3_auth_protocol: str
    snmp_v3_priv_protocol: str
    fingerprint_ai_enabled: bool
    fingerprint_ai_model: str | None
    fingerprint_ai_min_confidence: float
    fingerprint_ai_prompt_suffix: str | None
    internet_lookup_enabled: bool
    internet_lookup_allowed_domains: str | None
    internet_lookup_budget: int
    internet_lookup_timeout_seconds: int


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
                network = _default_route_network(line)
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


def _iter_ipv4_route_networks() -> list[ipaddress.IPv4Network]:
    routes: list[ipaddress.IPv4Network] = []
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as handle:
            next(handle, None)
            for line in handle:
                fields = line.strip().split()
                if len(fields) < 8:
                    continue
                iface, destination_hex, _, flags_hex, _, _, _, mask_hex = fields[:8]
                if iface.startswith(_IGNORED_INTERFACE_PREFIXES):
                    continue
                try:
                    flags = int(flags_hex, 16)
                except ValueError:
                    continue
                # RTF_UP
                if not flags & 0x1:
                    continue
                try:
                    destination = socket.inet_ntoa(struct.pack("<L", int(destination_hex, 16)))
                    mask = socket.inet_ntoa(struct.pack("<L", int(mask_hex, 16)))
                    network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
                except (OSError, ValueError):
                    continue
                routes.append(network)
    except OSError:
        pass

    return routes


def validate_scan_targets_routable(targets: str) -> str | None:
    """Return an actionable error when scan targets are not routable from this host."""
    route_networks = _iter_ipv4_route_networks()
    if not route_networks:
        return None

    unresolved = [candidate for candidate in _iter_target_tokens(targets) if not _target_is_routable(candidate, route_networks)]

    if not unresolved:
        return None

    known_routes = ", ".join(str(route) for route in route_networks[:6])
    suffix = " ..." if len(route_networks) > 6 else ""
    invalid_targets = ", ".join(unresolved)
    environment_hint = ""
    if any(str(route) == "192.168.65.0/24" for route in route_networks):
        environment_hint = (
            " The scanner appears to be running inside Docker Desktop and only sees the Docker VM subnet. "
            "Use a range reachable from the scanner host, or move the scanner onto a host/network with LAN access."
        )
    return (
        f"Scan targets are not routable from the scanner host: {invalid_targets}. "
        f"Known IPv4 routes: {known_routes}{suffix}. "
        f"Update the scanner target range in Settings or fix scanner host networking.{environment_hint}"
    )


def split_scan_targets(
    targets: str,
    *,
    max_network_prefix: int = 24,
    max_ip_group_size: int = 256,
) -> list[str]:
    chunks: list[str] = []
    ip_group: list[str] = []
    for token in _iter_target_tokens(targets):
        ip_group = _append_split_target(
            chunks,
            ip_group,
            token,
            max_network_prefix=max_network_prefix,
            max_ip_group_size=max_ip_group_size,
        )

    if ip_group:
        chunks.append(" ".join(ip_group))
    return chunks or [targets]


def _default_route_network(route_line: str) -> str | None:
    fields = route_line.strip().split()
    if len(fields) < 11:
        return None
    iface, destination, _, flags = fields[:4]
    if destination != "00000000":
        return None
    try:
        if not int(flags, 16) & 0x2:
            return None
    except ValueError:
        return None
    if iface.startswith(_IGNORED_INTERFACE_PREFIXES):
        return None
    return _get_ipv4_network(iface)


def _target_is_routable(candidate: str, route_networks: list[ipaddress.IPv4Network]) -> bool:
    try:
        target_network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return any(route.prefixlen == 0 or target_network.subnet_of(route) for route in route_networks)


def _append_split_target(
    chunks: list[str],
    ip_group: list[str],
    token: str,
    *,
    max_network_prefix: int,
    max_ip_group_size: int,
) -> list[str]:
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return _append_ip_group(chunks, ip_group, token, max_ip_group_size)

    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < max_network_prefix:
        if ip_group:
            chunks.append(" ".join(ip_group))
        chunks.extend(str(subnet) for subnet in network.subnets(new_prefix=max_network_prefix))
        return []

    return _append_ip_group(chunks, ip_group, str(network), max_ip_group_size)


def _append_ip_group(chunks: list[str], ip_group: list[str], value: str, max_ip_group_size: int) -> list[str]:
    ip_group.append(value)
    if len(ip_group) < max_ip_group_size:
        return ip_group
    chunks.append(" ".join(ip_group))
    return []


def _iter_target_tokens(targets: str) -> Iterable[str]:
    for token in targets.replace(",", " ").split():
        candidate = token.strip()
        if candidate:
            yield candidate


def _bootstrap_targets_from_env() -> tuple[str | None, bool]:
    configured = (settings.SCANNER_DEFAULT_TARGETS or "").strip()
    if configured and configured != DEFAULT_TARGET_PLACEHOLDER:
        return configured, False
    return None, True


def _normalize_ai_backend(value: str | None, default: str) -> str:
    normalized = (value or default).strip().lower()
    if normalized not in {"none", "ollama", "openai", "anthropic"}:
        return default
    return normalized


def _default_model_for_backend(backend: str) -> str:
    if backend == "anthropic":
        return settings.ANTHROPIC_MODEL
    if backend == "openai":
        return settings.OPENAI_MODEL
    return settings.OLLAMA_MODEL


async def get_or_create_scanner_config(db: AsyncSession) -> ScannerConfig:
    config = (await db.execute(select(ScannerConfig).limit(1))).scalar_one_or_none()
    if config is not None:
        return config

    default_targets, auto_detect_targets = _bootstrap_targets_from_env()
    config = ScannerConfig(
        enabled=True,
        scheduled_scans_enabled=False,
        default_targets=default_targets,
        auto_detect_targets=auto_detect_targets,
        default_profile=settings.SCANNER_DEFAULT_PROFILE,
        interval_minutes=settings.SCANNER_INTERVAL_MINUTES,
        concurrent_hosts=settings.SCANNER_CONCURRENT_HOSTS,
        host_chunk_size=64,
        top_ports_count=1000,
        deep_probe_timeout_seconds=6,
        ai_after_scan_enabled=settings.AI_ENABLE_PER_SCAN,
        ai_backend=_normalize_ai_backend(settings.AI_BACKEND, "ollama"),
        ai_model=_default_model_for_backend(_normalize_ai_backend(settings.AI_BACKEND, "ollama")),
        fingerprint_ai_backend="ollama",
        ollama_base_url=settings.OLLAMA_BASE_URL,
        openai_base_url=settings.OPENAI_BASE_URL,
        openai_api_key=settings.OPENAI_API_KEY,
        anthropic_api_key=settings.ANTHROPIC_API_KEY,
        passive_arp_enabled=settings.SCANNER_PASSIVE_ARP,
        passive_arp_interface=settings.SCANNER_PASSIVE_ARP_INTERFACE,
        snmp_enabled=True,
        snmp_version=settings.SNMP_VERSION,
        snmp_community=settings.SNMP_COMMUNITY,
        snmp_timeout=settings.SNMP_TIMEOUT,
        snmp_v3_username=settings.SNMP_V3_USERNAME,
        snmp_v3_auth_key=settings.SNMP_V3_AUTH_KEY,
        snmp_v3_priv_key=settings.SNMP_V3_PRIV_KEY,
        snmp_v3_auth_protocol=settings.SNMP_V3_AUTH_PROTOCOL,
        snmp_v3_priv_protocol=settings.SNMP_V3_PRIV_PROTOCOL,
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
    ai_backend = _normalize_ai_backend(config.ai_backend, _normalize_ai_backend(settings.AI_BACKEND, "ollama"))
    fingerprint_ai_backend = _normalize_ai_backend(config.fingerprint_ai_backend, ai_backend)
    return EffectiveScannerConfig(
        enabled=config.enabled,
        scheduled_scans_enabled=config.scheduled_scans_enabled,
        default_targets=config.default_targets,
        auto_detect_targets=config.auto_detect_targets,
        detected_targets=detected_targets,
        effective_targets=effective_targets,
        default_profile=config.default_profile,
        interval_minutes=config.interval_minutes,
        concurrent_hosts=config.concurrent_hosts,
        host_chunk_size=config.host_chunk_size,
        top_ports_count=config.top_ports_count,
        deep_probe_timeout_seconds=config.deep_probe_timeout_seconds,
        ai_after_scan_enabled=config.ai_after_scan_enabled,
        ai_backend=ai_backend,
        ai_model=(config.ai_model or _default_model_for_backend(ai_backend)),
        fingerprint_ai_backend=fingerprint_ai_backend,
        ollama_base_url=config.ollama_base_url or settings.OLLAMA_BASE_URL,
        openai_base_url=config.openai_base_url or settings.OPENAI_BASE_URL,
        openai_api_key=config.openai_api_key or settings.OPENAI_API_KEY,
        anthropic_api_key=config.anthropic_api_key or settings.ANTHROPIC_API_KEY,
        passive_arp_enabled=config.passive_arp_enabled,
        passive_arp_interface=config.passive_arp_interface,
        snmp_enabled=config.snmp_enabled,
        snmp_version=config.snmp_version,
        snmp_community=config.snmp_community,
        snmp_timeout=config.snmp_timeout,
        snmp_v3_username=config.snmp_v3_username or "",
        snmp_v3_auth_key=config.snmp_v3_auth_key or "",
        snmp_v3_priv_key=config.snmp_v3_priv_key or "",
        snmp_v3_auth_protocol=config.snmp_v3_auth_protocol,
        snmp_v3_priv_protocol=config.snmp_v3_priv_protocol,
        fingerprint_ai_enabled=config.fingerprint_ai_enabled,
        fingerprint_ai_model=config.fingerprint_ai_model or _default_model_for_backend(fingerprint_ai_backend),
        fingerprint_ai_min_confidence=config.fingerprint_ai_min_confidence,
        fingerprint_ai_prompt_suffix=config.fingerprint_ai_prompt_suffix,
        internet_lookup_enabled=config.internet_lookup_enabled,
        internet_lookup_allowed_domains=config.internet_lookup_allowed_domains,
        internet_lookup_budget=config.internet_lookup_budget,
        internet_lookup_timeout_seconds=config.internet_lookup_timeout_seconds,
        last_scheduled_scan_at=config.last_scheduled_scan_at,
        next_scheduled_scan_at=compute_next_scheduled_scan_at(config),
    )


async def read_effective_scanner_config(db: AsyncSession) -> tuple[ScannerConfig, EffectiveScannerConfig]:
    config = await get_or_create_scanner_config(db)
    return config, build_effective_scanner_config(config)


async def update_scanner_config(
    db: AsyncSession,
    payload: ScannerConfigUpdateInput,
) -> tuple[ScannerConfig, EffectiveScannerConfig]:
    normalized_targets = _normalize_optional_text(payload.default_targets)
    if not payload.auto_detect_targets and not normalized_targets:
        raise ValueError("Explicit scanner targets are required when auto-detect is disabled.")

    config = await get_or_create_scanner_config(db)
    _apply_core_scanner_settings(
        config,
        enabled=payload.enabled,
        scheduled_scans_enabled=payload.scheduled_scans_enabled,
        normalized_targets=normalized_targets,
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
    )
    _apply_snmp_settings(
        config,
        snmp_enabled=payload.snmp_enabled,
        snmp_version=payload.snmp_version,
        snmp_community=payload.snmp_community,
        snmp_timeout=payload.snmp_timeout,
        snmp_v3_username=payload.snmp_v3_username,
        snmp_v3_auth_key=payload.snmp_v3_auth_key,
        snmp_v3_priv_key=payload.snmp_v3_priv_key,
        snmp_v3_auth_protocol=payload.snmp_v3_auth_protocol,
        snmp_v3_priv_protocol=payload.snmp_v3_priv_protocol,
    )
    _apply_ai_and_lookup_settings(
        config,
        fingerprint_ai_enabled=payload.fingerprint_ai_enabled,
        fingerprint_ai_model=payload.fingerprint_ai_model,
        fingerprint_ai_min_confidence=payload.fingerprint_ai_min_confidence,
        fingerprint_ai_prompt_suffix=payload.fingerprint_ai_prompt_suffix,
        internet_lookup_enabled=payload.internet_lookup_enabled,
        internet_lookup_allowed_domains=payload.internet_lookup_allowed_domains,
        internet_lookup_budget=payload.internet_lookup_budget,
        internet_lookup_timeout_seconds=payload.internet_lookup_timeout_seconds,
    )
    await db.flush()
    return config, build_effective_scanner_config(config)


def _normalize_optional_text(value: str | None) -> str | None:
    normalized = (value or "").strip()
    return normalized or None


def _apply_core_scanner_settings(
    config: ScannerConfig,
    *,
    enabled: bool,
    scheduled_scans_enabled: bool,
    normalized_targets: str | None,
    auto_detect_targets: bool,
    default_profile: str,
    interval_minutes: int,
    concurrent_hosts: int,
    host_chunk_size: int,
    top_ports_count: int,
    deep_probe_timeout_seconds: int,
    ai_after_scan_enabled: bool,
    ai_backend: str,
    ai_model: str | None,
    fingerprint_ai_backend: str,
    ollama_base_url: str | None,
    openai_base_url: str | None,
    openai_api_key: str | None,
    anthropic_api_key: str | None,
    passive_arp_enabled: bool,
    passive_arp_interface: str,
) -> None:
    config.enabled = enabled
    config.scheduled_scans_enabled = scheduled_scans_enabled
    config.default_targets = normalized_targets
    config.auto_detect_targets = auto_detect_targets
    config.default_profile = default_profile
    config.interval_minutes = interval_minutes
    config.concurrent_hosts = concurrent_hosts
    config.host_chunk_size = max(1, min(256, host_chunk_size))
    config.top_ports_count = max(10, min(65535, top_ports_count))
    config.deep_probe_timeout_seconds = max(1, min(30, deep_probe_timeout_seconds))
    config.ai_after_scan_enabled = ai_after_scan_enabled
    normalized_ai_backend = _normalize_ai_backend(ai_backend, _normalize_ai_backend(settings.AI_BACKEND, "ollama"))
    normalized_fingerprint_backend = _normalize_ai_backend(fingerprint_ai_backend, normalized_ai_backend)
    config.ai_backend = normalized_ai_backend
    config.ai_model = _normalize_optional_text(ai_model) or _default_model_for_backend(normalized_ai_backend)
    config.fingerprint_ai_backend = normalized_fingerprint_backend
    config.ollama_base_url = _normalize_optional_text(ollama_base_url) or settings.OLLAMA_BASE_URL
    config.openai_base_url = _normalize_optional_text(openai_base_url) or settings.OPENAI_BASE_URL
    config.openai_api_key = _normalize_optional_text(openai_api_key)
    config.anthropic_api_key = _normalize_optional_text(anthropic_api_key)
    config.passive_arp_enabled = passive_arp_enabled
    config.passive_arp_interface = _normalize_optional_text(passive_arp_interface) or settings.SCANNER_PASSIVE_ARP_INTERFACE


def _apply_snmp_settings(
    config: ScannerConfig,
    *,
    snmp_enabled: bool,
    snmp_version: str,
    snmp_community: str | None,
    snmp_timeout: int,
    snmp_v3_username: str | None,
    snmp_v3_auth_key: str | None,
    snmp_v3_priv_key: str | None,
    snmp_v3_auth_protocol: str,
    snmp_v3_priv_protocol: str,
) -> None:
    config.snmp_enabled = snmp_enabled
    config.snmp_version = (snmp_version or "2c").lower()
    config.snmp_community = _normalize_optional_text(snmp_community) or settings.SNMP_COMMUNITY
    config.snmp_timeout = max(1, snmp_timeout)
    config.snmp_v3_username = _normalize_optional_text(snmp_v3_username)
    config.snmp_v3_auth_key = _normalize_optional_text(snmp_v3_auth_key)
    config.snmp_v3_priv_key = _normalize_optional_text(snmp_v3_priv_key)
    config.snmp_v3_auth_protocol = (snmp_v3_auth_protocol or "sha").lower()
    config.snmp_v3_priv_protocol = (snmp_v3_priv_protocol or "aes").lower()


def _apply_ai_and_lookup_settings(
    config: ScannerConfig,
    *,
    fingerprint_ai_enabled: bool,
    fingerprint_ai_model: str | None,
    fingerprint_ai_min_confidence: float,
    fingerprint_ai_prompt_suffix: str | None,
    internet_lookup_enabled: bool,
    internet_lookup_allowed_domains: str | None,
    internet_lookup_budget: int,
    internet_lookup_timeout_seconds: int,
) -> None:
    config.fingerprint_ai_enabled = fingerprint_ai_enabled
    config.fingerprint_ai_model = _normalize_optional_text(fingerprint_ai_model) or _default_model_for_backend(config.fingerprint_ai_backend)
    config.fingerprint_ai_min_confidence = max(0.0, min(1.0, fingerprint_ai_min_confidence))
    config.fingerprint_ai_prompt_suffix = _normalize_optional_text(fingerprint_ai_prompt_suffix)
    config.internet_lookup_enabled = internet_lookup_enabled
    config.internet_lookup_allowed_domains = _normalize_optional_text(internet_lookup_allowed_domains)
    config.internet_lookup_budget = max(1, internet_lookup_budget)
    config.internet_lookup_timeout_seconds = max(1, internet_lookup_timeout_seconds)


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


def compute_next_scheduled_scan_at(config: ScannerConfig, now: datetime | None = None) -> datetime | None:
    if not config.scheduled_scans_enabled:
        return None
    if config.interval_minutes <= 0:
        return None
    if config.last_scheduled_scan_at is None:
        return now or datetime.now(timezone.utc)
    return config.last_scheduled_scan_at + timedelta(minutes=config.interval_minutes)


def should_enqueue_scheduled_scan(config: ScannerConfig, now: datetime | None = None) -> bool:
    if not config.scheduled_scans_enabled:
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
