"""
Pydantic models for the Argus scanner pipeline.

These are the internal data transfer objects that flow through each stage.
Think of them as typed envelopes: each pipeline stage stamps new information
onto the envelope and passes it forward.

DB models (SQLAlchemy) live in app/db/models.py — these scan models are
deliberately separate so the scanner can operate without a DB connection
(useful for testing and CLI usage).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ─── Enums ──────────────────────────────────────────────────────────────────

class ScanProfile(str, Enum):
    QUICK      = "quick"        # fast first-pass inventory with shallow scan depth
    BALANCED   = "balanced"     # -T4, top 1000, OS+version — default
    DEEP_ENRICHMENT = "deep_enrichment"  # deeper scan/probes for follow-up investigation
    CUSTOM     = "custom"       # caller supplies raw nmap_args


@dataclass(frozen=True, slots=True)
class ScanModeBehavior:
    nmap_args: str
    enable_ai_by_default: bool
    run_deep_probes: bool


LEGACY_SCAN_PROFILE_ALIASES: dict[str, ScanProfile] = {
    "polite": ScanProfile.QUICK,
    "aggressive": ScanProfile.DEEP_ENRICHMENT,
}


class DeviceClass(str, Enum):
    ROUTER         = "router"
    SWITCH         = "switch"
    ACCESS_POINT   = "access_point"
    FIREWALL       = "firewall"
    SERVER         = "server"
    WORKSTATION    = "workstation"
    NAS            = "nas"
    PRINTER        = "printer"
    IP_CAMERA      = "ip_camera"
    SMART_TV       = "smart_tv"
    IOT_DEVICE     = "iot_device"
    VOIP           = "voip"
    UNKNOWN        = "unknown"


NMAP_PROFILE_ARGS: dict[ScanProfile, str] = {
    # Quick — version detection on a small top-port set, no OS probing.
    ScanProfile.QUICK: (
        "-sV -T4 --top-ports 100 --host-timeout 20s"
    ),

    # Balanced — version detection + OS detection, but NO guessing.
    # --osscan-guess is intentionally omitted: it forces nmap to guess even at
    # 5-10% confidence, causing projector/printer fingerprints (e.g. the infamous
    # "Sanyo PLC-XU88 digital projector") to be applied to most IoT devices that
    # share similar minimal TCP/IP stacks. Trust only confident fingerprints.
    # -A already includes -sV and -O so we avoid doubling up.
    ScanProfile.BALANCED: (
        "-sV -O -T4 --top-ports 1000 --host-timeout 60s"
    ),

    # Deep enrichment — full port range, OS guessing enabled, and service scripts.
    ScanProfile.DEEP_ENRICHMENT: (
        "-A -T4 -p- --osscan-guess --script=default,safe,vuln --host-timeout 90s"
    ),
}


SCAN_MODE_BEHAVIORS: dict[ScanProfile, ScanModeBehavior] = {
    ScanProfile.QUICK: ScanModeBehavior(
        nmap_args=NMAP_PROFILE_ARGS[ScanProfile.QUICK],
        enable_ai_by_default=False,
        run_deep_probes=False,
    ),
    ScanProfile.BALANCED: ScanModeBehavior(
        nmap_args=NMAP_PROFILE_ARGS[ScanProfile.BALANCED],
        enable_ai_by_default=True,
        run_deep_probes=True,
    ),
    ScanProfile.DEEP_ENRICHMENT: ScanModeBehavior(
        nmap_args=NMAP_PROFILE_ARGS[ScanProfile.DEEP_ENRICHMENT],
        enable_ai_by_default=True,
        run_deep_probes=True,
    ),
    ScanProfile.CUSTOM: ScanModeBehavior(
        nmap_args=NMAP_PROFILE_ARGS[ScanProfile.BALANCED],
        enable_ai_by_default=True,
        run_deep_probes=True,
    ),
}


def get_scan_mode_behavior(profile: ScanProfile) -> ScanModeBehavior:
    return SCAN_MODE_BEHAVIORS.get(profile, SCAN_MODE_BEHAVIORS[ScanProfile.BALANCED])


# ─── Stage 1: Discovery ──────────────────────────────────────────────────────

class DiscoveredHost(BaseModel):
    ip_address: str
    mac_address: str | None = None
    is_up: bool = True
    response_time_ms: float | None = None
    discovery_method: str = "arp"           # arp | ping | syn | passive
    ttl: int | None = None                   # TTL can hint at OS family
    nmap_hostname: str | None = None         # hostname nmap resolved during scan


# ─── Stage 2: Port scan ──────────────────────────────────────────────────────

class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"                   # tcp | udp
    state: str = "open"                     # open | filtered | closed
    service: str | None = None              # nmap service name
    version: str | None = None              # version string
    product: str | None = None              # product name
    extra_info: str | None = None
    cpe: str | None = None                  # Common Platform Enumeration URI
    banner: str | None = None               # raw banner if grabbed


# ─── Stage 3: Fingerprint ────────────────────────────────────────────────────

class OSFingerprint(BaseModel):
    os_name: str | None = None
    os_family: str | None = None            # Linux | Windows | iOS | Android | etc.
    os_version: str | None = None
    os_accuracy: int | None = None          # nmap accuracy percent (0–100)
    device_type: str | None = None          # nmap device type hint
    cpe: list[str] = Field(default_factory=list)


# ─── Stage 4: Deep probes ────────────────────────────────────────────────────

class ProbeResult(BaseModel):
    probe_type: str                         # http | tls | ssh | snmp | mdns | upnp | smb
    target_port: int | None = None
    success: bool = False
    duration_ms: float | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    raw: str | None = None                  # raw response for agent to reason about
    error: str | None = None


# HTTP probe output
class HttpProbeData(BaseModel):
    url: str
    status_code: int | None = None
    server: str | None = None               # Server: header
    title: str | None = None               # <title> tag content
    powered_by: str | None = None          # X-Powered-By header
    auth_header: str | None = None         # WWW-Authenticate header
    content_type: str | None = None
    redirect_host: str | None = None
    favicon_hash: str | None = None
    detected_app: str | None = None
    redirects: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    body_snippet: str | None = None        # first 500 chars of body (for AI analysis)
    auth_required: bool = False
    interesting_paths: list[str] = Field(default_factory=list)  # /admin, /cgi-bin, etc.


# TLS probe output
class TlsProbeData(BaseModel):
    subject_cn: str | None = None
    subject_san: list[str] = Field(default_factory=list)
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    is_self_signed: bool = False
    fingerprint_sha256: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    cert_org: str | None = None            # Organization field — often reveals vendor


# SSH probe output
class SshProbeData(BaseModel):
    banner: str | None = None              # e.g. "SSH-2.0-OpenSSH_9.3"
    server_version: str | None = None
    kex_algorithms: list[str] = Field(default_factory=list)
    host_key_algorithms: list[str] = Field(default_factory=list)
    encryption_algorithms: list[str] = Field(default_factory=list)


# SNMP probe output
class SnmpProbeData(BaseModel):
    sys_descr: str | None = None           # Most informative: "Linux nas 5.15.0 ..."
    sys_name: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None
    sys_object_id: str | None = None
    arp_table: list[dict[str, Any]] = Field(default_factory=list)
    interfaces: list[dict[str, Any]] = Field(default_factory=list)
    neighbors: list[dict[str, Any]] = Field(default_factory=list)
    wireless_clients: list[dict[str, Any]] = Field(default_factory=list)


# mDNS probe output
class MdnsProbeData(BaseModel):
    services: list[dict[str, Any]] = Field(default_factory=list)
    # Each: {type, name, host, port, properties}
    # e.g. {type: "_smb._tcp", name: "MyNAS", host: "nas.local", port: 445, properties: {...}}


# UPnP probe output
class UpnpProbeData(BaseModel):
    friendly_name: str | None = None       # e.g. "NETGEAR Nighthawk R8000"
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    serial_number: str | None = None
    device_type: str | None = None
    udn: str | None = None                 # Unique Device Name
    presentation_url: str | None = None


# SMB probe output
class SmbProbeData(BaseModel):
    netbios_name: str | None = None
    workgroup: str | None = None
    os_string: str | None = None
    smb_version: str | None = None
    signing_required: bool | None = None
    shares: list[str] = Field(default_factory=list)
    has_guest_access: bool | None = None


# ─── Stage 5: AI Analysis ────────────────────────────────────────────────────

class SecurityFinding(BaseModel):
    severity: str                          # info | low | medium | high | critical
    title: str
    detail: str


class AIAnalysis(BaseModel):
    device_class: DeviceClass = DeviceClass.UNKNOWN
    confidence: float = 0.0               # 0.0–1.0
    vendor: str | None = None
    model: str | None = None
    os_guess: str | None = None
    device_role: str | None = None        # "internet gateway", "media server", etc.
    open_services_summary: list[str] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    investigation_notes: str = ""         # Human-readable narrative from the agent
    suggested_tags: list[str] = Field(default_factory=list)
    ai_backend: str = "none"              # ollama | anthropic | rule_based (fallback)
    model_used: str | None = None
    agent_steps: int = 0                  # How many tool calls the agent made


# ─── Final host result ───────────────────────────────────────────────────────

class HostScanResult(BaseModel):
    host: DiscoveredHost
    ports: list[PortResult] = Field(default_factory=list)
    os_fingerprint: OSFingerprint = Field(default_factory=OSFingerprint)
    mac_vendor: str | None = None
    reverse_hostname: str | None = None
    probes: list[ProbeResult] = Field(default_factory=list)
    ai_analysis: AIAnalysis | None = None
    scan_profile: ScanProfile = ScanProfile.BALANCED
    scan_duration_ms: float = 0.0
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def best_hostname(self) -> str:
        """Return the most descriptive name available for this host."""
        if self.ai_analysis and self.ai_analysis.model:
            return self.ai_analysis.model
        if self.reverse_hostname:
            return self.reverse_hostname
        return self.host.ip_address


# ─── Scan job summary ────────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    job_id: str
    targets: str
    profile: ScanProfile
    hosts_scanned: int = 0
    hosts_up: int = 0
    new_assets: int = 0
    changed_assets: int = 0
    offline_assets: int = 0
    total_open_ports: int = 0
    ai_analyses_completed: int = 0
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
