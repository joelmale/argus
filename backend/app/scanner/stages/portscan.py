"""
Stage 2 — Port Scanning

Wraps nmap with profile-aware argument sets. For aggressive per-host
escalation (e.g. after the AI agent flags a device as interesting),
callers can override the profile or supply custom nmap_args.

Key design: scan a batch of hosts at once using nmap's multi-target
mode — far faster than one-host-at-a-time because nmap can parallelize
its own probes internally across the entire batch.

Return type for scan_hosts: list[tuple[list[PortResult], OSFingerprint, str, str|None, str|None]]
The extra elements are the nmap-resolved hostname and vendor hint, supplementing
reverse-DNS and OUI lookups in the pipeline.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import nmap

from app.scanner.models import DiscoveredHost, OSFingerprint, PortResult, ScanProfile, get_scan_mode_behavior

log = logging.getLogger(__name__)

# Minimum nmap OS-match accuracy (0–100) we will trust.
# --osscan-guess can return wild results at very low confidence — the infamous
# "Sanyo PLC-XU88 digital projector" fingerprint hits many IoT devices because
# they share similar minimal TCP/IP stacks. A threshold of 85 keeps only
# fingerprints that nmap itself is reasonably confident about.
_MIN_OS_ACCURACY = 85

# NSE scripts to run per service when in balanced/aggressive mode
SERVICE_SCRIPTS: dict[str, str] = {
    "http":    "http-title,http-headers,http-auth-finder,http-methods",
    "https":   "http-title,http-headers,ssl-cert,ssl-enum-ciphers",
    "ssh":     "ssh2-enum-algos,ssh-hostkey",
    "ftp":     "ftp-anon,ftp-syst",
    "smtp":    "smtp-commands,smtp-ntlm-info",
    "snmp":    "snmp-info,snmp-sysdescr",
    "smb":     "smb-os-discovery,smb-security-mode,smb2-security-mode",
    "rdp":     "rdp-enum-encryption",
    "telnet":  "telnet-ntlm-info",
    "mqtt":    "mqtt-subscribe",
    "upnp":    "upnp-info",
}

# Type alias for clarity
HostScanTuple = tuple[list[PortResult], OSFingerprint, str, str | None, str | None]
# (ports, os_fingerprint, ip_address, nmap_hostname, nmap_vendor)


def _first_cpe(value) -> str | None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
        return None
    if isinstance(value, str) and value:
        return value
    return None


def _flatten_cpes(items: list[dict]) -> list[str]:
    cpes: list[str] = []
    for item in items:
        value = item.get("cpe")
        if isinstance(value, list):
            cpes.extend(entry for entry in value if isinstance(entry, str) and entry)
        elif isinstance(value, str) and value:
            cpes.append(value)
    return cpes


async def scan_host(
    host: DiscoveredHost,
    profile: ScanProfile = ScanProfile.BALANCED,
    custom_args: Optional[str] = None,
    top_ports_count: int | None = None,
) -> tuple[list[PortResult], OSFingerprint]:
    """
    Scan a single host. Returns (ports, os_fingerprint).
    Used for targeted per-host scans (e.g. passive ARP discovery).
    """
    results = await scan_hosts([host], profile, custom_args, top_ports_count=top_ports_count)
    if results:
        ports, os_fp, _, nmap_hostname, _ = results[0]
        # Attach nmap hostname back onto the host object for callers that need it
        if nmap_hostname and not host.nmap_hostname:
            host.nmap_hostname = nmap_hostname
        return ports, os_fp
    return [], OSFingerprint()


async def scan_hosts(
    hosts: list[DiscoveredHost],
    profile: ScanProfile = ScanProfile.BALANCED,
    custom_args: Optional[str] = None,
    top_ports_count: int | None = None,
) -> list[HostScanTuple]:
    """
    Scan a list of hosts.
    Returns list of (ports, os_fingerprint, ip_address, nmap_hostname, nmap_vendor).
    The nmap_hostname is whatever nmap resolved via forward/reverse DNS
    during its scan — a useful supplement to our own reverse-DNS lookup.
    """
    if not hosts:
        return []

    loop = asyncio.get_event_loop()
    # Run nmap in thread executor — it's synchronous and CPU/IO bound
    return await loop.run_in_executor(
        None,
        _scan_sync,
        hosts,
        profile,
        custom_args,
        top_ports_count,
    )


def _scan_sync(
    hosts: list[DiscoveredHost],
    profile: ScanProfile,
    custom_args: Optional[str],
    top_ports_count: int | None = None,
) -> list[HostScanTuple]:
    """Synchronous nmap scan — runs in thread executor."""
    from app.scanner.enrichment.instant_win import fingerprint_from_nmap_host_data, merge_into_os_fingerprint

    target_str = " ".join(h.ip_address for h in hosts)
    mode_behavior = get_scan_mode_behavior(profile, top_ports_count=top_ports_count)
    base_args = custom_args or mode_behavior.nmap_args
    args = base_args if "-Pn" in base_args.split() else f"-Pn {base_args}"

    log.info("Port scan [%s] %d hosts | args: %s", profile.value, len(hosts), args)
    t0 = time.monotonic()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_str, arguments=args)
    except Exception as exc:
        log.error("nmap scan failed: %s", exc)
        return []

    log.info("Port scan complete in %.1fs", time.monotonic() - t0)

    results: list[HostScanTuple] = []
    host_map = {host.ip_address: host for host in hosts}
    for ip in nm.all_hosts():
        host_data = nm[ip]
        ports = _extract_ports(host_data)
        os_fp = _extract_os(host_data)
        nm_hostname = _extract_hostname(host_data)
        nmap_mac, nmap_vendor = _extract_mac_and_vendor(host_data)
        if not ports:
            log.warning(
                "No open ports parsed for %s using args '%s' | protocols=%s | state_summary=%s | status=%s",
                ip,
                args,
                _protocol_keys(host_data),
                _protocol_state_summary(host_data),
                host_data.get("status", {}),
            )
        instant = fingerprint_from_nmap_host_data(host_data)
        os_fp = merge_into_os_fingerprint(os_fp, instant)
        resolved_vendor = instant.vendor if instant is not None and instant.vendor else nmap_vendor

        source_host = host_map.get(ip)
        if source_host is not None and nmap_mac and not source_host.mac_address:
            source_host.mac_address = nmap_mac
        if source_host is not None and nm_hostname and not source_host.nmap_hostname:
            source_host.nmap_hostname = nm_hostname

        results.append((ports, os_fp, ip, nm_hostname, resolved_vendor))

    return results


def _extract_ports(host_data: dict) -> list[PortResult]:
    ports: list[PortResult] = []

    for proto, port_num, info in _iter_open_ports(host_data):
        ports.append(PortResult(
            port=int(port_num),
            protocol=proto,
            state=info.get("state", ""),
            service=info.get("name"),
            version=_build_version_string(info),
            product=info.get("product"),
            extra_info=info.get("extrainfo"),
            cpe=_first_cpe(info.get("cpe")),
            banner=_build_script_banner(info.get("script", {})),
        ))

    # Sort by port number for consistent output
    ports.sort(key=lambda p: p.port)
    return ports


def _iter_open_ports(host_data: dict):
    for proto in ("tcp", "udp"):
        proto_data = host_data.get(proto, {})
        for port_num, info in proto_data.items():
            if info.get("state", "") in ("open", "open|filtered"):
                yield proto, port_num, info


def _protocol_keys(host_data: dict) -> list[str]:
    return sorted(key for key, value in host_data.items() if isinstance(value, dict) and key in {"tcp", "udp", "sctp"})


def _protocol_state_summary(host_data: dict) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for proto in ("tcp", "udp", "sctp"):
        proto_data = host_data.get(proto, {})
        if not isinstance(proto_data, dict) or not proto_data:
            continue
        counts: dict[str, int] = {}
        for info in proto_data.values():
            if not isinstance(info, dict):
                continue
            state = info.get("state", "unknown")
            counts[state] = counts.get(state, 0) + 1
        if counts:
            summary[proto] = counts
    return summary


def _build_version_string(info: dict) -> str | None:
    parts = [info.get("product", ""), info.get("version", ""), info.get("extrainfo", "")]
    return " ".join(part for part in parts if part).strip() or None


def _build_script_banner(scripts: dict) -> str | None:
    banner_parts = []
    for script_name, output in scripts.items():
        if output and isinstance(output, str):
            banner_parts.append(f"[{script_name}] {output[:300]}")
    return "\n".join(banner_parts) if banner_parts else None


def _extract_os(host_data: dict) -> OSFingerprint:
    """
    Extract OS fingerprint from nmap host data.

    Enforces a minimum accuracy threshold (_MIN_OS_ACCURACY) to avoid
    low-confidence guesses poisoning the database. When nmap assigns 40%
    confidence to "Sanyo PLC-XU88 digital projector" for a Raspberry Pi,
    we return an empty fingerprint rather than propagate the wrong answer.
    """
    os_matches = host_data.get("osmatch", [])
    if not os_matches:
        return OSFingerprint()

    best = os_matches[0]
    accuracy = int(best.get("accuracy", 0))

    if accuracy < _MIN_OS_ACCURACY:
        log.debug(
            "OS match '%s' rejected: accuracy %d%% < threshold %d%%",
            best.get("name", "?"), accuracy, _MIN_OS_ACCURACY,
        )
        return OSFingerprint()

    osclass  = best.get("osclass", [{}])[0] if best.get("osclass") else {}
    cpe_list = _flatten_cpes(best.get("osclass", []))

    return OSFingerprint(
        os_name=best.get("name"),
        os_family=osclass.get("osfamily"),
        os_version=osclass.get("osgen"),
        os_accuracy=accuracy,
        device_type=osclass.get("type"),
        cpe=cpe_list,
    )


def _extract_hostname(host_data: dict) -> str | None:
    """
    Extract the best hostname nmap resolved during scanning.

    nmap stores hostnames in host_data["hostnames"] as a list of dicts like:
      [{"name": "router.local", "type": "PTR"}, {"name": "myrouter", "type": "user"}]

    We prefer "user" type (explicitly given) over "PTR" (reverse DNS) and
    skip entries that are just the IP address in arpa notation.
    """
    entries: list[dict] = host_data.get("hostnames", [])
    if not entries:
        return None

    # Prefer "user"-typed entries, then any non-empty non-arpa name
    for type_pref in ("user", "PTR", ""):
        for entry in entries:
            name = (entry.get("name") or "").strip()
            etype = entry.get("type", "")
            if not _is_usable_hostname(name):
                continue
            if type_pref == "" or etype == type_pref:
                return name

    return None


def _is_usable_hostname(name: str) -> bool:
    if not name:
        return False
    return not (name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"))


def _extract_mac_and_vendor(host_data: dict) -> tuple[str | None, str | None]:
    addresses = host_data.get("addresses", {})
    mac = addresses.get("mac")

    vendor_data = host_data.get("vendor", {})
    vendor = None
    if isinstance(vendor_data, dict):
        if mac and mac in vendor_data and vendor_data.get(mac):
            vendor = str(vendor_data[mac])
        else:
            for value in vendor_data.values():
                if value:
                    vendor = str(value)
                    break
    return mac, vendor


def build_escalated_args(ports: list[PortResult]) -> str:
    """
    Build targeted NSE script arguments based on detected services.
    Used for selective escalation — run only relevant scripts, not everything.

    This is the "selectively aggressive" mode: we already know what's open,
    so we target our deep probes precisely rather than brute-forcing all scripts.
    """
    script_set: set[str] = set()
    port_nums: list[str] = []

    for port in ports:
        if port.state != "open":
            continue
        port_nums.append(str(port.port))
        script_set.update(_service_scripts_for_port(port))

    if not script_set:
        return ""

    ports_arg = ",".join(sorted(set(port_nums)))
    scripts_arg = ",".join(sorted(script_set))
    return f"-sV -T4 -p {ports_arg} --script={scripts_arg}"


def _service_scripts_for_port(port: PortResult) -> set[str]:
    scripts: set[str] = set()
    svc = (port.service or "").lower()
    for key, service_scripts in SERVICE_SCRIPTS.items():
        if key in svc or (key == "https" and port.port == 443) or (key == "http" and port.port == 80):
            scripts.update(script.strip() for script in service_scripts.split(","))
    return scripts
