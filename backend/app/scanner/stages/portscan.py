"""
Stage 2 — Port Scanning

Wraps nmap with profile-aware argument sets. For aggressive per-host
escalation (e.g. after the AI agent flags a device as interesting),
callers can override the profile or supply custom nmap_args.

Key design: scan a batch of hosts at once using nmap's multi-target
mode — far faster than one-host-at-a-time because nmap can parallelize
its own probes internally across the entire batch.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import nmap

from app.scanner.models import NMAP_PROFILE_ARGS, DiscoveredHost, OSFingerprint, PortResult, ScanProfile

log = logging.getLogger(__name__)

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
) -> tuple[list[PortResult], OSFingerprint]:
    """
    Scan a single host. Returns (ports, os_fingerprint).
    Used for targeted per-host scans (e.g. passive ARP discovery).
    """
    results = await scan_hosts([host], profile, custom_args)
    if results:
        ports, os_fp, _ = results[0]
        return ports, os_fp
    return [], OSFingerprint()


async def scan_hosts(
    hosts: list[DiscoveredHost],
    profile: ScanProfile = ScanProfile.BALANCED,
    custom_args: Optional[str] = None,
) -> list[tuple[list[PortResult], OSFingerprint, str]]:
    """
    Scan a list of hosts. Returns list of (ports, os_fingerprint, ip).
    Batches hosts into groups for efficiency.
    """
    if not hosts:
        return []

    loop = asyncio.get_event_loop()
    # Run nmap in thread executor — it's synchronous and CPU/IO bound
    return await loop.run_in_executor(
        None, _scan_sync, hosts, profile, custom_args
    )


def _scan_sync(
    hosts: list[DiscoveredHost],
    profile: ScanProfile,
    custom_args: Optional[str],
) -> list[tuple[list[PortResult], OSFingerprint, str]]:
    """Synchronous nmap scan — runs in thread executor."""
    target_str = " ".join(h.ip_address for h in hosts)
    args = custom_args or NMAP_PROFILE_ARGS.get(profile, NMAP_PROFILE_ARGS[ScanProfile.BALANCED])

    log.info("Port scan [%s] %d hosts | args: %s", profile.value, len(hosts), args)
    t0 = time.monotonic()

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_str, arguments=args)
    except Exception as exc:
        log.error("nmap scan failed: %s", exc)
        return []

    log.info("Port scan complete in %.1fs", time.monotonic() - t0)

    results = []
    for ip in nm.all_hosts():
        ports = _extract_ports(nm[ip])
        os_fp = _extract_os(nm[ip])
        results.append((ports, os_fp, ip))

    return results


def _extract_ports(host_data: dict) -> list[PortResult]:
    ports: list[PortResult] = []

    for proto in ("tcp", "udp"):
        proto_data = host_data.get(proto, {})
        for port_num, info in proto_data.items():
            state = info.get("state", "")
            if state not in ("open", "open|filtered"):
                continue

            # Build version string from nmap components
            parts = [info.get("product", ""), info.get("version", ""), info.get("extrainfo", "")]
            version_str = " ".join(p for p in parts if p).strip() or None

            # Collect any NSE script output as a banner
            scripts = info.get("script", {})
            banner_parts = []
            for script_name, output in scripts.items():
                if output and isinstance(output, str):
                    banner_parts.append(f"[{script_name}] {output[:300]}")
            banner = "\n".join(banner_parts) if banner_parts else None

            ports.append(PortResult(
                port=int(port_num),
                protocol=proto,
                state=state,
                service=info.get("name"),
                version=version_str,
                product=info.get("product"),
                extra_info=info.get("extrainfo"),
                cpe=_first_cpe(info.get("cpe")),
                banner=banner,
            ))

    # Sort by port number for consistent output
    ports.sort(key=lambda p: p.port)
    return ports


def _extract_os(host_data: dict) -> OSFingerprint:
    os_matches = host_data.get("osmatch", [])
    if not os_matches:
        return OSFingerprint()

    best = os_matches[0]
    osclass = best.get("osclass", [{}])[0] if best.get("osclass") else {}
    cpe_list = _flatten_cpes(best.get("osclass", []))

    return OSFingerprint(
        os_name=best.get("name"),
        os_family=osclass.get("osfamily"),
        os_version=osclass.get("osgen"),
        os_accuracy=int(best.get("accuracy", 0)) or None,
        device_type=osclass.get("type"),
        cpe=cpe_list,
    )


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
        if port.state == "open":
            port_nums.append(str(port.port))
            svc = (port.service or "").lower()
            for key, scripts in SERVICE_SCRIPTS.items():
                if key in svc or (key == "https" and port.port == 443) or (key == "http" and port.port == 80):
                    for s in scripts.split(","):
                        script_set.add(s.strip())

    if not script_set:
        return ""

    ports_arg = ",".join(sorted(set(port_nums)))
    scripts_arg = ",".join(sorted(script_set))
    return f"-sV -T4 -p {ports_arg} --script={scripts_arg}"
