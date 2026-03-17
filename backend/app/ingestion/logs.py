from __future__ import annotations

import re

from app.scanner.models import DiscoveredHost, HostScanResult

IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
MAC_PATTERN = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"

DNSMASQ_DHCP_RE = re.compile(
    rf"(?:dnsmasq(?:-dhcp)?\[\d+\]:\s*)?DHCPACK\([^)]+\)\s+"
    rf"(?P<ip>{IPV4_PATTERN})\s+(?P<mac>{MAC_PATTERN})(?:\s+(?P<hostname>\S+))?",
    re.IGNORECASE,
)
ISC_DHCP_RE = re.compile(
    rf"(?:dhcpd(?:\[\d+\])?:\s*)?DHCPACK on\s+"
    rf"(?P<ip>{IPV4_PATTERN})\s+to\s+(?P<mac>{MAC_PATTERN})(?:\s+\((?P<hostname>[^)]+)\))?",
    re.IGNORECASE,
)
DNSMASQ_REPLY_RE = re.compile(
    rf"(?:dnsmasq\[\d+\]:\s*)?reply\s+(?P<hostname>[A-Za-z0-9._-]+)\s+is\s+(?P<ip>{IPV4_PATTERN})",
    re.IGNORECASE,
)
DNSMASQ_LEASE_RE = re.compile(
    rf"^\d+\s+(?P<mac>{MAC_PATTERN})\s+(?P<ip>{IPV4_PATTERN})\s+(?P<hostname>\S+)\s+.*$",
    re.IGNORECASE,
)


def parse_dns_dhcp_logs(content: str) -> list[HostScanResult]:
    """Parse a few common DHCP/DNS log formats into lightweight host observations."""
    observations: dict[str, dict[str, str | None]] = {}

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = (
            DNSMASQ_DHCP_RE.search(line)
            or ISC_DHCP_RE.search(line)
            or DNSMASQ_REPLY_RE.search(line)
            or DNSMASQ_LEASE_RE.search(line)
        )
        if not match:
            continue

        ip = match.group("ip")
        hostname = _normalize_hostname(match.groupdict().get("hostname"))
        mac = _normalize_mac(match.groupdict().get("mac"))

        existing = observations.setdefault(ip, {"hostname": None, "mac": None})
        if hostname:
            existing["hostname"] = hostname
        if mac:
            existing["mac"] = mac

    results: list[HostScanResult] = []
    for ip, observation in observations.items():
        results.append(
            HostScanResult(
                host=DiscoveredHost(
                    ip_address=ip,
                    mac_address=observation["mac"],
                    discovery_method="log",
                ),
                reverse_hostname=observation["hostname"],
            )
        )
    return results


def _normalize_hostname(value: str | None) -> str | None:
    if not value or value == "*":
        return None
    hostname = value.strip()
    if hostname == "<unknown>":
        return None
    return hostname


def _normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower()
