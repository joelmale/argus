"""
Active network discovery via nmap.

Analogy: nmap is like sending out a fleet of messengers to knock on every door
in a neighborhood. This module orchestrates those messengers, collects their
reports, and translates them into Asset records.
"""
import nmap
from datetime import datetime, timezone

from app.core.config import settings


class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, targets: str, args: str | None = None) -> list[dict]:
        """
        Run an nmap scan against `targets` (CIDR or space-separated IPs).
        Returns a list of normalized host dicts ready for upsert into the DB.
        """
        scan_args = args or settings.SCANNER_NMAP_ARGS
        self.nm.scan(hosts=targets, arguments=scan_args)

        results = []
        for host in self.nm.all_hosts():
            host_data = self.nm[host]
            results.append(self._normalize(host, host_data))
        return results

    def _normalize(self, ip: str, data: dict) -> dict:
        """Map raw nmap output to our internal schema."""
        hostnames = data.get("hostnames", [])
        hostname = hostnames[0].get("name") if hostnames else None

        os_matches = data.get("osmatch", [])
        os_name = os_matches[0].get("name") if os_matches else None
        os_version = os_matches[0].get("osclass", [{}])[0].get("osgen") if os_matches else None

        ports = []
        for proto in data.get("tcp", {}), data.get("udp", {}):
            for port_num, port_data in (proto or {}).items():
                ports.append({
                    "port_number": int(port_num),
                    "protocol": "tcp" if port_num in data.get("tcp", {}) else "udp",
                    "service": port_data.get("name"),
                    "version": f"{port_data.get('product','')} {port_data.get('version','')}".strip(),
                    "state": port_data.get("state", "open"),
                })

        return {
            "ip_address": ip,
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version,
            "status": "online" if data.get("status", {}).get("state") == "up" else "offline",
            "ports": ports,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
