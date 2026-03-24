from __future__ import annotations

from app.scanner.models import DiscoveredHost, ScanProfile
from app.scanner.stages import portscan


class _FakePortScanner:
    def __init__(self):
        self.arguments = None
        self.hosts = None

    def scan(self, hosts: str, arguments: str):
        self.hosts = hosts
        self.arguments = arguments

    def all_hosts(self):
        return []


def test_portscan_forces_pn_for_discovered_hosts(monkeypatch):
    fake = _FakePortScanner()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        None,
    )

    assert fake.hosts == "192.168.100.4"
    assert fake.arguments is not None
    assert "-Pn" in fake.arguments.split()


def test_portscan_does_not_duplicate_pn(monkeypatch):
    fake = _FakePortScanner()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        "-Pn -sV -T4",
    )

    assert fake.arguments is not None
    assert fake.arguments.split().count("-Pn") == 1
