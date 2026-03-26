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


def test_balanced_profile_scans_well_known_ports(monkeypatch):
    fake = _FakePortScanner()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        None,
    )

    assert fake.arguments is not None
    assert "-p1-1023" in fake.arguments
    assert "--top-ports" not in fake.arguments


def test_deep_enrichment_scans_registered_ports(monkeypatch):
    fake = _FakePortScanner()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.DEEP_ENRICHMENT,
        None,
    )

    assert fake.arguments is not None
    assert "-p1-49151" in fake.arguments
    assert "--min-rate 1000" in fake.arguments
    assert "-A" not in fake.arguments.split()
    assert "--script=default,safe,vuln" not in fake.arguments
