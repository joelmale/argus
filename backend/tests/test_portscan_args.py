from __future__ import annotations

from app.scanner.models import DiscoveredHost, ScanProfile
from app.scanner.stages import portscan


EMPTY_XML = """\
<nmaprun>
  <host>
    <status state="up" reason="arp-response" />
    <address addr="192.168.100.4" addrtype="ipv4" />
  </host>
</nmaprun>
"""


def test_portscan_forces_pn_for_discovered_hosts(monkeypatch):
    captured: dict[str, str] = {}

    def fake_run(targets: str, arguments: str):
        captured["targets"] = targets
        captured["arguments"] = arguments
        return EMPTY_XML

    monkeypatch.setattr(portscan, "_run_nmap_xml_scan", fake_run)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        None,
    )

    assert captured["targets"] == "192.168.100.4"
    assert "-Pn" in captured["arguments"].split()


def test_portscan_does_not_duplicate_pn(monkeypatch):
    captured: dict[str, str] = {}

    def fake_run(targets: str, arguments: str):
        captured["targets"] = targets
        captured["arguments"] = arguments
        return EMPTY_XML

    monkeypatch.setattr(portscan, "_run_nmap_xml_scan", fake_run)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        "-Pn -sV -T4",
    )

    assert captured["arguments"].split().count("-Pn") == 1


def test_balanced_profile_scans_well_known_ports(monkeypatch):
    captured: dict[str, str] = {}

    def fake_run(targets: str, arguments: str):
        captured["targets"] = targets
        captured["arguments"] = arguments
        return EMPTY_XML

    monkeypatch.setattr(portscan, "_run_nmap_xml_scan", fake_run)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.BALANCED,
        None,
    )

    assert "-p1-1023" in captured["arguments"]
    assert "--top-ports" not in captured["arguments"]


def test_deep_enrichment_scans_registered_ports(monkeypatch):
    captured: dict[str, str] = {}

    def fake_run(targets: str, arguments: str):
        captured["targets"] = targets
        captured["arguments"] = arguments
        return EMPTY_XML

    monkeypatch.setattr(portscan, "_run_nmap_xml_scan", fake_run)

    portscan._scan_sync(
        [DiscoveredHost(ip_address="192.168.100.4", discovery_method="arp")],
        ScanProfile.DEEP_ENRICHMENT,
        None,
    )

    assert "-p1-49151" in captured["arguments"]
    assert "--min-rate 1000" in captured["arguments"]
    assert "-A" not in captured["arguments"].split()
    assert "--script=default,safe,vuln" not in captured["arguments"]
