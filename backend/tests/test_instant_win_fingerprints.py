from __future__ import annotations

from app.scanner.enrichment.instant_win import (
    fingerprint_from_nmap_host_data,
    fingerprint_from_nmap_xml,
)
from app.scanner.models import DiscoveredHost, ScanProfile
from app.scanner.stages import portscan


FIREWALLA_XML = """\
<nmaprun>
  <host>
    <address addr="192.168.100.1" addrtype="ipv4"/>
    <address addr="20:6D:31:41:56:2A" addrtype="mac" vendor="Firewalla Inc."/>
    <hostnames>
      <hostname name="firewalla.lan" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.14"/>
      </port>
      <port protocol="tcp" portid="53">
        <state state="open"/>
        <service name="domain" product="dnsmasq" version="UNKNOWN"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)" accuracy="98">
        <osclass osfamily="Linux" osgen="5.X" type="general purpose">
          <cpe>cpe:/o:linux:linux_kernel:5</cpe>
          <cpe>cpe:/o:mikrotik:routeros:7</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""


def test_fingerprint_from_nmap_xml_detects_firewalla():
    fingerprint = fingerprint_from_nmap_xml(FIREWALLA_XML)

    assert fingerprint is not None
    assert fingerprint.vendor == "Firewalla"
    assert fingerprint.device_type == "firewall"
    assert fingerprint.os_name == "Ubuntu Linux"
    assert fingerprint.os_version == "22.04"


def test_fingerprint_from_nmap_host_data_detects_firewalla():
    host_data = {
        "vendor": {"20:6D:31:41:56:2A": "Firewalla Inc."},
        "hostnames": [{"name": "firewalla.lan", "type": "PTR"}],
        "tcp": {
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": "Ubuntu 3ubuntu0.14"},
            53: {"state": "open", "name": "domain", "product": "dnsmasq", "version": "UNKNOWN", "extrainfo": ""},
        },
        "osmatch": [
            {
                "name": "Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)",
                "accuracy": "98",
                "osclass": [{"osfamily": "Linux", "osgen": "5.X", "type": "general purpose", "cpe": ["cpe:/o:mikrotik:routeros:7"]}],
            }
        ],
    }

    fingerprint = fingerprint_from_nmap_host_data(host_data)

    assert fingerprint is not None
    assert fingerprint.vendor == "Firewalla"
    assert fingerprint.device_type == "firewall"
    assert fingerprint.os_name == "Ubuntu Linux"


class _FakePortScannerWithHostData:
    def __init__(self):
        self.arguments = None
        self.hosts = None
        self._data = {
            "192.168.100.1": {
                "addresses": {"mac": "20:6D:31:41:56:2A"},
                "vendor": {"20:6D:31:41:56:2A": "Firewalla Inc."},
                "hostnames": [{"name": "firewalla.lan", "type": "PTR"}],
                "tcp": {
                    22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": "Ubuntu 3ubuntu0.14"},
                    53: {"state": "open", "name": "domain", "product": "dnsmasq", "version": "UNKNOWN", "extrainfo": ""},
                },
                "osmatch": [
                    {
                        "name": "Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)",
                        "accuracy": "98",
                        "osclass": [{"osfamily": "Linux", "osgen": "5.X", "type": "general purpose", "cpe": ["cpe:/o:mikrotik:routeros:7"]}],
                    }
                ],
            }
        }

    def scan(self, hosts: str, arguments: str):
        self.hosts = hosts
        self.arguments = arguments

    def all_hosts(self):
        return list(self._data.keys())

    def __getitem__(self, key: str):
        return self._data[key]


def test_scan_sync_returns_nmap_vendor_and_enriched_os(monkeypatch):
    fake = _FakePortScannerWithHostData()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)
    host = DiscoveredHost(ip_address="192.168.100.1", discovery_method="arp")

    results = portscan._scan_sync([host], ScanProfile.BALANCED, None)

    ports, os_fp, ip, hostname, vendor = results[0]
    assert ip == "192.168.100.1"
    assert hostname == "firewalla.lan"
    assert vendor == "Firewalla"
    assert os_fp.device_type == "firewall"
    assert os_fp.os_name == "Ubuntu Linux"
    assert host.mac_address == "20:6D:31:41:56:2A"
    assert len(ports) == 2


def test_scan_sync_handles_missing_instant_win_fingerprint(monkeypatch):
    fake = _FakePortScannerWithHostData()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)
    monkeypatch.setattr(portscan, "_extract_mac_and_vendor", lambda host_data: ("20:6D:31:41:56:2A", "Firewalla Inc."))
    monkeypatch.setattr(
        "app.scanner.enrichment.instant_win.fingerprint_from_nmap_host_data",
        lambda host_data: None,
    )
    host = DiscoveredHost(ip_address="192.168.100.1", discovery_method="arp")

    results = portscan._scan_sync([host], ScanProfile.BALANCED, None)

    ports, os_fp, ip, hostname, vendor = results[0]
    assert ip == "192.168.100.1"
    assert hostname == "firewalla.lan"
    assert vendor == "Firewalla Inc."
    assert os_fp.os_name is not None
    assert len(ports) == 2
