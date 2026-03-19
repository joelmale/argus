from __future__ import annotations

from app.fingerprinting.evidence import derive_detected_device_type, extract_evidence
from app.scanner.models import DiscoveredHost, HostScanResult, ProbeResult


def test_extract_evidence_captures_http_favicon_and_detected_app_signatures():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.4", ttl=64, nmap_hostname="proxmox2.lan"),
        probes=[
            ProbeResult(
                probe_type="http",
                target_port=8006,
                success=True,
                data={
                    "server": "pve-api-daemon/3.0",
                    "title": "Proxmox Virtual Environment",
                    "favicon_hash": "abc123deadbeef42",
                    "detected_app": "Proxmox VE",
                },
            )
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}

    assert ("probe_http", "identity", "favicon_hash", "abc123deadbeef42") in keys
    assert ("probe_http", "identity", "detected_app", "Proxmox VE") in keys
    assert ("probe_http", "device_type", "signature:proxmox", "server") in keys


def test_extract_evidence_uses_ttl_family_and_mdns_signatures():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.20", ttl=255),
        probes=[
            ProbeResult(
                probe_type="mdns",
                success=True,
                data={
                    "services": [
                        {
                            "type": "_googlecast._tcp.local",
                            "name": "Living Room Chromecast",
                            "host": "chromecast.local",
                            "properties": {"md": "Chromecast"},
                        }
                    ]
                },
            )
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}

    assert ("tcpip_stack", "os_hint", "ttl_family", "network_appliance_like") in keys
    assert ("probe_mdns", "identity", "service_name", "Living Room Chromecast") in keys


def test_detected_type_accepts_multi_source_probe_evidence():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.30", ttl=64),
        probes=[
            ProbeResult(
                probe_type="http",
                success=True,
                data={"title": "pfSense", "detected_app": "pfSense"},
            ),
            ProbeResult(
                probe_type="tls",
                success=True,
                data={"subject_cn": "pfSense.localdomain", "cert_org": "Netgate"},
            ),
        ],
    )

    device_type, source = derive_detected_device_type(extract_evidence(result))

    assert device_type == "firewall"
    assert source == "probe"
