from __future__ import annotations

from app.fingerprinting.evidence import _hostname_signature_evidence, derive_detected_device_type, extract_evidence
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


def test_extract_evidence_uses_rapid7_recog_http_server_database():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.8"),
        probes=[
            ProbeResult(
                probe_type="http",
                target_port=80,
                success=True,
                data={"server": "lighttpd/1.4.59"},
            )
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}
    recog_product = next(item for item in evidence if item.source == "recog_http" and item.key == "http_server")

    assert ("recog_http", "service", "http_server", "lighttpd") in keys
    assert ("recog_http", "service", "http_server_version", "1.4.59") in keys
    assert recog_product.details["product"] == "lighttpd"
    assert recog_product.details["version"] == "1.4.59"
    assert recog_product.details["cpe"] == "cpe:/a:lighttpd:lighttpd:1.4.59"


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


def test_hostname_signature_evidence_uses_role_tokens_and_normalized_names():
    matches = _hostname_signature_evidence("nas-backup.home", "hostname", {"hostname": "nas-backup.home"})
    values = {(item.category, item.value) for item in matches}

    assert ("device_type", "nas") in values

    matches = _hostname_signature_evidence("home-assistant.local", "hostname", {"hostname": "home-assistant.local"})
    keys = {(item.category, item.key, item.value) for item in matches}

    assert ("device_type", "signature:home assistant", "iot_device") in keys


def test_hostname_signature_evidence_treats_nintendo_switch_as_console_not_network_switch():
    matches = _hostname_signature_evidence("nintendo-switch.lan", "hostname", {"hostname": "nintendo-switch.lan"})
    values = {(item.category, item.value) for item in matches}

    assert ("device_type", "game_console") in values
    assert ("device_type", "switch") not in values
