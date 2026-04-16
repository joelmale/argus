from __future__ import annotations

from pathlib import Path

from app.fingerprinting import datasets
from app.fingerprinting.evidence import _hostname_signature_evidence, derive_detected_device_type, extract_evidence
from app.scanner.models import DiscoveredHost, HostScanResult, PortResult, ProbeResult


def _write_recog_dataset(tmp_path: Path, filename: str, pattern: str, params: str) -> None:
    (tmp_path / filename).write_text(
        f"""<?xml version='1.0' encoding='UTF-8'?>
<fingerprints>
  <fingerprint pattern="{pattern}">
    <description>Test fingerprint</description>
{params}
  </fingerprint>
</fingerprints>
""",
        encoding="utf-8",
    )


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


def test_extract_evidence_uses_rapid7_recog_http_server_database(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(datasets, "DATASET_DIR", tmp_path)
    datasets._clear_caches()
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_http.xml",
        r"(?i)^lighttpd(?:/(\d[\d.]+))?",
        """    <param pos="0" name="service.vendor" value="lighttpd"/>
    <param pos="0" name="service.product" value="lighttpd"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:lighttpd:lighttpd:{service.version}"/>""",
    )
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


def test_extract_evidence_uses_recog_for_ssh_http_auth_cookies_titles_snmp_and_mdns(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(datasets, "DATASET_DIR", tmp_path)
    datasets._clear_caches()
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_ssh_banners.xml",
        r"^SSH-2\.0-OpenSSH_([\w.]+)",
        """    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_http_wwwauth.xml",
        r"^Basic realm=&quot;Transmission&quot;$",
        """    <param pos="0" name="service.vendor" value="TransmissionBT"/>
    <param pos="0" name="service.product" value="Transmission"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_html_title.xml",
        r"^pfSense - Login$",
        """    <param pos="0" name="service.vendor" value="Netgate"/>
    <param pos="0" name="service.product" value="pfSense"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_http_cookies.xml",
        r"^FGTServer=",
        """    <param pos="0" name="hw.vendor" value="Fortinet"/>
    <param pos="0" name="hw.device" value="Firewall"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_snmp_sysdescr.xml",
        r"^Cisco IOS Software, C2960",
        """    <param pos="0" name="os.vendor" value="Cisco"/>
    <param pos="0" name="os.device" value="Switch"/>
    <param pos="0" name="os.product" value="IOS"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_mdns_device-info_txt.xml",
        r"^osxvers=22",
        """    <param pos="0" name="os.vendor" value="Apple"/>
    <param pos="0" name="os.product" value="Mac OS X"/>
    <param pos="0" name="os.version" value="13.0"/>""",
    )
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.9"),
        probes=[
            ProbeResult(probe_type="ssh", target_port=22, success=True, data={"banner": "SSH-2.0-OpenSSH_9.3"}),
            ProbeResult(
                probe_type="http",
                target_port=80,
                success=True,
                data={
                    "auth_header": 'Basic realm="Transmission"',
                    "title": "pfSense - Login",
                    "headers": {"set-cookie": "FGTServer=abc; path=/"},
                },
            ),
            ProbeResult(probe_type="snmp", target_port=161, success=True, data={"sys_descr": "Cisco IOS Software, C2960"}),
            ProbeResult(
                probe_type="mdns",
                success=True,
                data={"services": [{"type": "_device-info._tcp.local.", "name": "Mac", "properties": {"osxvers": "22"}}]},
            ),
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}

    assert ("recog_ssh", "service", "ssh_banner", "OpenSSH") in keys
    assert ("recog_http_auth", "service", "http_auth", "Transmission") in keys
    assert ("recog_http_title", "service", "html_title", "pfSense") in keys
    assert ("recog_http_cookie", "device_type", "http_cookie_device", "firewall") in keys
    assert ("recog_snmp", "device_type", "snmp_sysdescr_device", "switch") in keys
    assert ("recog_mdns", "service", "mdns_device_info", "Mac OS X") in keys


def test_extract_evidence_uses_recog_for_nmap_service_banners(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(datasets, "DATASET_DIR", tmp_path)
    datasets._clear_caches()
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_ftp_banners.xml",
        r"^FileZilla Server ([\d.]+)",
        """    <param pos="0" name="service.vendor" value="FileZilla"/>
    <param pos="0" name="service.product" value="FileZilla Server"/>
    <param pos="1" name="service.version"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_telnet_banners.xml",
        r"^BusyBox",
        """    <param pos="0" name="service.vendor" value="BusyBox"/>
    <param pos="0" name="service.product" value="BusyBox"/>
    <param pos="0" name="hw.device" value="Embedded"/>""",
    )
    _write_recog_dataset(
        tmp_path,
        "rapid7_recog_smtp_banners.xml",
        r"^Postfix",
        """    <param pos="0" name="service.vendor" value="Postfix"/>
    <param pos="0" name="service.product" value="Postfix"/>""",
    )
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.10"),
        ports=[
            PortResult(port=21, service="ftp", banner="FileZilla Server 1.7.2 ready"),
            PortResult(port=23, service="telnet", banner="BusyBox v1.36.1"),
            PortResult(port=25, service="smtp", banner="Postfix SMTP ready"),
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}

    assert ("recog_ftp", "service", "ftp_banner", "FileZilla Server") in keys
    assert ("recog_ftp", "service", "ftp_banner_version", "1.7.2") in keys
    assert ("recog_telnet", "device_type", "telnet_banner_device", "iot_device") in keys
    assert ("recog_smtp", "service", "smtp_banner", "Postfix") in keys


def test_mdns_service_type_hints_classify_homekit_accessory():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.100.11"),
        probes=[
            ProbeResult(
                probe_type="mdns",
                success=True,
                data={"services": [{"type": "_hap._tcp.local.", "name": "Door Lock", "properties": {}}]},
            )
        ],
    )

    evidence = extract_evidence(result)
    keys = {(item.source, item.category, item.key, item.value) for item in evidence}

    assert ("mdns_service_type", "device_type", "service_type_hint", "iot_device") in keys


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
