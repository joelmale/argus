from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest

from app.db.models import ScanJob, ScannerConfig
from app.fingerprinting.evidence import EvidenceItem
from app.fingerprinting.risk import extract_normalized_products
from app.scanner.config import (
    AUTO_TARGET_SENTINEL,
    ScannerConfigUpdateInput,
    build_effective_scanner_config,
    materialize_scan_targets,
    split_scan_targets,
    update_scanner_config,
    validate_scan_targets_routable,
)
from app.scanner.models import (
    AIAnalysis,
    DeviceClass,
    DiscoveredHost,
    HostScanResult,
    HttpProbeData,
    OSFingerprint,
    PortResult,
    ProbeResult,
    ScanProfile,
    ScanSummary,
)
from app.scanner.pipeline import (
    ScanControlDecision,
    _build_investigation_tasks,
    _build_control_interrupt,
    _build_partial_results,
    _call_persist_results,
    _call_scan_hosts,
    _extract_probe_hostname,
    _get_offline_ips,
    _port_details_for_host,
    _progress_payload,
    _resolve_hostname_from_probes,
    _run_ai_investigation,
)
from app.scanner.probes import http as http_probe
from app.scanner.probes import mdns as mdns_probe
from app.scanner.probes import tls as tls_probe
from app.scanner.probes import upnp as upnp_probe
from app.scanner.enrichment import dns_lookup
from app.scanner.stages import deep_probe, discovery
from app.scanner.stages import fingerprint, portscan
from app.scanner.stages.discovery import (
    _merge_discovered_host,
    _merge_discovery_results,
    _parse_ping_sweep_xml,
)
from app.workers.tasks import (
    _apply_interrupt_result,
    _build_control_fn,
    _build_parent_chunk_broadcast_fn,
    _extract_scan_job_id,
    _get_scan_task_id,
    _interrupt_stage,
    _merge_scan_summary,
    _record_job_progress,
)

from app.scanner.probes import ssh as ssh_probe


@pytest.mark.asyncio
async def test_ssh_probe_returns_success_when_banner_is_collected(monkeypatch):
    async def fake_grab_ssh_info(_ip, _port):
        return ssh_probe.SshProbeData(
            banner="SSH-2.0-OpenSSH_9.3p2 Ubuntu-1ubuntu3.6",
            server_version="OpenSSH_9.3p2 Ubuntu-1ubuntu3.6",
            kex_algorithms=["curve25519-sha256", "ecdh-sha2-nistp256"],
            host_key_algorithms=["ssh-ed25519"],
            encryption_algorithms=["chacha20-poly1305@openssh.com"],
        )

    monkeypatch.setattr(ssh_probe, "_grab_ssh_info", fake_grab_ssh_info)

    result = await ssh_probe.probe("10.0.0.25", 22)

    assert result.success is True
    assert result.probe_type == "ssh"
    assert result.target_port == 22
    assert result.data["server_version"] == "OpenSSH_9.3p2 Ubuntu-1ubuntu3.6"
    assert "Banner: SSH-2.0-OpenSSH_9.3p2" in (result.raw or "")


class _FakeDb:
    def __init__(self):
        self.flush_calls = 0
        self.commit_calls = 0
        self.refresh_calls = 0

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def refresh(self, _obj):
        self.refresh_calls += 1


class _FakeExecuteResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeOfflineDb:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _stmt):
        return _FakeExecuteResult(self.rows)


@pytest.fixture(autouse=True)
def reset_async_engine():
    yield


@pytest.fixture(autouse=True)
def clean_database():
    yield


@pytest.mark.asyncio
async def test_call_scan_hosts_falls_back_when_old_signature_rejects_top_ports_count():
    async def old_signature(hosts, profile):
        assert hosts == ["host"]
        assert profile is ScanProfile.BALANCED
        return ["ok"]

    result = await _call_scan_hosts(
        old_signature, ["host"], ScanProfile.BALANCED, top_ports_count=250
    )

    assert result == ["ok"]


@pytest.mark.asyncio
async def test_call_persist_results_falls_back_when_old_signature_rejects_kwargs():
    called = []

    async def old_persist(
        db_session, results, scanned_ips, summary, broadcast_fn, job_id
    ):
        called.append((db_session, results, scanned_ips, summary, broadcast_fn, job_id))

    summary = ScanSummary(
        job_id="job-1", targets="10.0.0.0/24", profile=ScanProfile.BALANCED
    )
    await _call_persist_results(
        old_persist,
        "db",
        ["result"],
        {"10.0.0.5"},
        summary,
        None,
        "job-1",
        mark_missing_offline=False,
        allow_discovery_only=True,
        stage="discovery",
    )

    assert called == [("db", ["result"], {"10.0.0.5"}, summary, None, "job-1")]


def test_build_partial_results_preserves_completed_results_and_backfills_remaining_hosts():
    hosts = [
        DiscoveredHost(ip_address="10.0.0.10", discovery_method="arp"),
        DiscoveredHost(ip_address="10.0.0.11", discovery_method="ping"),
    ]
    completed = [
        HostScanResult(
            host=hosts[0],
            ports=[PortResult(port=22, protocol="tcp", state="open", service="ssh")],
            scan_profile=ScanProfile.BALANCED,
        )
    ]

    partial = _build_partial_results(hosts, completed, ScanProfile.BALANCED)

    assert partial[0] is completed[0]
    assert partial[1].host.ip_address == "10.0.0.11"
    assert partial[1].scan_profile is ScanProfile.BALANCED


def test_build_control_interrupt_preserves_partial_results_when_requested():
    summary = ScanSummary(
        job_id="job-2", targets="10.0.0.0/24", profile=ScanProfile.BALANCED
    )
    hosts = [
        DiscoveredHost(ip_address="10.0.0.10", discovery_method="arp"),
        DiscoveredHost(ip_address="10.0.0.11", discovery_method="ping"),
    ]
    completed = [HostScanResult(host=hosts[0], scan_profile=ScanProfile.BALANCED)]
    partial = _build_partial_results(hosts, completed, ScanProfile.BALANCED)

    interrupt = _build_control_interrupt(
        ScanControlDecision(
            action="pause",
            mode="preserve_discovery",
            resume_after="2026-03-23T16:00:00+00:00",
        ),
        "post_discovery",
        summary,
        partial,
        completed,
    )

    assert interrupt.status == "paused"
    assert {result.host.ip_address for result in interrupt.partial_results} == {
        "10.0.0.10",
        "10.0.0.11",
    }
    assert interrupt.scanned_ips == {"10.0.0.10", "10.0.0.11"}


def test_progress_payload_includes_summary_counters_and_extra_fields():
    summary = ScanSummary(
        job_id="job-3", targets="10.0.0.0/24", profile=ScanProfile.BALANCED
    )
    summary.new_assets = 2
    summary.changed_assets = 1

    payload = _progress_payload(
        "job-3", "discovery", 0.15, summary, message="hello", hosts_found=4
    )

    assert payload["event"] == "scan_progress"
    assert payload["data"]["assets_created"] == 2
    assert payload["data"]["assets_updated"] == 1
    assert payload["data"]["hosts_found"] == 4
    assert payload["data"]["message"] == "hello"


def test_port_details_for_host_returns_empty_defaults_when_missing():
    ports, os_fp, nmap_hostname, nmap_vendor = _port_details_for_host({}, "10.0.0.99")

    assert ports == []
    assert os_fp.os_name is None
    assert nmap_hostname is None
    assert nmap_vendor is None


def test_extract_probe_hostname_supports_dns_mdns_and_snmp():
    dns_probe = SimpleNamespace(
        success=True, probe_type="dns", data={"hostname": "switch.lan"}
    )
    mdns_probe = SimpleNamespace(
        success=True, probe_type="mdns", data={"services": [{"host": "printer.local"}]}
    )
    snmp_probe = SimpleNamespace(
        success=True, probe_type="snmp", data={"sys_name": "router-core"}
    )
    failed_probe = SimpleNamespace(
        success=False, probe_type="dns", data={"hostname": "ignored"}
    )

    assert _extract_probe_hostname(dns_probe) == "switch.lan"
    assert _extract_probe_hostname(mdns_probe) == "printer.local"
    assert _extract_probe_hostname(snmp_probe) == "router-core"
    assert _extract_probe_hostname(failed_probe) is None


def test_resolve_hostname_from_probes_returns_first_available_hostname():
    probes = [
        SimpleNamespace(success=True, probe_type="http", data={}),
        SimpleNamespace(
            success=True,
            probe_type="mdns",
            data={"services": [{"host": "speaker.local"}]},
        ),
        SimpleNamespace(
            success=True, probe_type="dns", data={"hostname": "later.example"}
        ),
    ]

    assert _resolve_hostname_from_probes(probes) == "speaker.local"


@pytest.mark.asyncio
async def test_run_ai_investigation_sets_analysis_and_broadcasts_event():
    payloads = []
    result = HostScanResult(
        host=DiscoveredHost(ip_address="10.0.0.20", discovery_method="ping"),
        scan_profile=ScanProfile.BALANCED,
    )

    class Analyst:
        async def investigate(self, _result):
            return AIAnalysis(
                device_class=DeviceClass.ROUTER, confidence=0.91, vendor="Ubiquiti"
            )

    async def broadcast(payload):
        payloads.append(payload)

    await _run_ai_investigation(Analyst(), result, broadcast, "job-4", "10.0.0.20")

    assert result.ai_analysis is not None
    assert payloads == [
        {
            "event": "device_investigated",
            "data": {
                "job_id": "job-4",
                "ip": "10.0.0.20",
                "device_class": "router",
                "vendor": "Ubiquiti",
                "confidence": 0.91,
            },
        }
    ]


@pytest.mark.asyncio
async def test_build_investigation_tasks_uses_port_map_details(monkeypatch):
    host = DiscoveredHost(ip_address="10.0.0.20", discovery_method="arp")
    port_map = {
        "10.0.0.20": (
            [PortResult(port=22, protocol="tcp", state="open", service="ssh")],
            SimpleNamespace(),
            "router.local",
            "Ubiquiti",
        )
    }

    async def fake_investigate_host(**kwargs):
        return kwargs

    semaphore = asyncio.Semaphore(1)
    monkeypatch.setattr("app.scanner.pipeline._investigate_host", fake_investigate_host)
    tasks = _build_investigation_tasks(
        [host],
        port_map,
        ScanProfile.BALANCED,
        analyst=None,
        run_deep_probes=True,
        deep_probe_timeout_seconds=6,
        semaphore=semaphore,
        broadcast_fn=None,
        job_id="job-build",
    )
    result = await tasks[0]

    assert result["nmap_hostname"] == "router.local"
    assert result["nmap_vendor"] == "Ubiquiti"
    assert result["ports"][0].port == 22


@pytest.mark.asyncio
async def test_get_offline_ips_respects_mark_missing_offline_flag():
    db = _FakeOfflineDb([("10.0.0.10",), ("10.0.0.11",)])

    skipped = await _get_offline_ips(
        db,
        lambda *_args, **_kwargs: object(),
        SimpleNamespace(ip_address="ip_address", status="status"),
        {"10.0.0.10"},
        False,
    )
    assert skipped == []


def test_merge_discovery_results_ignores_failed_method_and_prefers_mac_addresses():
    arp_results = [
        DiscoveredHost(
            ip_address="10.0.0.5",
            mac_address="AA:BB:CC:DD:EE:FF",
            discovery_method="arp",
        )
    ]
    ping_results = [
        DiscoveredHost(ip_address="10.0.0.5", discovery_method="ping"),
        DiscoveredHost(ip_address="10.0.0.6", discovery_method="ping"),
    ]

    merged = _merge_discovery_results(arp_results, ping_results)
    merged_from_exception = _merge_discovery_results(
        RuntimeError("arp failed"), ping_results
    )

    assert merged["10.0.0.5"].mac_address == "AA:BB:CC:DD:EE:FF"
    assert set(merged_from_exception) == {"10.0.0.5", "10.0.0.6"}


def test_merge_discovered_host_only_replaces_when_mac_is_better():
    merged = {
        "10.0.0.5": DiscoveredHost(ip_address="10.0.0.5", discovery_method="ping")
    }

    _merge_discovered_host(
        merged,
        DiscoveredHost(
            ip_address="10.0.0.5", discovery_method="arp", mac_address="AA:BB"
        ),
    )
    _merge_discovered_host(
        merged, DiscoveredHost(ip_address="10.0.0.5", discovery_method="ping")
    )

    assert merged["10.0.0.5"].mac_address == "AA:BB"


def test_parse_ping_sweep_xml_ignores_invalid_ttl_and_missing_ipv4():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason_ttl="not-a-number"/>
    <address addr="printer.local" addrtype="mac"/>
  </host>
  <host>
    <status state="up" reason_ttl="not-a-number"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

    hosts = _parse_ping_sweep_xml(xml)

    assert len(hosts) == 1
    assert hosts[0].ip_address == "10.0.0.8"
    assert hosts[0].ttl is None


@pytest.mark.asyncio
async def test_deep_probe_run_builds_expected_probe_mix(monkeypatch):
    async def fake_dns_probe(_ip):
        return ProbeResult(probe_type="dns", success=True)

    async def fake_http_probe(_ip, port, use_https):
        return ProbeResult(
            probe_type="https" if use_https else "http", target_port=port, success=True
        )

    async def fake_tls_probe(_ip, port):
        return ProbeResult(probe_type="tls", target_port=port, success=True)

    async def fake_ssh_probe(_ip, port):
        return ProbeResult(probe_type="ssh", target_port=port, success=True)

    async def fake_snmp_probe(_ip):
        return ProbeResult(probe_type="snmp", target_port=161, success=True)

    async def fake_mdns_probe(_ip):
        return ProbeResult(probe_type="mdns", success=True)

    async def fake_upnp_probe(_ip):
        return ProbeResult(probe_type="upnp", target_port=1900, success=True)

    async def fake_smb_probe(_ip, port):
        return ProbeResult(probe_type="smb", target_port=port, success=True)

    monkeypatch.setattr(deep_probe, "_dns_probe", fake_dns_probe)
    monkeypatch.setattr(deep_probe, "_http_probe", fake_http_probe)
    monkeypatch.setattr(deep_probe, "_tls_probe", fake_tls_probe)
    monkeypatch.setattr(deep_probe, "_ssh_probe", fake_ssh_probe)
    monkeypatch.setattr(deep_probe, "_snmp_probe", fake_snmp_probe)
    monkeypatch.setattr(deep_probe, "_mdns_probe", fake_mdns_probe)
    monkeypatch.setattr(deep_probe, "_upnp_probe", fake_upnp_probe)
    monkeypatch.setattr(deep_probe, "_smb_probe", fake_smb_probe)

    host = DiscoveredHost(ip_address="10.0.0.50", discovery_method="arp")
    ports = [
        PortResult(port=80, protocol="tcp", state="open", service="http"),
        PortResult(port=443, protocol="tcp", state="open", service="https"),
        PortResult(port=22, protocol="tcp", state="open", service="ssh"),
        PortResult(port=445, protocol="tcp", state="open", service="microsoft-ds"),
    ]

    results = await deep_probe.run(
        host, ports, ["snmp", "mdns", "upnp"], timeout_seconds=4
    )

    probe_types = [result.probe_type for result in results]
    assert probe_types.count("tls") == 1
    assert "dns" in probe_types
    assert "http" in probe_types
    assert "https" in probe_types
    assert "ssh" in probe_types
    assert "snmp" in probe_types
    assert "mdns" in probe_types
    assert "upnp" in probe_types
    assert "smb" in probe_types


def test_deep_probe_timeout_helpers_normalize_and_default():
    assert deep_probe._normalize_probe_timeout(None) is None
    assert deep_probe._normalize_probe_timeout(0.2) == 1.0
    assert deep_probe._normalize_probe_timeout(99) == 30.0
    assert (
        deep_probe._resolve_probe_timeout("tls", None)
        == deep_probe.PROBE_TIMEOUTS["tls"]
    )
    assert deep_probe._resolve_probe_timeout("http", 4.5) == 4.5


@pytest.mark.asyncio
async def test_mdns_probe_returns_success_when_services_found(monkeypatch):
    async def fake_query(_ip):
        return mdns_probe.MdnsProbeData(
            services=[
                {
                    "type": "_googlecast._tcp.local",
                    "name": "Living Room",
                    "host": "tv.local",
                    "port": 8009,
                    "properties": {"fn": "TV"},
                }
            ]
        )

    monkeypatch.setattr(mdns_probe, "_query_mdns", fake_query)

    result = await mdns_probe.probe("10.0.0.15")

    assert result.success is True
    assert "Living Room" in (result.raw or "")


@pytest.mark.asyncio
async def test_mdns_probe_handles_timeout_and_import_errors(monkeypatch):
    async def fake_query_timeout(_ip):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(mdns_probe, "_query_mdns", fake_query_timeout)
    timeout_result = await mdns_probe.probe("10.0.0.15")
    assert timeout_result.success is False
    assert timeout_result.error == "No mDNS services found for this host"

    async def fake_query_import(_ip):
        raise ImportError("missing zeroconf")

    monkeypatch.setattr(mdns_probe, "_query_mdns", fake_query_import)
    import_result = await mdns_probe.probe("10.0.0.15")
    assert import_result.success is False
    assert "zeroconf not installed" in (import_result.error or "")


@pytest.mark.asyncio
async def test_query_mdns_filters_to_target_ip_and_decodes_properties(monkeypatch):
    class Info:
        name = "Kitchen._http._tcp.local."
        server = "kitchen.local."
        port = 80
        properties = {b"fn": b"Kitchen Display", "model": "Nest Hub"}

        def parsed_scoped_addresses(self):
            return ["10.0.0.10"]

    class FakeZeroconf:
        async def async_get_service_info(self, _svc_type, _name, timeout=1000):
            return Info()

        async def async_close(self):
            return None

    monkeypatch.setattr("zeroconf.asyncio.AsyncZeroconf", lambda: FakeZeroconf())

    data = await mdns_probe._query_mdns("10.0.0.10")

    assert data.services[0]["host"] == "kitchen.local."
    assert data.services[0]["properties"]["fn"] == "Kitchen Display"
    assert data.services[0]["properties"]["model"] == "Nest Hub"


@pytest.mark.asyncio
async def test_dns_reverse_lookup_filters_placeholders_and_handles_errors(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda _ip: ("broadcasthost", [], []))
    assert await dns_lookup.reverse_lookup("10.0.0.8") is None

    def raise_herror(_ip):
        raise socket.herror()

    monkeypatch.setattr(socket, "gethostbyaddr", raise_herror)
    assert await dns_lookup.reverse_lookup("10.0.0.8") is None


@pytest.mark.asyncio
async def test_dns_reverse_lookup_returns_none_on_timeout(monkeypatch):
    @asynccontextmanager
    async def fake_timeout(_seconds):
        raise asyncio.TimeoutError()
        yield

    monkeypatch.setattr(dns_lookup.asyncio, "timeout", fake_timeout, raising=False)

    assert await dns_lookup.reverse_lookup("10.0.0.8") is None


@pytest.mark.asyncio
async def test_dns_forward_lookup_deduplicates_addresses_and_handles_failures(
    monkeypatch,
):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, _port: [
            (None, None, None, None, ("10.0.0.5", 0)),
            (None, None, None, None, ("10.0.0.5", 0)),
            (None, None, None, None, ("fe80::1", 0)),
        ],
    )

    result = await dns_lookup.forward_lookup("nas.local")
    assert set(result) == {"10.0.0.5", "fe80::1"}

    def raise_error(_host, _port):
        raise RuntimeError("boom")

    monkeypatch.setattr(socket, "getaddrinfo", raise_error)
    assert await dns_lookup.forward_lookup("nas.local") == []


@pytest.mark.asyncio
async def test_discovery_sweep_merges_results_when_one_method_fails(monkeypatch):
    async def fake_arp(_targets):
        return [
            DiscoveredHost(
                ip_address="10.0.0.8", mac_address=None, discovery_method="arp"
            ),
            DiscoveredHost(
                ip_address="10.0.0.9",
                mac_address="AA:BB:CC:DD:EE:FF",
                discovery_method="arp",
            ),
        ]

    async def fake_ping(_targets):
        raise RuntimeError("nmap missing")

    monkeypatch.setattr(discovery, "_arp_sweep", fake_arp)
    monkeypatch.setattr(discovery, "_ping_sweep", fake_ping)

    hosts = await discovery.sweep("10.0.0.0/24")

    assert sorted(host.ip_address for host in hosts) == ["10.0.0.8", "10.0.0.9"]


def test_fingerprint_classify_prefers_vendor_and_dnsmasq_gateway_pattern():
    host = DiscoveredHost(ip_address="10.0.0.1", nmap_hostname="fw-core")
    ports = [
        PortResult(port=22, protocol="tcp", state="open", service="ssh"),
        PortResult(
            port=53, protocol="tcp", state="open", service="domain", product="dnsmasq"
        ),
        PortResult(port=443, protocol="tcp", state="open", service="https"),
    ]

    hint = fingerprint.classify(
        host, ports, OSFingerprint(os_name="Linux"), mac_vendor="Firewalla Inc."
    )

    assert hint.device_class is DeviceClass.FIREWALL
    assert hint.confidence >= 0.95


def test_portscan_extract_ports_builds_versions_and_truncates_script_banner():
    host_data = {
        "tcp": {
            80: {
                "state": "open",
                "name": "http",
                "product": "nginx",
                "version": "1.25",
                "extrainfo": "Ubuntu",
                "cpe": ["cpe:/a:nginx:nginx:1.25"],
                "script": {"http-title": "A" * 400},
            },
            81: {"state": "closed"},
        }
    }

    ports = portscan._extract_ports(host_data)

    assert len(ports) == 1
    assert ports[0].version == "nginx 1.25 Ubuntu"
    assert ports[0].cpe == "cpe:/a:nginx:nginx:1.25"
    assert ports[0].banner is not None
    assert len(ports[0].banner) < 330


def test_portscan_service_scripts_match_web_ports_without_service_names():
    https_scripts = portscan._service_scripts_for_port(
        PortResult(port=443, protocol="tcp", state="open", service=None)
    )
    http_scripts = portscan._service_scripts_for_port(
        PortResult(port=80, protocol="tcp", state="open", service=None)
    )

    assert "ssl-cert" in https_scripts
    assert "http-title" in http_scripts


def test_split_scan_targets_breaks_large_networks_and_groups_ips():
    chunks = split_scan_targets(
        "10.0.0.0/22 10.0.5.1 10.0.5.2", max_network_prefix=24, max_ip_group_size=2
    )

    assert "10.0.0.0/24" in chunks
    assert "10.0.1.0/24" in chunks
    assert "10.0.2.0/24" in chunks
    assert "10.0.3.0/24" in chunks
    assert "10.0.5.1/32 10.0.5.2/32" in chunks


def test_materialize_scan_targets_uses_detected_network(monkeypatch):
    monkeypatch.setattr(
        "app.scanner.config.detect_local_ipv4_cidr", lambda: "10.23.0.0/24"
    )

    assert materialize_scan_targets(AUTO_TARGET_SENTINEL) == "10.23.0.0/24"
    assert materialize_scan_targets("10.24.0.0/24") == "10.24.0.0/24"


def test_validate_scan_targets_routable_includes_docker_desktop_hint(monkeypatch):
    monkeypatch.setattr(
        "app.scanner.config._iter_ipv4_route_networks",
        lambda: [ipaddress.IPv4Network("192.168.65.0/24")],
    )

    error = validate_scan_targets_routable("192.168.1.0/24")

    assert error is not None
    assert "Docker Desktop" in error


@pytest.mark.asyncio
async def test_update_scanner_config_normalizes_and_clamps_values(monkeypatch):
    config = ScannerConfig(
        enabled=True,
        default_targets="10.0.0.0/24",
        auto_detect_targets=False,
        default_profile="balanced",
        interval_minutes=60,
        concurrent_hosts=4,
        host_chunk_size=64,
        top_ports_count=1000,
        deep_probe_timeout_seconds=6,
        ai_after_scan_enabled=True,
        passive_arp_enabled=False,
        passive_arp_interface="eth0",
        snmp_enabled=True,
        snmp_version="2c",
        snmp_community="public",
        snmp_timeout=5,
        snmp_v3_auth_protocol="sha",
        snmp_v3_priv_protocol="aes",
        fingerprint_ai_enabled=False,
        fingerprint_ai_model="model-a",
        fingerprint_ai_min_confidence=0.75,
        internet_lookup_enabled=False,
        internet_lookup_budget=3,
        internet_lookup_timeout_seconds=5,
    )

    async def fake_get_or_create_scanner_config(_db):
        return config

    monkeypatch.setattr(
        "app.scanner.config.get_or_create_scanner_config",
        fake_get_or_create_scanner_config,
    )
    monkeypatch.setattr(
        "app.scanner.config.detect_local_ipv4_cidr", lambda: "10.99.0.0/24"
    )

    db = _FakeDb()
    updated, effective = await update_scanner_config(
        db,
        ScannerConfigUpdateInput(
            enabled=False,
            default_targets="  ",
            auto_detect_targets=True,
            default_profile="deep",
            interval_minutes=15,
            concurrent_hosts=9,
            host_chunk_size=999,
            top_ports_count=5,
            deep_probe_timeout_seconds=999,
            ai_after_scan_enabled=False,
            passive_arp_enabled=True,
            passive_arp_interface=" ",
            snmp_enabled=True,
            snmp_version="3",
            snmp_community=" ",
            snmp_timeout=0,
            snmp_v3_username=" user ",
            snmp_v3_auth_key=" auth ",
            snmp_v3_priv_key=" priv ",
            snmp_v3_auth_protocol="SHA256",
            snmp_v3_priv_protocol="AES256",
            fingerprint_ai_enabled=True,
            fingerprint_ai_model=" ",
            fingerprint_ai_min_confidence=2.0,
            fingerprint_ai_prompt_suffix="  prefer serial numbers  ",
            internet_lookup_enabled=True,
            internet_lookup_allowed_domains=" example.com, docs.local ",
            internet_lookup_budget=0,
            internet_lookup_timeout_seconds=0,
        ),
    )

    assert updated is config
    assert config.enabled is False
    assert config.default_targets is None
    assert config.host_chunk_size == 256
    assert config.top_ports_count == 10
    assert config.deep_probe_timeout_seconds == 30
    assert config.passive_arp_interface
    assert config.snmp_timeout == 1
    assert config.snmp_v3_username == "user"
    assert config.snmp_v3_auth_key == "auth"
    assert config.snmp_v3_priv_key == "priv"
    assert config.snmp_v3_auth_protocol == "sha256"
    assert config.snmp_v3_priv_protocol == "aes256"
    assert config.fingerprint_ai_min_confidence == 1.0
    assert config.fingerprint_ai_prompt_suffix == "prefer serial numbers"
    assert config.internet_lookup_allowed_domains == "example.com, docs.local"
    assert config.internet_lookup_budget == 1
    assert config.internet_lookup_timeout_seconds == 1
    assert effective.detected_targets == "10.99.0.0/24"
    assert effective.effective_targets == "10.99.0.0/24"
    assert db.flush_calls == 1


def test_build_effective_scanner_config_prefers_explicit_targets(monkeypatch):
    monkeypatch.setattr(
        "app.scanner.config.detect_local_ipv4_cidr", lambda: "10.88.0.0/24"
    )
    config = ScannerConfig(
        enabled=True,
        default_targets="10.55.0.0/24",
        auto_detect_targets=True,
        default_profile="balanced",
        interval_minutes=60,
        concurrent_hosts=4,
        host_chunk_size=64,
        top_ports_count=1000,
        deep_probe_timeout_seconds=6,
        ai_after_scan_enabled=True,
        passive_arp_enabled=False,
        passive_arp_interface="eth0",
        snmp_enabled=True,
        snmp_version="2c",
        snmp_community="public",
        snmp_timeout=5,
        snmp_v3_auth_protocol="sha",
        snmp_v3_priv_protocol="aes",
        fingerprint_ai_enabled=False,
        fingerprint_ai_model="model-a",
        fingerprint_ai_min_confidence=0.75,
        internet_lookup_enabled=False,
        internet_lookup_budget=3,
        internet_lookup_timeout_seconds=5,
    )

    effective = build_effective_scanner_config(config)

    assert effective.detected_targets == "10.88.0.0/24"
    assert effective.effective_targets == "10.55.0.0/24"


def test_extract_normalized_products_deduplicates_product_cpe_and_detected_app():
    evidence = [
        EvidenceItem(
            source="nmap_service",
            category="service",
            key="443/tcp",
            value="https",
            confidence=0.9,
            details={
                "product": "OpenSSL",
                "version": "1.0.1f",
                "cpe": "cpe:/a:openssl:openssl:1.0.1f",
            },
        ),
        EvidenceItem(
            source="nmap_service",
            category="service",
            key="443/tcp",
            value="https",
            confidence=0.9,
            details={
                "product": " OpenSSL ",
                "version": "1.0.1f",
                "cpe": "cpe:/a:openssl:openssl:1.0.1f",
            },
        ),
        EvidenceItem(
            source="probe_http",
            category="identity",
            key="detected_app",
            value="Proxmox Virtual Environment",
            confidence=0.9,
            details={"cpe": "not-a-cpe"},
        ),
    ]

    products = extract_normalized_products(evidence)

    assert [
        (product.product, product.version, product.source) for product in products
    ] == [
        ("openssl", "1.0.1f", "nmap_service"),
        ("proxmox virtual environment", None, "probe_http"),
    ]


def test_http_apply_main_response_sets_redirect_host_only_for_external_host():
    data = HttpProbeData(url="http://10.0.0.10:80")
    request = httpx.Request("GET", "http://10.0.0.10:80/")
    redirect = httpx.Response(
        301, request=request, headers={"location": "https://console.local/"}
    )
    final = httpx.Response(
        200,
        request=httpx.Request("GET", "https://console.local/"),
        headers={
            "server": "nginx",
            "content-type": "text/html",
            "x-powered-by": "Express",
        },
        history=[redirect],
    )

    http_probe._apply_main_response(data, final, "10.0.0.10")

    assert data.status_code == 200
    assert data.server == "nginx"
    assert data.powered_by == "Express"
    assert data.redirect_host == "console.local"
    assert data.redirects == ["http://10.0.0.10/"]


@pytest.mark.asyncio
async def test_http_fetch_favicon_hash_requires_expected_content_type():
    content = b"icon-bytes"

    class Client:
        async def get(self, _url, follow_redirects=True):
            return SimpleNamespace(
                status_code=200,
                content=content,
                headers={"content-type": "image/x-icon"},
            )

    result = await http_probe._fetch_favicon_hash(Client(), "http://10.0.0.10:80")

    assert result == hashlib.sha256(content).hexdigest()[:16]


@pytest.mark.asyncio
async def test_http_collect_interesting_paths_filters_404_and_errors(monkeypatch):
    async def fake_probe_path(_client, _base_url, path):
        if path == "/admin":
            return 200
        if path == "/manager/":
            return 500
        if path == "/panel/":
            return 404
        return 0

    monkeypatch.setattr(http_probe, "_probe_path", fake_probe_path)

    paths = await http_probe._collect_interesting_paths(object(), "http://10.0.0.10:80")

    assert "/admin (200)" in paths
    assert "/manager/ (500)" in paths
    assert all("404" not in item for item in paths)


@pytest.mark.asyncio
async def test_upnp_probe_uses_common_paths_when_ssdp_misses(monkeypatch):
    @asynccontextmanager
    async def fake_timeout(_seconds):
        yield

    async def fake_ssdp_discover(_ip):
        return None

    async def fake_try_common_paths(_ip):
        return "http://10.0.0.15:5000/rootDesc.xml"

    async def fake_fetch_description(_location):
        return upnp_probe.UpnpProbeData(
            friendly_name="Media Server", manufacturer="MiniDLNA"
        )

    monkeypatch.setattr(upnp_probe, "_ssdp_discover", fake_ssdp_discover)
    monkeypatch.setattr(upnp_probe, "_try_common_paths", fake_try_common_paths)
    monkeypatch.setattr(upnp_probe, "_fetch_description", fake_fetch_description)
    monkeypatch.setattr(upnp_probe.asyncio, "timeout", fake_timeout, raising=False)

    result = await upnp_probe.probe("10.0.0.15")

    assert result.success is True
    assert result.data["friendly_name"] == "Media Server"


@pytest.mark.asyncio
async def test_upnp_fetch_description_returns_none_on_non_200(monkeypatch):
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, _location):
            return SimpleNamespace(status_code=404, text="")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: FakeClient())

    assert (
        await upnp_probe._fetch_description("http://10.0.0.15:5000/rootDesc.xml")
        is None
    )


@pytest.mark.asyncio
async def test_upnp_probe_returns_timeout_when_deadline_expires(monkeypatch):
    async def fake_await_with_deadline(awaitable, _seconds):
        close = getattr(awaitable, "close", None)
        if close is not None:
            close()
        raise TimeoutError()

    monkeypatch.setattr(upnp_probe, "_await_with_deadline", fake_await_with_deadline)

    result = await upnp_probe.probe("10.0.0.15")

    assert result.success is False
    assert result.error == "Timeout"


def test_tls_parse_cert_handles_invalid_dates_and_populates_fields():
    cert = {
        "subject": (
            (("commonName", "switch.local"),),
            (("organizationName", "Lab Inc"),),
        ),
        "issuer": ((("commonName", "switch.local"),),),
        "subjectAltName": [("DNS", "switch.local"), ("DNS", "switch")],
        "notBefore": "bad-date",
        "notAfter": "Mar 23 15:44:00 2026 GMT",
    }

    data = tls_probe._parse_cert(
        cert, b"cert-bytes", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3"
    )

    assert data.subject_cn == "switch.local"
    assert data.cert_org == "Lab Inc"
    assert data.is_self_signed is True
    assert data.subject_san == ["switch.local", "switch"]
    assert data.not_before == "bad-date"
    assert data.not_after.startswith("2026-03-23T15:44:00")
    assert data.cipher_suite == "TLS_AES_256_GCM_SHA384"


def test_upnp_parse_xml_supports_namespaced_description_documents():
    xml = """
    <root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <friendlyName>Living Room TV</friendlyName>
        <manufacturer>Samsung</manufacturer>
        <modelName>The Frame</modelName>
        <modelNumber>QN55</modelNumber>
        <serialNumber>ABC123</serialNumber>
        <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
        <UDN>uuid:device-1</UDN>
        <presentationURL>http://10.0.0.15/</presentationURL>
      </device>
    </root>
    """

    data = upnp_probe._parse_xml(xml)

    assert data.friendly_name == "Living Room TV"
    assert data.manufacturer == "Samsung"
    assert data.model_name == "The Frame"
    assert data.model_number == "QN55"
    assert data.serial_number == "ABC123"
    assert data.udn == "uuid:device-1"


@pytest.mark.asyncio
async def test_build_control_fn_maps_job_actions_to_control_decisions():
    db = _FakeDb()
    job = SimpleNamespace(
        control_action="pause",
        control_mode="preserve_discovery",
        resume_after=datetime(2026, 3, 23, 16, 0, tzinfo=timezone.utc),
    )

    control = _build_control_fn(db, job, ScanControlDecision)
    decision = await control()

    assert decision == ScanControlDecision(
        action="pause",
        mode="preserve_discovery",
        resume_after="2026-03-23T16:00:00+00:00",
        message="Operator paused scan",
    )
    assert db.refresh_calls == 1


@pytest.mark.asyncio
async def test_apply_interrupt_result_requeues_pending_jobs(monkeypatch):
    async def fake_next_queue_position(_db):
        return 7

    monkeypatch.setattr(
        "app.workers.tasks._next_queue_position", fake_next_queue_position
    )
    job = ScanJob(
        targets="10.0.0.0/24",
        scan_type="balanced",
        triggered_by="manual",
        status="running",
        control_mode="requeue",
    )
    summary = ScanSummary(
        job_id="job-5", targets="10.0.0.0/24", profile=ScanProfile.BALANCED
    )
    exc = SimpleNamespace(
        status="paused",
        message="Preempted",
        resume_after=None,
        scanned_ips={"10.0.0.10", "10.0.0.11"},
    )

    await _apply_interrupt_result(_FakeDb(), job, exc, summary)

    assert job.status == "pending"
    assert job.queue_position == 7
    assert job.resume_after is None
    assert job.result_summary["stage"] == "queued"
    assert job.result_summary["preserved_hosts"] == 2


@pytest.mark.asyncio
async def test_record_job_progress_commits_only_on_stage_change_or_flush_interval(
    monkeypatch,
):
    db = _FakeDb()
    job = SimpleNamespace(result_summary={})
    progress_state = {"last_flush": 10.0, "last_stage": "discovery"}

    monkeypatch.setattr("app.workers.tasks.time.monotonic", lambda: 12.0)
    await _record_job_progress(
        db,
        job,
        {"event": "scan_progress", "data": {"stage": "discovery", "progress": 0.2}},
        progress_state,
    )
    assert db.commit_calls == 0

    monkeypatch.setattr("app.workers.tasks.time.monotonic", lambda: 16.0)
    await _record_job_progress(
        db,
        job,
        {"event": "scan_progress", "data": {"stage": "investigation", "progress": 0.6}},
        progress_state,
    )
    assert db.commit_calls == 1
    assert job.result_summary["stage"] == "investigation"


@pytest.mark.asyncio
async def test_parent_chunk_broadcast_scales_progress_and_records_chunk_metadata(
    monkeypatch,
):
    published = []
    recorded = []

    async def fake_record_job_progress(_db, _job, payload, _progress_state):
        recorded.append(payload)

    async def fake_publish_event(payload):
        published.append(payload)

    monkeypatch.setattr(
        "app.workers.tasks._record_job_progress", fake_record_job_progress
    )
    monkeypatch.setattr("app.workers.tasks._publish_event", fake_publish_event)

    job = SimpleNamespace(id="parent-1")
    broadcast = _build_parent_chunk_broadcast_fn(
        object(),
        job,
        {"last_flush": 0.0, "last_stage": None},
        chunk_index=2,
        chunk_count=4,
    )
    await broadcast(
        {
            "event": "scan_progress",
            "data": {"job_id": "child-2", "progress": 0.5, "message": "Scanning"},
        }
    )

    assert recorded[0]["data"]["job_id"] == "parent-1"
    assert recorded[0]["data"]["chunk_index"] == 2
    assert recorded[0]["data"]["chunk_count"] == 4
    assert recorded[0]["data"]["progress"] == 0.375
    assert recorded[0]["data"]["message"] == "Chunk 2/4: Scanning"
    assert published == recorded


def test_task_id_helpers_extract_matching_scan_jobs():
    task = {
        "name": "app.workers.tasks.run_scan_job",
        "id": "celery-1",
        "args": ["job-123"],
        "kwargs": {},
    }
    kwargs_task = {
        "name": "app.workers.tasks.run_scan_job",
        "id": "celery-2",
        "args": [],
        "kwargs": {"job_id": "job-456"},
    }
    stringified_task = {
        "name": "app.workers.tasks.run_scan_job",
        "id": "celery-3",
        "args": "('job-789',)",
        "kwargs": {},
    }

    assert _extract_scan_job_id(task, "job-123") == "job-123"
    assert _extract_scan_job_id(kwargs_task, "job-456") == "job-456"
    assert _extract_scan_job_id(stringified_task, "job-789") == "job-789"
    assert _get_scan_task_id(task, "job-123") == "celery-1"
    assert _get_scan_task_id(task, "different-job") is None


def test_interrupt_stage_and_merge_scan_summary_cover_queue_and_rollup_logic():
    parent = ScanSummary(
        job_id="job-parent", targets="10.0.0.0/24", profile=ScanProfile.BALANCED
    )
    child = ScanSummary(
        job_id="job-child", targets="10.0.0.0/25", profile=ScanProfile.BALANCED
    )
    child.hosts_scanned = 3
    child.hosts_up = 2
    child.total_open_ports = 4
    child.new_assets = 1
    child.changed_assets = 2
    child.offline_assets = 1
    child.ai_analyses_completed = 2
    child.duration_seconds = 5.43

    _merge_scan_summary(parent, child)

    assert parent.hosts_scanned == 3
    assert parent.changed_assets == 2
    assert parent.ai_analyses_completed == 2
    assert parent.duration_seconds == 5.43
    assert _interrupt_stage("pending", "paused") == "queued"
    assert _interrupt_stage("paused", "paused") == "paused"
    assert _interrupt_stage("cancelled", "cancelled") == "cancelled"
