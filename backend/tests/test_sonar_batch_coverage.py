from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from types import ModuleType
from uuid import uuid4

import pytest
import pytest_asyncio
import httpx
from fastapi import HTTPException
from starlette.requests import Request

from app.api import deps
from app.api.routes import assets as assets_routes
from app.api.routes import scans as scans_routes
from app.api.routes import system as system_routes
from app.db.models import ApiKey, Asset, AssetTag, Port, ProbeRun, ScanJob
from app.db.upsert import (
    _ai_stage_trace,
    _best_device_type_confidence,
    _apply_asset_updates,
    _autopsy_weak_points,
    _build_autopsy_trace,
    _build_device_type_candidate_trace,
    _deep_probe_stage_trace,
    _derive_asset_fields,
    _delete_existing_evidence_snapshot,
    _has_probe_evidence,
    _persistence_stage_trace,
    _probe_run_summary,
    _record_discovery_history,
    _should_persist_ai_fields,
    _should_persist_os_name,
    _store_probe_runs,
    _top_evidence_snapshot,
    _upsert_autopsy,
    _upsert_fingerprint_hypothesis,
    _upsert_internet_lookup,
    _upsert_ports,
    _upsert_single_port,
    upsert_scan_result,
    mark_offline,
)
from app.fingerprinting.evidence import extract_evidence
from app.modules import tplink_deco
from app.scanner import config as scanner_config
from app.scanner.agent import anthropic_analyst as anthropic_mod
from app.scanner.agent import ollama_analyst as ollama_mod
from app.scanner.agent import tools as agent_tools
from app.scanner.config import ScannerConfigUpdateInput
from app.scanner.models import AIAnalysis, DeviceClass, DiscoveredHost, HostScanResult, OSFingerprint, PortResult, ProbeResult, ScanProfile, ScanSummary
from app.scanner.probes import http as http_probe
from app.scanner.probes import smb as smb_probe
from app.scanner import topology as topology_mod
from app.scanner.pipeline import (
    ScanControlDecision,
    _check_control,
    _build_control_interrupt,
    _build_investigation_tasks,
    _build_partial_results,
    _call_scan_hosts,
    _cancel_pending_tasks,
    _collect_investigation_results,
    _port_details_for_host,
    _persist_investigation_result,
    _progress_payload,
    _run_discovery_stage,
    _run_deep_probe_stage,
    _run_port_scan_chunks,
    run_scan,
)
from app.scanner.stages import deep_probe
from app.scanner.stages.fingerprint import DeviceHint, probe_priority
from app.workers import tasks as worker_tasks


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        if not self._rows:
            raise LookupError("No rows")
        return self._rows[0]

    def scalars(self):
        return self


class _FakeDb:
    def __init__(self, execute_result=None, get_result=None):
        self.execute_result = execute_result
        self.get_result = get_result
        self.added = []
        self.committed = False
        self.refreshed = []
        self.executed = []

    async def execute(self, stmt):
        self.executed.append(stmt)
        return self.execute_result

    async def get(self, model, key):
        return self.get_result.get((model, key)) if isinstance(self.get_result, dict) else self.get_result

    async def commit(self):
        self.committed = True

    async def flush(self):
        return None

    async def refresh(self, obj):
        self.refreshed.append(obj)

    async def scalar(self, stmt):
        self.executed.append(stmt)
        if callable(self.execute_result):
            return self.execute_result(stmt)
        return self.execute_result

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        self.added.append(("deleted", obj))


def _request_with_headers(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in headers.items()],
    }
    return Request(scope)


async def _completed_task(value):
    return value


@pytest_asyncio.fixture(autouse=True)
async def reset_async_engine():
    yield


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    yield


def _sample_result(ip: str = "192.168.1.10") -> HostScanResult:
    return HostScanResult(
        host=DiscoveredHost(ip_address=ip, discovery_method="arp", mac_address="AA:BB:CC:DD:EE:FF", ttl=64),
        reverse_hostname="gateway.lan",
        mac_vendor="Netgate",
        os_fingerprint=OSFingerprint(os_name="Linux", os_accuracy=91, device_type="router"),
        ports=[
            PortResult(port=53, protocol="tcp", state="open", service="domain", product="dnsmasq"),
            PortResult(port=22, protocol="tcp", state="open", service="ssh"),
            PortResult(port=443, protocol="tcp", state="open", service="https"),
        ],
        probes=[
            ProbeResult(probe_type="http", target_port=443, success=True, data={"title": "pfSense", "detected_app": "pfSense"}),
            ProbeResult(probe_type="snmp", target_port=161, success=False, error="no response"),
        ],
        ai_analysis=AIAnalysis(
            device_class=DeviceClass.FIREWALL,
            confidence=0.91,
            vendor="Netgate",
            os_guess="FreeBSD",
            investigation_notes="Strong firewall evidence",
        ),
        scan_profile=ScanProfile.BALANCED,
        scan_duration_ms=321.0,
    )


def _sample_asset(ip: str = "192.168.1.10") -> Asset:
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        ip_address=ip,
        status="online",
        first_seen=now,
        last_seen=now,
    )
    return asset


@pytest.mark.asyncio
async def test_collect_investigation_results_persists_progress_and_counts(monkeypatch):
    broadcasts = []
    persisted = []
    summary = ScanSummary(job_id="job-1", targets="192.168.1.0/24", profile=ScanProfile.BALANCED)
    host_one = DiscoveredHost(ip_address="192.168.1.10")
    host_two = DiscoveredHost(ip_address="192.168.1.11")
    result_one = HostScanResult(host=host_one, probes=[ProbeResult(probe_type="http", success=True)])
    result_two = HostScanResult(host=host_two, probes=[])

    async def fake_persist(*args, **kwargs):
        persisted.append((args, kwargs))

    async def fake_progress(*args):
        broadcasts.append(args[-1])

    monkeypatch.setattr("app.scanner.pipeline._call_persist_results", fake_persist)
    monkeypatch.setattr("app.scanner.pipeline._broadcast_investigation_progress", fake_progress)

    tasks = [
        asyncio.create_task(_completed_task(result_one)),
        asyncio.create_task(_completed_task(result_two)),
    ]
    results, completed_hosts, deep_probed_hosts = await _collect_investigation_results(
        tasks,
        [host_one, host_two],
        2,
        summary,
        "db",
        None,
        "job-1",
        None,
    )

    assert results == [result_one, result_two]
    assert completed_hosts == 2
    assert deep_probed_hosts == 1
    assert len(persisted) == 2
    assert broadcasts == [result_one, result_two]


@pytest.mark.asyncio
async def test_persist_investigation_result_skips_empty_inputs(monkeypatch):
    called = False

    async def fake_persist(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.scanner.pipeline._call_persist_results", fake_persist)
    await _persist_investigation_result(None, _sample_result(), ScanSummary(job_id="1", targets="x", profile=ScanProfile.BALANCED), None, "job")
    await _persist_investigation_result("db", None, ScanSummary(job_id="1", targets="x", profile=ScanProfile.BALANCED), None, "job")

    assert called is False


def test_build_control_interrupt_preserves_discovery_results():
    summary = ScanSummary(job_id="job", targets="x", profile=ScanProfile.BALANCED)
    host_one = DiscoveredHost(ip_address="192.168.1.10")
    host_two = DiscoveredHost(ip_address="192.168.1.11")
    completed = [HostScanResult(host=host_one, scan_profile=ScanProfile.BALANCED)]
    partial = _build_partial_results([host_one, host_two], completed, ScanProfile.BALANCED)

    interrupt = _build_control_interrupt(
        ScanControlDecision(action="pause", mode="preserve_discovery", resume_after="later"),
        "investigation",
        summary,
        partial,
        completed,
    )

    assert interrupt.status == "paused"
    assert interrupt.resume_after == "later"
    assert interrupt.scanned_ips == {"192.168.1.10", "192.168.1.11"}
    assert len(interrupt.partial_results) == 2


@pytest.mark.asyncio
async def test_deep_probe_timeout_returns_probe_result():
    async def never_finishes():
        await asyncio.sleep(1)

    result = await deep_probe._with_timeout(never_finishes(), 0.01, "ssh", 22)

    assert result.success is False
    assert result.error == "Timeout after 0.01s"
    assert result.target_port == 22


@pytest.mark.asyncio
async def test_deep_probe_run_collects_exceptions_and_optional_priority(monkeypatch):
    async def fake_dns(ip: str):
        return ProbeResult(probe_type="dns", success=True, data={"hostname": ip})

    async def fake_http(ip: str, port: int, use_https: bool):
        if port == 80:
            raise RuntimeError("boom")
        return ProbeResult(probe_type="https" if use_https else "http", success=True, target_port=port, data={"port": port})

    async def fake_snmp(ip: str):
        return ProbeResult(probe_type="snmp", success=True, target_port=161, data={"sys_name": ip})

    monkeypatch.setattr(deep_probe, "_dns_probe", fake_dns)
    monkeypatch.setattr(deep_probe, "_http_probe", fake_http)
    monkeypatch.setattr(deep_probe, "_snmp_probe", fake_snmp)

    results = await deep_probe.run(
        DiscoveredHost(ip_address="192.168.1.55"),
        [
            PortResult(port=80, protocol="tcp", state="open", service="http"),
            PortResult(port=443, protocol="tcp", state="open", service="https"),
        ],
        ["snmp"],
        timeout_seconds=1,
    )

    probe_types = {result.probe_type: result for result in results}
    assert probe_types["dns"].success is True
    assert probe_types["http"].success is False
    assert "boom" in probe_types["http"].error
    assert probe_types["https"].success is True
    assert probe_types["snmp"].success is True


def test_deep_probe_priority_helpers_cover_false_and_duplicate_paths():
    open_ports = {
        443: PortResult(port=443, protocol="tcp", state="open", service="https"),
        139: PortResult(port=139, protocol="tcp", state="open", service="netbios"),
    }
    tls_duplicate = deep_probe._select_probe_port("tls", open_ports, [("tls", object())])
    smb_port = deep_probe._select_probe_port("smb", open_ports, [])

    assert tls_duplicate is None
    assert smb_port == 139
    assert deep_probe._should_run_priority_probe("mdns", open_ports, []) is False
    assert deep_probe._normalize_probe_timeout(0.2) == 1.0
    assert deep_probe._normalize_probe_timeout(45) == 30.0


def test_fingerprint_priority_and_hints_cover_router_iot_and_firewall_paths():
    hint = DeviceHint(DeviceClass.IOT_DEVICE, 0.8, "iot")
    priorities = probe_priority(
        [
            PortResult(port=1900, protocol="udp", state="open", service="upnp"),
            PortResult(port=5353, protocol="udp", state="open", service="mdns"),
            PortResult(port=80, protocol="tcp", state="open", service="http"),
        ],
        hint,
    )

    assert priorities[0] == "dns"
    assert "http" in priorities
    assert "mdns" in priorities
    assert "upnp" in priorities

    result = _sample_result()
    derived = _derive_asset_fields(result)
    assert derived[1] == "FreeBSD"
    assert derived[2] == "Netgate"
    assert derived[4] == "firewall"


def test_extract_evidence_covers_snmp_upnp_and_smb_branches():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.44", ttl=128),
        probes=[
            ProbeResult(probe_type="snmp", success=True, data={"sys_descr": "TP-Link router", "sys_name": "router", "sys_object_id": "1.3.6.1.4.1.11863.1"}),
            ProbeResult(probe_type="upnp", success=True, data={"manufacturer": "Netgate", "model_name": "6100", "friendly_name": "pfSense", "device_type": "gateway"}),
            ProbeResult(probe_type="smb", success=True, data={"os_string": "Windows 11 Pro", "netbios_name": "LABPC"}),
        ],
        ai_analysis=AIAnalysis(
            device_class=DeviceClass.WORKSTATION,
            confidence=0.66,
            vendor="Microsoft",
            model="Surface",
            os_guess="Windows 11",
            investigation_notes="workstation",
        ),
    )

    evidence = extract_evidence(result)
    values = {(item.source, item.key, item.value) for item in evidence}

    assert ("probe_snmp", "sys_name", "router") in values
    assert ("probe_upnp", "model_name", "6100") in values
    assert ("probe_smb", "netbios_name", "LABPC") in values
    assert ("ai", "vendor", "Microsoft") in values
    assert ("ai", "model", "Surface") in values
    assert ("ai", "os_guess", "Windows 11") in values


def test_tplink_log_summary_and_analysis_capture_recommendations():
    raw = """
    AP-STA-CONNECTED 20:AA:BB:CC:DD:EE
    EAPOL-4WAY-HS-COMPLETED
    Timeout waiting for 802.11k response from 20:AA:BB:CC:DD:EE
    targetBand(5) != measuredBss->band(2)
    """

    summary = tplink_deco._parse_deco_log_summary(raw)
    analysis = tplink_deco.analyze_deco_logs(raw)

    assert "wifi_client_associations: 1" in summary
    assert "unique_macs_observed: 1" in summary
    assert analysis["health_score"] < 100
    assert analysis["issues"]
    assert analysis["recommendations"]
    assert "20:AA:BB:CC:DD:EE" in analysis["observed_macs"]


def test_tplink_helpers_cover_defaults_and_decoding():
    assert tplink_deco._normalize_base_url("tplinkdeco.net") == "http://tplinkdeco.net"
    assert tplink_deco._effective_owner_username(" ") == "admin"
    assert tplink_deco._decode_deco_label("VGVzdCBMYWJlbA==") == "Test Label"
    assert tplink_deco._decode_deco_label("not-base64") == "not-base64"
    assert tplink_deco._parse_deco_log_summary(" \n ") == ""


def test_upsert_helper_traces_cover_skipped_ai_and_probe_summary():
    result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.60", discovery_method="ping"),
        scan_profile=ScanProfile.BALANCED,
        probes=[ProbeResult(probe_type="http", success=False, error="no response")],
    )
    asset = Asset(ip_address="192.168.1.60", status="online")

    weak_points = _autopsy_weak_points(result, None)
    top_evidence = _top_evidence_snapshot([])
    trace = _build_autopsy_trace(asset, result, [], None, None, None, None, "unknown")

    assert "No AI investigation was attached to this host result." in weak_points
    assert top_evidence == []
    assert _ai_stage_trace(result)["status"] == "skipped"
    assert _deep_probe_stage_trace(result)["status"] == "limited"
    assert _probe_run_summary({"banner": "SSH-2.0"}, True) == "SSH-2.0"
    assert _probe_run_summary({}, False) is None
    assert _persistence_stage_trace(asset, None, None, None)["outputs"]["manual_override_present"] is False
    assert trace["pipeline"][0]["stage"] == "discovery"
    assert trace["pipeline"][-1]["stage"] == "persistence"


@pytest.mark.asyncio
async def test_upsert_snapshot_helpers_delete_non_passive_and_store_probe_runs():
    asset = _sample_asset()
    result = _sample_result(asset.ip_address)
    evidence_row = SimpleNamespace(source="probe_http")
    passive_row = SimpleNamespace(source="passive_arp")
    probe_row = SimpleNamespace(source="snmp")
    db = _FakeDb(
        execute_result=None,
    )
    execute_results = [
        _ScalarResult([evidence_row, passive_row]),
        _ScalarResult([probe_row]),
    ]

    async def fake_execute(_stmt):
        return execute_results.pop(0)

    db.execute = fake_execute
    await _delete_existing_evidence_snapshot(db, asset)
    _store_probe_runs(db, asset, result)

    deleted = [entry for entry in db.added if isinstance(entry, tuple) and entry[0] == "deleted"]
    assert len(deleted) == 2
    assert any(isinstance(entry, ProbeRun) for entry in db.added if not isinstance(entry, tuple))


def test_apply_asset_updates_and_port_upsert_cover_override_and_service_changes():
    existing = Asset(
        ip_address="192.168.1.70",
        status="offline",
        hostname="old",
        vendor="OldVendor",
        os_name="Linux",
        device_type="router",
        device_type_source="rule",
    )
    changes = {}
    result = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.70", mac_address="AA:AA:AA:AA:AA:AA"))

    _apply_asset_updates(
        existing,
        result,
        changes,
        "new-host",
        "NewVendor",
        "FreeBSD",
        "firewall",
        "ai",
    )

    assert changes["status"]["new"] == "online"
    assert existing.hostname == "new-host"
    assert existing.mac_address == "AA:AA:AA:AA:AA:AA"

    existing_port = SimpleNamespace(port_number=443, protocol="tcp", version="1.0", service="https", state="open")
    port_changes = {}
    fake_db = _FakeDb()
    _upsert_single_port(
        fake_db,
        existing,
        {(443, "tcp"): existing_port},
        port_changes,
        (443, "tcp"),
        PortResult(port=443, protocol="tcp", state="open", service="http-alt", version="2.0"),
    )
    assert port_changes["port_443_version"]["new"] == "2.0"
    assert existing_port.service == "http-alt"


@pytest.mark.asyncio
async def test_get_current_user_handles_invalid_token_and_api_key_success(monkeypatch):
    request = _request_with_headers({"Authorization": "Bearer bad-token"})

    monkeypatch.setattr(deps, "decode_token", lambda token: None)
    with pytest.raises(HTTPException) as invalid:
        await deps.get_current_user(request, _FakeDb())
    assert invalid.value.detail == "Invalid token"

    user = SimpleNamespace(id=uuid4(), is_active=True, role="admin")
    api_key = ApiKey(user_id=user.id, key_prefix="abc", hashed_key="hashed", is_active=True)
    db = _FakeDb(execute_result=_ScalarResult([api_key]), get_result=user)
    request = _request_with_headers({"X-API-Key": "secret-token"})
    monkeypatch.setattr(deps, "api_key_prefix", lambda raw: "abc")
    monkeypatch.setattr(deps, "verify_api_key", lambda raw, hashed: True)

    current = await deps.get_current_user(request, db)

    assert current is user
    assert db.committed is True
    assert api_key.last_used_at is not None


@pytest.mark.asyncio
async def test_get_current_user_and_role_helpers_cover_remaining_auth_branches(monkeypatch):
    bearer_request = _request_with_headers({"Authorization": "Bearer good-token"})
    active_user = SimpleNamespace(id=uuid4(), is_active=True, role="admin")
    inactive_user = SimpleNamespace(id=uuid4(), is_active=False, role="admin")

    monkeypatch.setattr(deps, "decode_token", lambda token: active_user.id)
    assert await deps.get_current_user(bearer_request, _FakeDb(get_result=active_user)) is active_user

    monkeypatch.setattr(deps, "decode_token", lambda token: inactive_user.id)
    with pytest.raises(HTTPException) as inactive_exc:
        await deps.get_current_user(bearer_request, _FakeDb(get_result=inactive_user))
    assert inactive_exc.value.detail == "User not found"

    api_key_request = _request_with_headers({"X-API-Key": "bad-key"})
    monkeypatch.setattr(deps, "api_key_prefix", lambda raw: "abc")
    monkeypatch.setattr(deps, "verify_api_key", lambda raw, hashed: False)
    with pytest.raises(HTTPException) as api_exc:
        await deps.get_current_user(api_key_request, _FakeDb(execute_result=_ScalarResult([ApiKey(user_id=uuid4(), key_prefix="abc", hashed_key="hashed", is_active=True)])))
    assert api_exc.value.detail == "Invalid API key"

    with pytest.raises(HTTPException) as missing_auth:
        await deps.get_current_user(_request_with_headers({}), _FakeDb())
    assert missing_auth.value.detail == "Authentication required"

    require_viewer = deps.require_role("viewer")
    assert require_viewer(SimpleNamespace(role="viewer")) .role == "viewer"
    with pytest.raises(HTTPException) as role_exc:
        require_viewer(SimpleNamespace(role="admin"))
    assert role_exc.value.status_code == 403


def test_get_current_admin_rejects_non_admin():
    with pytest.raises(HTTPException) as exc:
        deps.get_current_admin(SimpleNamespace(role="viewer"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_route_and_pipeline_helpers_cover_fallback_paths(monkeypatch):
    async def scan_hosts_without_top_ports(hosts, profile):
        return [([], OSFingerprint(), host.ip_address, None, None) for host in hosts]

    hosts = [DiscoveredHost(ip_address="192.168.1.80"), DiscoveredHost(ip_address="192.168.1.81")]
    results = await _call_scan_hosts(scan_hosts_without_top_ports, hosts, ScanProfile.BALANCED, top_ports_count=200)
    assert len(results) == 2

    broadcasts = []

    async def fake_broadcast(_broadcast_fn, payload):
        broadcasts.append(payload)

    monkeypatch.setattr("app.scanner.pipeline._broadcast", fake_broadcast)
    monkeypatch.setattr("app.scanner.pipeline._call_scan_hosts", lambda *args, **kwargs: _completed_task([([], OSFingerprint(), hosts[0].ip_address, None, None), ([], OSFingerprint(), hosts[1].ip_address, None, None)]))
    port_map = await _run_port_scan_chunks(hosts, ScanProfile.BALANCED, 100, 1, None, "job-x", ScanSummary(job_id="job-x", targets="x", profile=ScanProfile.BALANCED))
    assert set(port_map) == {"192.168.1.80", "192.168.1.81"}
    assert len(broadcasts) == 2
    assert await _run_deep_probe_stage(False, hosts[0], [], [], 5) == []


@pytest.mark.asyncio
async def test_route_units_cover_assets_scans_and_system_paths(monkeypatch):
    captured = {}

    class _AssetsDb(_FakeDb):
        async def execute(self, stmt):
            captured["assets_stmt"] = stmt
            return _ScalarResult([])

    await assets_routes.list_assets(search="fw", status="online", tag="gateway", db=_AssetsDb(), _=object())
    compiled_assets = str(captured["assets_stmt"])
    assert "asset_tags" in compiled_assets.lower()
    assert "LIMIT" in compiled_assets

    now = datetime.now(timezone.utc)
    running = ScanJob(id=uuid4(), status="running", created_at=now, queue_position=2)
    paused = ScanJob(id=uuid4(), status="paused", created_at=now, queue_position=1)
    child = ScanJob(id=uuid4(), status="pending", created_at=now, parent_id=uuid4())
    pending = ScanJob(id=uuid4(), status="pending", created_at=now, queue_position=1)
    scans_db = _FakeDb(execute_result=_ScalarResult([pending, child, paused, running]))
    listed = await scans_routes.list_scans(scans_db, object(), limit=3)
    assert [scan.status for scan in listed] == ["running", "paused", "pending"]

    async def fake_get_config(_db):
        return SimpleNamespace()

    async def fake_create_graph(_db, *, targets, scan_type, triggered_by):
        job = ScanJob(id=uuid4(), targets=targets, scan_type=scan_type, triggered_by=triggered_by, queue_position=1)
        return job, []

    monkeypatch.setattr(scans_routes, "get_or_create_scanner_config", fake_get_config)
    monkeypatch.setattr(scans_routes, "resolve_scan_targets", lambda _config, targets: targets or "auto")
    monkeypatch.setattr(scans_routes, "materialize_scan_targets", lambda targets: f"materialized:{targets}")
    monkeypatch.setattr(scans_routes, "validate_scan_targets_routable", lambda targets: None)
    monkeypatch.setattr(scans_routes, "_create_scan_job_graph", fake_create_graph)
    monkeypatch.setattr(scans_routes, "_has_active_scan", lambda _db: asyncio.sleep(0, result=False))

    started = []

    class _Runner:
        @staticmethod
        def delay(job_id: str):
            started.append(job_id)

    monkeypatch.setattr(scans_routes, "run_scan_job", _Runner())
    trigger_db = _FakeDb()
    response = await scans_routes.trigger_scan(scans_routes.TriggerScanRequest(targets="192.168.1.0/24", scan_type="balanced"), trigger_db, object())
    assert response["status"] == "started"
    assert started == [response["job_id"]]

    payload = system_routes.ScannerConfigUpdateRequest(
        enabled=True,
        scheduled_scans_enabled=True,
        default_targets="192.168.1.0/24",
        auto_detect_targets=False,
        default_profile="balanced",
        interval_minutes=10,
        concurrent_hosts=5,
        host_chunk_size=32,
        top_ports_count=100,
        deep_probe_timeout_seconds=6,
        ai_after_scan_enabled=True,
        passive_arp_enabled=True,
        passive_arp_interface="en0",
        snmp_enabled=True,
        snmp_version="2c",
        snmp_community="public",
        snmp_timeout=5,
        snmp_v3_username=None,
        snmp_v3_auth_key=None,
        snmp_v3_priv_key=None,
        snmp_v3_auth_protocol="sha",
        snmp_v3_priv_protocol="aes",
        fingerprint_ai_enabled=False,
        fingerprint_ai_model=None,
        fingerprint_ai_min_confidence=0.75,
        fingerprint_ai_prompt_suffix=None,
        internet_lookup_enabled=False,
        internet_lookup_allowed_domains=None,
        internet_lookup_budget=2,
        internet_lookup_timeout_seconds=5,
    )

    captured_payload = {}

    async def fake_update_config(_db, payload_obj: ScannerConfigUpdateInput):
        captured_payload["payload"] = payload_obj
        now = datetime.now(timezone.utc)
        config = SimpleNamespace(
            id=1,
            enabled=True,
            scheduled_scans_enabled=True,
            default_targets="192.168.1.0/24",
            auto_detect_targets=False,
            default_profile="balanced",
            interval_minutes=10,
            concurrent_hosts=5,
            host_chunk_size=32,
            top_ports_count=100,
            deep_probe_timeout_seconds=6,
            ai_after_scan_enabled=True,
            ai_backend="ollama",
            ai_model="qwen-test",
            fingerprint_ai_backend="ollama",
            ollama_base_url="http://ollama:11434/v1",
            openai_base_url="https://api.openai.com/v1",
            openai_api_key="",
            anthropic_api_key="",
            passive_arp_enabled=True,
            passive_arp_interface="en0",
            snmp_enabled=True,
            snmp_version="2c",
            snmp_community="public",
            snmp_timeout=5,
            snmp_v3_username="",
            snmp_v3_auth_key="",
            snmp_v3_priv_key="",
            snmp_v3_auth_protocol="sha",
            snmp_v3_priv_protocol="aes",
            fingerprint_ai_enabled=False,
            fingerprint_ai_min_confidence=0.75,
            fingerprint_ai_prompt_suffix=None,
            internet_lookup_enabled=False,
            internet_lookup_allowed_domains=None,
            internet_lookup_budget=2,
            internet_lookup_timeout_seconds=5,
            last_scheduled_scan_at=None,
            created_at=now,
            updated_at=now,
        )
        effective = SimpleNamespace(
            effective_targets="192.168.1.0/24",
            enabled=True,
            scheduled_scans_enabled=True,
            default_targets="192.168.1.0/24",
            auto_detect_targets=False,
            detected_targets=None,
            default_profile="balanced",
            interval_minutes=10,
            concurrent_hosts=5,
            host_chunk_size=32,
            top_ports_count=100,
            deep_probe_timeout_seconds=6,
            ai_after_scan_enabled=True,
            ai_backend="ollama",
            ai_model="qwen-test",
            fingerprint_ai_backend="ollama",
            ollama_base_url="http://ollama:11434/v1",
            openai_base_url="https://api.openai.com/v1",
            openai_api_key="",
            anthropic_api_key="",
            passive_arp_enabled=True,
            passive_arp_interface="en0",
            snmp_enabled=True,
            snmp_version="2c",
            snmp_community="public",
            snmp_timeout=5,
            snmp_v3_username="",
            snmp_v3_auth_key="",
            snmp_v3_priv_key="",
            snmp_v3_auth_protocol="sha",
            snmp_v3_priv_protocol="aes",
            fingerprint_ai_enabled=False,
            fingerprint_ai_model="",
            fingerprint_ai_min_confidence=0.75,
            fingerprint_ai_prompt_suffix=None,
            internet_lookup_enabled=False,
            internet_lookup_allowed_domains=None,
            internet_lookup_budget=2,
            internet_lookup_timeout_seconds=5,
            last_scheduled_scan_at=None,
            next_scheduled_scan_at=now,
        )
        return config, effective

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(system_routes, "update_scanner_config", fake_update_config)
    monkeypatch.setattr(system_routes, "log_audit_event", fake_audit)
    system_db = _FakeDb()
    body = await system_routes.write_scanner_config(payload, SimpleNamespace(id=uuid4()), system_db)

    assert isinstance(captured_payload["payload"], ScannerConfigUpdateInput)
    assert captured_payload["payload"].default_targets == "192.168.1.0/24"
    assert body["effective_targets"] == "192.168.1.0/24"
    assert system_db.committed is True


@pytest.mark.asyncio
async def test_route_units_cover_assets_exports_scan_errors_and_reset(monkeypatch):
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        ip_address="192.168.1.90",
        hostname="router",
        status="online",
        first_seen=now,
        last_seen=now,
    )
    asset.tags = [AssetTag(tag="gateway")]
    asset.ports = []
    asset.ai_analysis = None

    class _AssetDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([asset])

    csv_response = await assets_routes.export_assets_csv(_AssetDb(), object())
    assert "argus-assets.csv" in csv_response.headers["Content-Disposition"]
    assert "192.168.1.90" in csv_response.body.decode()

    missing_db = _FakeDb(execute_result=_ScalarResult([]), get_result=None)
    with pytest.raises(HTTPException) as asset_exc:
        await assets_routes.get_wireless_clients(uuid4(), missing_db, object())
    assert asset_exc.value.status_code == 404

    monkeypatch.setattr(scans_routes, "get_or_create_scanner_config", lambda _db: _completed_task(SimpleNamespace()))
    monkeypatch.setattr(scans_routes, "resolve_scan_targets", lambda _config, _targets: (_ for _ in ()).throw(ValueError("bad targets")))
    with pytest.raises(HTTPException) as trigger_exc:
        await scans_routes.trigger_scan(scans_routes.TriggerScanRequest(targets="bad", scan_type="balanced"), _FakeDb(), object())
    assert trigger_exc.value.status_code == 400

    child = ScanJob(id=uuid4(), parent_id=uuid4(), status="pending")
    conflict_db = _FakeDb(get_result=child)
    with pytest.raises(HTTPException) as scan_exc:
        await scans_routes.get_scan(child.id, conflict_db, object())
    assert scan_exc.value.status_code == 409

    with pytest.raises(HTTPException) as reset_exc:
        await system_routes.reset_inventory(system_routes.ResetInventoryRequest(confirm="bad", include_scan_history=False), SimpleNamespace(id=uuid4()), _FakeDb())
    assert reset_exc.value.status_code == 400

    async def fake_clear_inventory(_db, include_scan_history: bool, actor):
        return {"assets_deleted": 3, "scans_deleted": 1, "include_scan_history": include_scan_history, "actor": str(actor.id)}

    monkeypatch.setattr(system_routes, "clear_inventory", fake_clear_inventory)
    db = _FakeDb()
    reset = await system_routes.reset_inventory(system_routes.ResetInventoryRequest(confirm="reset inventory", include_scan_history=True), SimpleNamespace(id=uuid4()), db)
    assert reset["assets_deleted"] == 3
    assert db.committed is True


@pytest.mark.asyncio
async def test_system_routes_cover_tplink_datasets_integrations_and_backup_policy(monkeypatch):
    now = datetime.now(timezone.utc)
    dataset = SimpleNamespace(
        id=1,
        key="nmap-services",
        name="Nmap Services",
        category="fingerprint",
        description="desc",
        upstream_url="https://example.com",
        local_path="/tmp/file",
        update_mode="pull",
        enabled=True,
        status="ok",
        last_checked_at=now,
        last_updated_at=now,
        upstream_last_modified="etag",
        etag="abc",
        sha256="deadbeef",
        record_count=12,
        error=None,
        notes="ready",
        created_at=now,
        updated_at=now,
    )
    monkeypatch.setattr(system_routes, "list_backup_drivers", lambda: [{"id": "ssh"}])
    monkeypatch.setattr(system_routes, "list_plugins", lambda: [{"name": "demo"}])
    monkeypatch.setattr(system_routes, "list_integration_events", lambda: [{"event": "scan_complete"}])
    monkeypatch.setattr(system_routes, "list_datasets", lambda db: _completed_task([dataset]))
    monkeypatch.setattr(system_routes, "refresh_dataset", lambda db, key: _completed_task(dataset) if key == "nmap-services" else (_ for _ in ()).throw(ValueError("missing dataset")))
    monkeypatch.setattr(system_routes, "log_audit_event", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr(system_routes, "build_home_assistant_entities", lambda assets: {"entities": len(assets)})
    monkeypatch.setattr(system_routes, "build_inventory_snapshot", lambda assets: {"assets": len(assets)})
    monkeypatch.setattr(system_routes, "get_backup_policy", lambda db: _completed_task(SimpleNamespace(
        id=3,
        enabled=True,
        interval_minutes=60,
        tag_filter="gateway",
        retention_count=5,
        last_run_at=now,
        created_at=now,
        updated_at=now,
    )))
    monkeypatch.setattr(system_routes, "update_backup_policy", lambda db, **kwargs: _completed_task(SimpleNamespace(
        id=4,
        enabled=kwargs["enabled"],
        interval_minutes=kwargs["interval_minutes"],
        tag_filter=kwargs["tag_filter"],
        retention_count=kwargs["retention_count"],
        last_run_at=None,
        created_at=now,
        updated_at=now,
    )))

    class _SystemDb(_FakeDb):
        async def execute(self, stmt):
            self.executed.append(stmt)
            return _ScalarResult([])

    db = _SystemDb()
    assert await system_routes.get_backup_drivers(object()) == [{"id": "ssh"}]
    assert await system_routes.get_plugins(object()) == [{"name": "demo"}]
    assert await system_routes.get_integration_events(object()) == [{"event": "scan_complete"}]
    datasets = await system_routes.get_fingerprint_datasets(object(), db)
    assert datasets[0]["key"] == "nmap-services"
    assert db.committed is True

    refreshed = await system_routes.refresh_fingerprint_dataset("nmap-services", SimpleNamespace(id=uuid4()), _FakeDb())
    assert refreshed["record_count"] == 12
    with pytest.raises(HTTPException) as refresh_exc:
        await system_routes.refresh_fingerprint_dataset("missing", SimpleNamespace(id=uuid4()), _FakeDb())
    assert refresh_exc.value.status_code == 404

    ha = await system_routes.get_home_assistant_entities(object(), _SystemDb())
    inventory = await system_routes.get_inventory_sync_export(object(), _SystemDb())
    assert ha == {"entities": 0}
    assert inventory["snapshot"] == {"assets": 0}

    policy = await system_routes.read_backup_policy(object(), _FakeDb())
    assert policy["tag_filter"] == "gateway"
    updated_policy = await system_routes.write_backup_policy(
        system_routes.BackupPolicyUpdateRequest(enabled=False, interval_minutes=30, tag_filter="lab", retention_count=3),
        object(),
        _FakeDb(),
    )
    assert updated_policy["enabled"] is False


@pytest.mark.asyncio
async def test_system_routes_cover_tplink_module_error_branches(monkeypatch):
    now = datetime.now(timezone.utc)
    config = SimpleNamespace(
        id=8,
        enabled=True,
        base_url="http://tplinkdeco.net",
        owner_username=None,
        owner_password="secret",
        fetch_connected_clients=True,
        fetch_portal_logs=True,
        request_timeout_seconds=10,
        verify_tls=False,
        last_tested_at=now,
        last_sync_at=now,
        last_status="healthy",
        last_error=None,
        last_client_count=1,
        created_at=now,
        updated_at=now,
    )
    run = SimpleNamespace(id=1, status="done", client_count=1, clients_payload=[], logs_excerpt=None, log_analysis={}, error=None, started_at=now, finished_at=now)
    monkeypatch.setattr(system_routes, "get_or_create_tplink_deco_config", lambda db: _completed_task(config))
    monkeypatch.setattr(system_routes, "list_recent_tplink_deco_sync_runs", lambda db: _completed_task([run]))
    monkeypatch.setattr(system_routes, "update_tplink_deco_config", lambda db, **kwargs: _completed_task(config))
    monkeypatch.setattr(system_routes, "audit_tplink_config_change", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr(system_routes, "log_audit_event", lambda *args, **kwargs: _completed_task(None))

    module_body = await system_routes.get_tplink_deco_module(object(), _FakeDb())
    assert module_body["config"]["id"] == 8
    assert module_body["recent_runs"][0]["id"] == 1

    written = await system_routes.write_tplink_deco_module(
        system_routes.TplinkDecoConfigUpdateRequest(enabled=True),
        SimpleNamespace(id=uuid4()),
        _FakeDb(),
    )
    assert written["id"] == 8

    monkeypatch.setattr(system_routes, "test_tplink_deco_connection", lambda db: (_ for _ in ()).throw(ValueError("missing password")))
    with pytest.raises(HTTPException) as test_bad_req:
        await system_routes.test_tplink_deco_module(SimpleNamespace(id=uuid4()), _FakeDb())
    assert test_bad_req.value.status_code == 400

    monkeypatch.setattr(system_routes, "test_tplink_deco_connection", lambda db: (_ for _ in ()).throw(RuntimeError("connect failed")))
    with pytest.raises(HTTPException) as test_bad_gateway:
        await system_routes.test_tplink_deco_module(SimpleNamespace(id=uuid4()), _FakeDb())
    assert test_bad_gateway.value.status_code == 502

    monkeypatch.setattr(system_routes, "sync_tplink_deco_module", lambda db: (_ for _ in ()).throw(ValueError("disabled")))
    with pytest.raises(HTTPException) as sync_bad_req:
        await system_routes.run_tplink_deco_module_sync(SimpleNamespace(id=uuid4()), _FakeDb())
    assert sync_bad_req.value.status_code == 400

    monkeypatch.setattr(system_routes, "sync_tplink_deco_module", lambda db: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(HTTPException) as sync_bad_gateway:
        await system_routes.run_tplink_deco_module_sync(SimpleNamespace(id=uuid4()), _FakeDb())
    assert sync_bad_gateway.value.status_code == 502


@pytest.mark.asyncio
async def test_assets_routes_cover_additional_exports_and_backup_error_paths(monkeypatch):
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        ip_address="192.168.1.15",
        hostname="nas",
        status="offline",
        first_seen=now,
        last_seen=now,
    )
    asset.tags = [AssetTag(tag="storage")]
    asset.ports = []
    asset.ai_analysis = None

    scalar_counts = iter([2, 5, 1, 2, 1])
    history_entry = SimpleNamespace(asset_id=asset.id, change_type="updated", changed_at=now, diff={"field": "vendor"})

    class _AssetsReportDb(_FakeDb):
        async def execute(self, stmt):
            self.executed.append(stmt)
            text = str(stmt)
            if "asset_history" in text.lower():
                return _ScalarResult([history_entry])
            return _ScalarResult([asset])

        async def scalar(self, stmt):
            self.executed.append(stmt)
            return next(scalar_counts)

    report_db = _AssetsReportDb()
    monkeypatch.setattr(assets_routes, "render_ansible_inventory", lambda assets: "ansible")
    monkeypatch.setattr(assets_routes, "render_terraform_inventory", lambda assets: '{"terraform":true}')
    monkeypatch.setattr(assets_routes, "build_inventory_snapshot", lambda assets: {"count": len(assets)})

    assert (await assets_routes.export_assets_ansible(report_db, object())).body.decode() == "ansible"
    assert (await assets_routes.export_assets_terraform(report_db, object())).body.decode() == '{"terraform":true}'
    assert await assets_routes.export_assets_inventory_json(report_db, object()) == {"count": 1}
    report_json = await assets_routes.export_assets_report_json(report_db, object())
    assert report_json["summary"]["total_findings"] == 5
    assert report_json["recent_changes"][0]["change_type"] == "updated"
    report_html = await assets_routes.export_assets_report_html(report_db, object())
    assert "Argus Inventory Report" in report_html.body.decode()

    with pytest.raises(HTTPException) as update_422:
        await assets_routes.update_asset(asset.id, {"device_type": "not-real"}, _FakeDb(get_result=asset), object())
    assert update_422.value.status_code == 422

    missing_db = _FakeDb(get_result=None)
    with pytest.raises(HTTPException) as history_missing:
        await assets_routes.get_asset_history(uuid4(), missing_db, object())
    assert history_missing.value.status_code == 404
    with pytest.raises(HTTPException) as ports_missing:
        await assets_routes.get_asset_ports(uuid4(), missing_db, object())
    assert ports_missing.value.status_code == 404

    existing_tag_db = _FakeDb(get_result=asset, execute_result=_ScalarResult([AssetTag(asset_id=asset.id, tag="storage")]))
    with pytest.raises(HTTPException) as tag_conflict:
        await assets_routes.add_asset_tag(asset.id, assets_routes.AssetTagRequest(tag="storage"), existing_tag_db, object())
    assert tag_conflict.value.status_code == 409

    read_target_db = _FakeDb(get_result=asset)
    monkeypatch.setattr(assets_routes, "get_backup_target", lambda db, asset_id: _completed_task(None))
    assert await assets_routes.read_config_backup_target(asset.id, read_target_db, object()) is None

    monkeypatch.setattr(assets_routes, "upsert_backup_target", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("invalid driver")))
    with pytest.raises(HTTPException) as backup_target_bad:
        await assets_routes.write_config_backup_target(
            asset.id,
            assets_routes.ConfigBackupTargetRequest(driver="bad", username="user"),
            _FakeDb(get_result=asset),
            object(),
        )
    assert backup_target_bad.value.status_code == 400

    monkeypatch.setattr(assets_routes, "capture_backup_for_asset", lambda db, asset_id: (_ for _ in ()).throw(LookupError("not found")))
    with pytest.raises(HTTPException) as backup_lookup:
        await assets_routes.trigger_config_backup(asset.id, _FakeDb(), object())
    assert backup_lookup.value.status_code == 404

    monkeypatch.setattr(assets_routes, "capture_backup_for_asset", lambda db, asset_id: (_ for _ in ()).throw(RuntimeError("capture failed")))
    with pytest.raises(HTTPException) as backup_runtime:
        await assets_routes.trigger_config_backup(asset.id, _FakeDb(), object())
    assert backup_runtime.value.status_code == 400

    monkeypatch.setattr(assets_routes, "get_backup_snapshot", lambda db, asset_id, snapshot_id: _completed_task(SimpleNamespace(content=None)))
    with pytest.raises(HTTPException) as download_missing:
        await assets_routes.download_config_backup(asset.id, 1, _FakeDb(), object())
    assert download_missing.value.status_code == 404

    monkeypatch.setattr(assets_routes, "generate_backup_diff", lambda *args, **kwargs: (_ for _ in ()).throw(LookupError("missing diff")))
    with pytest.raises(HTTPException) as diff_missing:
        await assets_routes.diff_config_backup(asset.id, 1, None, _FakeDb(), object())
    assert diff_missing.value.status_code == 404

    monkeypatch.setattr(assets_routes, "generate_restore_assist", lambda *args, **kwargs: (_ for _ in ()).throw(LookupError("missing restore")))
    with pytest.raises(HTTPException) as restore_missing:
        await assets_routes.get_restore_assist(asset.id, 1, _FakeDb(), object())
    assert restore_missing.value.status_code == 404


@pytest.mark.asyncio
async def test_assets_routes_cover_success_paths_for_asset_views_and_backups(monkeypatch):
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid4(),
        ip_address="192.168.1.44",
        hostname="edge-gw",
        mac_address="AA:BB:CC:DD:EE:44",
        vendor="Netgate",
        status="online",
        first_seen=now,
        last_seen=now,
    )
    asset.tags = [AssetTag(tag="gateway")]
    asset.ports = [Port(port_number=443, protocol="tcp", service="https", version="1.0", state="open")]
    scan_ports = [PortResult(port=443, protocol="tcp", service="https", version="1.0", state="open")]
    asset.history = []
    asset.ai_analysis = None
    asset.evidence = []
    asset.probe_runs = []
    asset.observations = []
    asset.fingerprint_hypotheses = []
    asset.internet_lookup_results = []
    asset.lifecycle_records = []
    asset.autopsy = None

    snapshot = SimpleNamespace(
        id=7,
        asset_id=asset.id,
        target_id=3,
        status="done",
        driver="ssh",
        command="show run",
        content="running-config",
        error=None,
        captured_at=now,
    )
    backup_target = SimpleNamespace(
        id=4,
        asset_id=asset.id,
        driver="ssh",
        username="admin",
        password_env_var="BACKUP_PASSWORD",
        port=22,
        host_override="192.168.1.99",
        enabled=True,
        created_at=now,
        updated_at=now,
    )
    association = SimpleNamespace(
        id=11,
        access_point_asset_id=asset.id,
        client_asset_id=None,
        client_mac="CC:DD:EE:FF:00:11",
        client_ip="192.168.1.88",
        ssid="Argus",
        band="5GHz",
        signal_dbm=-45,
        source="snmp",
        first_seen=now,
        last_seen=now,
    )

    class _RichAssetDb(_FakeDb):
        async def execute(self, stmt):
            self.executed.append(stmt)
            text = str(stmt).lower()
            if "wireless_associations" in text:
                return _ScalarResult([association])
            if "asset_history" in text:
                return _ScalarResult([SimpleNamespace(id=1, asset_id=asset.id, change_type="updated", changed_at=now)])
            if "ports" in text and "from ports" in text:
                return _ScalarResult(asset.ports)
            return _ScalarResult([asset])

    db = _RichAssetDb(get_result=asset)
    monkeypatch.setattr(assets_routes, "get_backup_target", lambda db, asset_id: _completed_task(backup_target))
    monkeypatch.setattr(assets_routes, "list_backup_snapshots", lambda db, asset_id: _completed_task([snapshot]))
    monkeypatch.setattr(assets_routes, "capture_backup_for_asset", lambda db, asset_id: _completed_task(snapshot))
    monkeypatch.setattr(assets_routes, "get_backup_snapshot", lambda db, asset_id, snapshot_id: _completed_task(snapshot))
    monkeypatch.setattr(assets_routes, "generate_backup_diff", lambda *args, **kwargs: _completed_task(""))
    monkeypatch.setattr(assets_routes, "generate_restore_assist", lambda *args, **kwargs: _completed_task({"steps": ["restore"]}))
    monkeypatch.setattr(assets_routes.portscan, "scan_host", lambda host, profile: _completed_task((scan_ports, OSFingerprint(os_name="Linux"))))
    monkeypatch.setattr(assets_routes, "_load_asset", lambda db, asset_id: _completed_task(asset))
    monkeypatch.setattr("app.db.upsert.upsert_scan_result", lambda db, result: _completed_task(None))
    monkeypatch.setattr(
        assets_routes,
        "_investigate_host",
        lambda **kwargs: _completed_task(
                HostScanResult(
                    host=kwargs["host"],
                    ports=scan_ports,
                    os_fingerprint=kwargs["os_fp"],
                    reverse_hostname="edge-gw",
                    scan_profile=ScanProfile.BALANCED,
            )
        ),
    )

    serialized = await assets_routes.get_asset(asset.id, db, object())
    assert serialized["ip_address"] == "192.168.1.44"
    assert serialized["ports"][0]["port_number"] == 443
    assert serialized["tags"][0]["tag"] == "gateway"
    assert await assets_routes.get_asset_evidence(asset.id, db, object()) == []
    assert await assets_routes.get_asset_probe_runs(asset.id, db, object()) == []

    refreshed = await assets_routes.update_asset(asset.id, {"hostname": "edge", "device_type": "router"}, _FakeDb(get_result=asset, execute_result=_ScalarResult([asset])), object())
    assert refreshed["hostname"] == "edge"

    await assets_routes.delete_asset(asset.id, _FakeDb(get_result=asset), object())
    history = await assets_routes.get_asset_history(asset.id, db, object())
    ports = await assets_routes.get_asset_ports(asset.id, db, object())
    wireless = await assets_routes.get_wireless_clients(asset.id, db, object())
    assert history[0].change_type == "updated"
    assert ports[0].port_number == 443
    assert wireless[0]["ssid"] == "Argus"

    tag_db = _FakeDb(get_result=asset, execute_result=_ScalarResult([]))
    created_tag = await assets_routes.add_asset_tag(asset.id, assets_routes.AssetTagRequest(tag=" Core "), tag_db, object())
    assert created_tag.tag == "core"
    await assets_routes.delete_asset_tag(asset.id, "core", _FakeDb(execute_result=_ScalarResult([created_tag])), object())

    read_target = await assets_routes.read_config_backup_target(asset.id, db, object())
    backups = await assets_routes.get_config_backups(asset.id, db, object())
    backup = await assets_routes.trigger_config_backup(asset.id, db, object())
    download = await assets_routes.download_config_backup(asset.id, 7, db, object())
    diff = await assets_routes.diff_config_backup(asset.id, 7, None, db, object())
    restore = await assets_routes.get_restore_assist(asset.id, 7, db, object())
    assert read_target["driver"] == "ssh"
    assert backups[0]["id"] == 7
    assert backup["status"] == "done"
    assert download.body.decode() == "running-config"
    assert diff.body.decode() == "No diff\n"
    assert restore == {"steps": ["restore"]}

    port_scan = await assets_routes.run_asset_port_scan(asset.id, db, object())
    ai_refresh = await assets_routes.run_asset_ai_refresh(asset.id, db, object())
    assert port_scan["ip_address"] == "192.168.1.44"
    assert ai_refresh["hostname"] == "edge"


def test_scanner_config_helpers_cover_normalization_and_routing(monkeypatch):
    config = SimpleNamespace(
        enabled=True,
        default_targets=None,
        auto_detect_targets=False,
        default_profile="balanced",
        interval_minutes=0,
        concurrent_hosts=1,
        host_chunk_size=0,
        top_ports_count=1,
        deep_probe_timeout_seconds=60,
        ai_after_scan_enabled=True,
        passive_arp_enabled=True,
        passive_arp_interface=" ",
        snmp_enabled=False,
        snmp_version="V3",
        snmp_community=" ",
        snmp_timeout=0,
        snmp_v3_username=" user ",
        snmp_v3_auth_key=" auth ",
        snmp_v3_priv_key=" priv ",
        snmp_v3_auth_protocol="SHA",
        snmp_v3_priv_protocol="AES",
        fingerprint_ai_enabled=False,
        fingerprint_ai_model=" ",
        fingerprint_ai_min_confidence=2.0,
        fingerprint_ai_prompt_suffix=" ",
        internet_lookup_enabled=False,
        internet_lookup_allowed_domains=" ",
        internet_lookup_budget=0,
        internet_lookup_timeout_seconds=0,
        last_scheduled_scan_at=None,
    )

    scanner_config._apply_core_scanner_settings(
        config,
        enabled=True,
        normalized_targets=None,
        auto_detect_targets=False,
        default_profile="balanced",
        interval_minutes=15,
        concurrent_hosts=4,
        host_chunk_size=999,
        top_ports_count=5,
        deep_probe_timeout_seconds=99,
        ai_after_scan_enabled=False,
        passive_arp_enabled=False,
        passive_arp_interface=" ",
    )
    scanner_config._apply_snmp_settings(
        config,
        snmp_enabled=True,
        snmp_version="V3",
        snmp_community=" ",
        snmp_timeout=0,
        snmp_v3_username=" user ",
        snmp_v3_auth_key=" auth ",
        snmp_v3_priv_key=" priv ",
        snmp_v3_auth_protocol="SHA",
        snmp_v3_priv_protocol="AES",
    )
    scanner_config._apply_ai_and_lookup_settings(
        config,
        fingerprint_ai_enabled=True,
        fingerprint_ai_model=" ",
        fingerprint_ai_min_confidence=2.0,
        fingerprint_ai_prompt_suffix=" ",
        internet_lookup_enabled=True,
        internet_lookup_allowed_domains=" example.com ",
        internet_lookup_budget=0,
        internet_lookup_timeout_seconds=0,
    )

    assert scanner_config._normalize_optional_text("  hello  ") == "hello"
    assert config.host_chunk_size == 256
    assert config.top_ports_count == 10
    assert config.deep_probe_timeout_seconds == 30
    assert config.passive_arp_interface == scanner_config.settings.SCANNER_PASSIVE_ARP_INTERFACE
    assert config.snmp_version == "v3"
    assert config.snmp_timeout == 1
    assert config.snmp_v3_username == "user"
    assert config.fingerprint_ai_min_confidence == 1.0
    assert config.internet_lookup_budget == 1
    assert config.internet_lookup_timeout_seconds == 1

    monkeypatch.setattr(scanner_config, "_iter_ipv4_route_networks", lambda: [])
    assert scanner_config.validate_scan_targets_routable("192.168.1.0/24") is None

    monkeypatch.setattr(
        scanner_config,
        "_iter_ipv4_route_networks",
        lambda: [scanner_config.ipaddress.ip_network("192.168.65.0/24")],
    )
    route_error = scanner_config.validate_scan_targets_routable("10.0.0.0/24")
    assert "not routable" in route_error
    assert "Docker Desktop" in route_error

    split_targets = scanner_config.split_scan_targets("10.0.0.0/23 192.168.1.10", max_network_prefix=24, max_ip_group_size=1)
    assert "10.0.0.0/24" in split_targets
    assert "10.0.1.0/24" in split_targets
    assert "192.168.1.10/32" in split_targets

    default_config = SimpleNamespace(default_targets=" 192.168.1.0/24 ", auto_detect_targets=False)
    assert scanner_config.resolve_scan_targets(default_config, "10.0.0.0/24") == "10.0.0.0/24"
    assert scanner_config.resolve_scan_targets(default_config, None) == "192.168.1.0/24"
    assert scanner_config.resolve_scan_targets(SimpleNamespace(default_targets=None, auto_detect_targets=True), None) == scanner_config.AUTO_TARGET_SENTINEL
    with pytest.raises(ValueError):
        scanner_config.resolve_scan_targets(SimpleNamespace(default_targets=None, auto_detect_targets=False), None)

    monkeypatch.setattr(scanner_config, "detect_local_ipv4_cidr", lambda: "192.168.1.0/24")
    assert scanner_config.materialize_scan_targets(scanner_config.AUTO_TARGET_SENTINEL) == "192.168.1.0/24"
    monkeypatch.setattr(scanner_config, "detect_local_ipv4_cidr", lambda: None)
    with pytest.raises(RuntimeError):
        scanner_config.materialize_scan_targets(scanner_config.AUTO_TARGET_SENTINEL)


def test_scanner_config_scheduling_and_evidence_helpers():
    now = datetime.now(timezone.utc)
    scheduled = SimpleNamespace(scheduled_scans_enabled=True, interval_minutes=30, last_scheduled_scan_at=now)
    assert scanner_config.should_enqueue_scheduled_scan(SimpleNamespace(scheduled_scans_enabled=False, interval_minutes=30, last_scheduled_scan_at=None)) is False
    assert scanner_config.should_enqueue_scheduled_scan(SimpleNamespace(scheduled_scans_enabled=True, interval_minutes=0, last_scheduled_scan_at=None)) is False
    assert scanner_config.should_enqueue_scheduled_scan(SimpleNamespace(scheduled_scans_enabled=True, interval_minutes=30, last_scheduled_scan_at=None)) is True
    assert scanner_config.should_enqueue_scheduled_scan(scheduled, now=now) is False
    assert scanner_config.should_enqueue_scheduled_scan(scheduled, now=now + timedelta(minutes=31))
    assert scanner_config.compute_next_scheduled_scan_at(SimpleNamespace(scheduled_scans_enabled=False, interval_minutes=30, last_scheduled_scan_at=None), now=now) is None
    assert scanner_config.compute_next_scheduled_scan_at(SimpleNamespace(scheduled_scans_enabled=True, interval_minutes=30, last_scheduled_scan_at=None), now=now) == now

    empty = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.1"))
    rich = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.2", mac_address="AA:BB:CC:DD:EE:FF"),
        probes=[ProbeResult(probe_type="http", success=True, data={"title": "ok"})],
        ai_analysis=AIAnalysis(device_class=DeviceClass.ROUTER, confidence=0.8),
    )
    assert scanner_config.has_meaningful_scan_evidence(empty) is False
    assert scanner_config.has_meaningful_scan_evidence(rich) is True


@pytest.mark.asyncio
async def test_smb_probe_async_wrapper_covers_success_and_error_paths(monkeypatch):
    monkeypatch.setattr(
        smb_probe,
        "_smb_probe_sync",
        lambda ip, port: smb_probe.SmbProbeData(
            netbios_name="LABPC",
            workgroup="WORKGROUP",
            os_string="Windows 11",
            smb_version="SMBv3.1.1",
            signing_required=True,
            shares=["IPC$", "Users"],
            has_guest_access=False,
        ),
    )
    success = await smb_probe.probe("192.168.1.20", port=445)
    assert success.success is True
    assert success.data["netbios_name"] == "LABPC"
    assert "SMB Version: SMBv3.1.1" in success.raw

    async def raise_timeout(awaitable, deadline_seconds):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(smb_probe, "_await_with_deadline", raise_timeout)
    timeout = await smb_probe.probe("192.168.1.20", port=445)
    assert timeout.success is False
    assert timeout.error == "Timeout"

    async def raise_error(awaitable, deadline_seconds):
        raise RuntimeError("broken smb")

    monkeypatch.setattr(smb_probe, "_await_with_deadline", raise_error)
    failed = await smb_probe.probe("192.168.1.20", port=445)
    assert failed.success is False
    assert failed.error == "broken smb"

    async def return_none(awaitable, deadline_seconds):
        return None

    monkeypatch.setattr(smb_probe, "_await_with_deadline", return_none)
    no_data = await smb_probe.probe("192.168.1.20", port=445)
    assert no_data.success is False
    assert no_data.error == "SMB probe returned no data"


def test_smb_probe_sync_covers_impacket_and_netbios_fallback(monkeypatch):
    class _Conn:
        def __init__(self, remote_name, remote_host, sess_port, timeout):
            self.closed = False

        def getDialect(self):
            return 0x0311

        def isSigningRequired(self):
            return True

        def getServerName(self):
            return "LABNAS"

        def getServerOS(self):
            return "Samba 4.19"

        def getServerDomain(self):
            return "WORKGROUP"

        def login(self, user, password):
            return None

        def listShares(self):
            return [{"shi1_netname": "IPC$\x00"}, {"shi1_netname": "Media\x00"}]

        def close(self):
            self.closed = True

    impacket_mod = ModuleType("impacket")
    smb_mod = ModuleType("impacket.smb")
    smb_mod.SMB_DIALECT = 0x00
    smb3_mod = ModuleType("impacket.smb3")
    smb3_mod.SMB2_DIALECT_21 = 0x0210
    smb3_mod.SMB2_DIALECT_30 = 0x0300
    smb3_mod.SMB2_DIALECT_311 = 0x0311
    smbconnection_mod = ModuleType("impacket.smbconnection")
    smbconnection_mod.SMBConnection = _Conn
    impacket_mod.smb = smb_mod
    impacket_mod.smb3 = smb3_mod

    monkeypatch.setitem(sys.modules, "impacket", impacket_mod)
    monkeypatch.setitem(sys.modules, "impacket.smb", smb_mod)
    monkeypatch.setitem(sys.modules, "impacket.smb3", smb3_mod)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smbconnection_mod)

    data = smb_probe._smb_probe_sync("192.168.1.21", 445)
    assert data.netbios_name == "LABNAS"
    assert data.smb_version == "SMBv3.1.1"
    assert data.shares == ["IPC$", "Media"]
    assert data.has_guest_access is True

    monkeypatch.delitem(sys.modules, "impacket.smbconnection", raising=False)
    monkeypatch.delitem(sys.modules, "impacket.smb", raising=False)
    monkeypatch.delitem(sys.modules, "impacket.smb3", raising=False)
    monkeypatch.delitem(sys.modules, "impacket", raising=False)
    monkeypatch.setattr(smb_probe, "_netbios_name_query", lambda ip: "FALLBACKHOST")
    fallback = smb_probe._smb_probe_sync("192.168.1.22", 445)
    assert fallback.netbios_name == "FALLBACKHOST"
    monkeypatch.setattr(smb_probe, "_netbios_name_query", lambda ip: None)
    assert smb_probe._smb_probe_sync("192.168.1.23", 445) is None


def test_netbios_name_query_covers_parse_and_failure(monkeypatch):
    import socket

    workstation_name = b"WORKSTATION    "[:15]
    response = (
        b"\x00" * 56
        + bytes([1])
        + workstation_name
        + bytes([0x00])
        + b"\x00\x00"
    )

    class _UdpSocket:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def settimeout(self, value):
            return None

        def sendto(self, payload, addr):
            self.payload = payload
            self.addr = addr

        def recvfrom(self, size):
            return response, ("192.168.1.30", 137)

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: _UdpSocket())
    assert smb_probe._netbios_name_query("192.168.1.30") == "WORKSTATION"

    class _BadSocket(_UdpSocket):
        def recvfrom(self, size):
            return b"short", ("192.168.1.30", 137)

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: _BadSocket())
    assert smb_probe._netbios_name_query("192.168.1.30") is None


@pytest.mark.asyncio
async def test_agent_backends_cover_anthropic_ollama_and_tool_dispatch(monkeypatch):
    hint = SimpleNamespace(device_class=DeviceClass.ROUTER, confidence=0.8, reason="gateway traits")
    result = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.50"), ports=[PortResult(port=443, protocol="tcp", state="open")])

    anthropic = object.__new__(anthropic_mod.AnthropicAnalyst)
    anthropic.client = SimpleNamespace()
    anthropic.model = "claude-test"
    monkeypatch.setattr(anthropic, "_build_investigation_seed", lambda res: (hint, "seed-context"))
    tool_calls = [SimpleNamespace(type="tool_use", name="probe_http", input={"port": 443}, id="tool-1")]
    final_tool_call = SimpleNamespace(type="tool_use", name="final_analysis", input={"device_class": "router", "confidence": 0.9, "investigation_notes": "done"}, id="tool-2")
    messages = iter(
        [
            SimpleNamespace(content=tool_calls, stop_reason="tool_use"),
            SimpleNamespace(content=[final_tool_call], stop_reason="end_turn"),
        ]
    )

    class _AnthropicStream:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get_final_message(self):
            return next(messages)

    anthropic.client.messages = SimpleNamespace(stream=lambda **kwargs: _AnthropicStream())
    monkeypatch.setattr(anthropic_mod, "execute", lambda name, args, ip: _completed_task("http ok"))
    analysis = await anthropic.investigate(result)
    assert analysis.ai_backend == "anthropic"
    assert analysis.model_used == "claude-test"
    assert analysis.device_class == DeviceClass.ROUTER
    assert analysis.agent_steps == 2

    anthropic_fallback = object.__new__(anthropic_mod.AnthropicAnalyst)
    anthropic_fallback.client = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))))
    anthropic_fallback.model = "claude-test"
    monkeypatch.setattr(anthropic_fallback, "_build_investigation_seed", lambda res: (hint, "seed-context"))
    fallback = await anthropic_fallback.investigate(result)
    assert fallback.ai_backend == "anthropic"
    assert "Heuristic" in fallback.investigation_notes

    tool_results = await anthropic._handle_tool_calls([SimpleNamespace(name="probe_http", input={"port": 443}, id="tool-1")], "192.168.1.50")
    assert tool_results[0] is None
    assert tool_results[1][0]["type"] == "tool_result"
    anthropic_messages = []
    anthropic._request_final_analysis(anthropic_messages, 3)
    assert anthropic_messages[-1]["content"] == "Please call final_analysis now."

    ollama = object.__new__(ollama_mod.OllamaAnalyst)
    ollama.client = SimpleNamespace()
    ollama.model = "qwen-test"
    monkeypatch.setattr(ollama, "_build_investigation_seed", lambda res: (hint, "seed-context"))
    responses = iter(
        [
            SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[SimpleNamespace(id="1", function=SimpleNamespace(name="probe_http", arguments='{"port": 443}'))]))]),
            SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[SimpleNamespace(id="2", function=SimpleNamespace(name="final_analysis", arguments='{"device_class":"router","confidence":0.91,"investigation_notes":"done"}'))]))]),
        ]
    )
    ollama.client.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: _completed_task(next(responses))))
    monkeypatch.setattr(ollama_mod, "execute", lambda name, args, ip: _completed_task("tool ok"))
    ollama_analysis = await ollama.investigate(result)
    assert ollama_analysis.ai_backend == "ollama"
    assert ollama_analysis.model_used == "qwen-test"
    assert ollama_analysis.agent_steps == 2

    assert ollama._parse_tool_args('{"a":1}') == {"a": 1}
    assert ollama._parse_tool_args("{bad") == {}
    ollama_messages = []
    final_args = await ollama._handle_tool_calls(
        ollama_messages,
        [SimpleNamespace(id="f", function=SimpleNamespace(name="final_analysis", arguments='{"device_class":"router"}'))],
        "192.168.1.50",
    )
    assert final_args == {"device_class": "router"}
    ollama._request_final_analysis(ollama_messages, 3)
    assert "Please call final_analysis now" in ollama_messages[-1]["content"]

    monkeypatch.setattr(agent_tools, "_TOOL_EXECUTORS", {
        "probe_http": lambda ip, args: _completed_task(ProbeResult(probe_type="http", success=True, raw="raw http", data={"ok": True})),
        "probe_tls": lambda ip, args: (_ for _ in ()).throw(RuntimeError("tls failed")),
    })
    assert await agent_tools.execute("probe_http", {"port": 80}, "192.168.1.50") == "raw http"
    assert "tls failed" in await agent_tools.execute("probe_tls", {}, "192.168.1.50")
    assert await agent_tools.execute("unknown", {}, "192.168.1.50") == "Unknown tool: unknown"


@pytest.mark.asyncio
async def test_http_probe_helpers_cover_success_and_error_branches(monkeypatch):
    body = "<html><title>Home Assistant</title><body>dashboard</body></html>"
    resp = httpx.Response(
        200,
        text=body,
        headers={"content-type": "text/html", "server": "nginx", "x-powered-by": "Home Assistant"},
        request=httpx.Request("GET", "http://192.168.1.60:8123/"),
    )
    data = http_probe.HttpProbeData(url="http://192.168.1.60:8123")
    http_probe._apply_main_response(data, resp, "192.168.1.60")
    http_probe._apply_response_body(data, body)
    assert data.status_code == 200
    assert data.title == "Home Assistant"
    assert data.detected_app == "Home Assistant"

    redirect_resp = httpx.Response(
        200,
        text="ok",
        headers={},
        request=httpx.Request("GET", "http://192.168.1.60:80/"),
        history=[httpx.Response(302, headers={"location": "https://router.local"}, request=httpx.Request("GET", "http://192.168.1.60:80/"))],
    )
    redirect_resp._request = httpx.Request("GET", "https://router.local/")
    redirect_resp._content = b"ok"
    http_probe._apply_main_response(data, redirect_resp, "192.168.1.60")
    assert data.redirect_host == "router.local"
    assert http_probe._detect_app("Apache", None, None, None, "Proxmox VE login") == "Proxmox VE"

    class _Client:
        async def get(self, url, **kwargs):
            if url.endswith("/favicon.ico"):
                return httpx.Response(200, content=b"icon", headers={"content-type": "image/x-icon"}, request=httpx.Request("GET", url))
            if url.endswith("/admin"):
                return httpx.Response(403, request=httpx.Request("GET", url))
            if url.endswith("/manager/"):
                raise RuntimeError("boom")
            return httpx.Response(200, text=body, headers={"content-type": "text/html", "server": "nginx"}, request=httpx.Request("GET", url))

    favicon_hash = await http_probe._fetch_favicon_hash(_Client(), "http://192.168.1.60:8123")
    assert favicon_hash is not None
    interesting = await http_probe._collect_interesting_paths(_Client(), "http://192.168.1.60:8123")
    assert any("/admin" in item for item in interesting)
    assert await http_probe._probe_path(_Client(), "http://192.168.1.60:8123", "/manager/") == 0

    async def fake_populate(client, base_url, ip, data_obj, raw_parts):
        data_obj.title = "Router"
        raw_parts.append("GET / -> 200")

    class _AsyncHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(http_probe.httpx, "AsyncClient", lambda **kwargs: _AsyncHttpClient())
    monkeypatch.setattr(http_probe, "_populate_probe_data", fake_populate)
    success = await http_probe.probe("192.168.1.60", 80, use_https=False)
    assert success.success is True
    assert success.probe_type == "http"

    async def raise_connect(awaitable, timeout):
        awaitable.close()
        raise httpx.ConnectError("refused")

    async def raise_timeout(awaitable, timeout):
        awaitable.close()
        raise httpx.TimeoutException("slow")

    async def raise_runtime(awaitable, timeout):
        awaitable.close()
        raise RuntimeError("explode")

    monkeypatch.setattr(http_probe, "_await_with_deadline", raise_connect)
    assert (await http_probe.probe("192.168.1.60", 80)).error == "Connection refused"
    monkeypatch.setattr(http_probe, "_await_with_deadline", raise_timeout)
    assert (await http_probe.probe("192.168.1.60", 80)).error == "Timeout"
    monkeypatch.setattr(http_probe, "_await_with_deadline", raise_runtime)
    assert "explode" in (await http_probe.probe("192.168.1.60", 80)).error


@pytest.mark.asyncio
async def test_worker_task_helpers_cover_control_queue_and_publish_paths(monkeypatch):
    active_map = {
        "worker-a": [
            {"name": "app.workers.tasks.run_scan_job", "id": "task-1", "args": ["job-1"]},
            {"name": "other.task", "id": "task-2", "args": ["job-1"]},
        ]
    }
    monkeypatch.setattr(worker_tasks.celery_app.control, "inspect", lambda: SimpleNamespace(active=lambda: active_map))
    task_ids = worker_tasks._get_active_scan_task_ids("job-1")
    assert task_ids == ["task-1"]
    revoked = []
    monkeypatch.setattr(worker_tasks.celery_app.control, "revoke", lambda task_id, **kwargs: revoked.append(task_id))
    assert worker_tasks.revoke_active_scan_job("job-1") is True
    assert revoked == ["task-1"]

    assert worker_tasks._extract_scan_job_id({"args": ["job-x"], "kwargs": {}}, "job-x") == "job-x"
    assert worker_tasks._extract_scan_job_id({"args": "job-x payload", "kwargs": {}}, "job-x") == "job-x"
    assert worker_tasks._get_scan_task_id({"name": "other", "id": "t", "args": ["job-1"]}, "job-1") is None
    assert worker_tasks._prepare_scan_job_targets(SimpleNamespace(targets="raw"), lambda v: f"mat:{v}", lambda v: None) is None
    assert worker_tasks._scan_config_value(SimpleNamespace(ai_after_scan_enabled=False), "ai_after_scan_enabled", True) is False

    child = SimpleNamespace(status="pending", started_at=None, finished_at=None, result_summary=None, chunk_index=1, chunk_count=2)
    worker_tasks._mark_child_running(child)
    assert child.status == "running"
    worker_tasks._mark_child_done(child, SimpleNamespace(model_dump=lambda mode=None: {"hosts_scanned": 1}))
    assert child.status == "done"
    job = SimpleNamespace(result_summary={})
    summary = SimpleNamespace(model_dump=lambda mode=None: {"hosts_scanned": 1})
    worker_tasks._record_parent_chunk_progress(job, child, summary)
    assert job.result_summary["chunk_index"] == 1

    decision_type = lambda **kwargs: SimpleNamespace(**kwargs)
    pause_job = SimpleNamespace(control_action="pause", control_mode="preserve_discovery", resume_after=datetime.now(timezone.utc))
    assert worker_tasks._scan_control_decision_from_job(pause_job, decision_type).action == "pause"
    requeue_job = SimpleNamespace(control_action="requeue", control_mode=None, resume_after=None)
    assert worker_tasks._scan_control_decision_from_job(requeue_job, decision_type).mode == "requeue"
    cancel_job = SimpleNamespace(control_action="cancel", control_mode=None, resume_after=None)
    assert worker_tasks._scan_control_decision_from_job(cancel_job, decision_type).action == "cancel"
    assert worker_tasks._scan_control_decision_from_job(SimpleNamespace(control_action=None), decision_type) is None

    interrupted = SimpleNamespace(control_mode="requeue", status="running", started_at=datetime.now(timezone.utc), finished_at=None)
    worker_tasks._apply_interrupt_status(interrupted, "paused")
    assert interrupted.status == "pending"
    assert worker_tasks._interrupt_stage("pending", "paused") == "queued"
    assert worker_tasks._interrupt_stage("running", "paused") == "paused"
    assert worker_tasks._interrupt_stage("running", "cancelled") == "cancelled"

    now = datetime.now(timezone.utc)
    paused_job = SimpleNamespace(control_action="pause", control_mode="preserve_discovery", resume_after=now, result_summary={})
    worker_tasks._resume_paused_job(paused_job, now)
    assert paused_job.status == "pending"
    assert paused_job.queue_position == 1
    assert paused_job.result_summary["resumed_at"] == now.isoformat()

    parent = SimpleNamespace(id=uuid4(), result_summary={}, queue_position=None)
    progress_state = {"last_flush": 0.0, "last_stage": None}
    db = _FakeDb()
    monkeypatch.setattr(worker_tasks, "_publish_event", lambda payload: _completed_task(None))
    broadcast = worker_tasks._build_parent_chunk_broadcast_fn(db, parent, progress_state, chunk_index=2, chunk_count=4)
    await broadcast({"event": "scan_progress", "data": {"job_id": "child", "progress": 0.5, "stage": "investigation", "message": "Scanning"}})
    assert parent.result_summary["chunk_index"] == 2
    assert db.committed is True

    progress_job = SimpleNamespace(result_summary={})
    await worker_tasks._record_job_progress(db, progress_job, {"event": "scan_progress", "data": {"stage": "ports", "progress": 0.2}}, {"last_flush": 0.0, "last_stage": None})
    assert progress_job.result_summary["stage"] == "ports"

    published = []
    fake_redis = SimpleNamespace(
        publish=lambda channel, payload: published.append((channel, payload)),
        close=lambda: published.append(("closed", None)),
    )
    monkeypatch.setitem(sys.modules, "redis", SimpleNamespace(from_url=lambda url: fake_redis))
    worker_tasks._publish_event_sync({"event": "scan_progress"})
    assert published[0][0] == "argus:events"


@pytest.mark.asyncio
async def test_worker_task_helpers_cover_job_state_and_queue_management(monkeypatch):
    now = datetime.now(timezone.utc)
    summary_parent = SimpleNamespace(
        hosts_scanned=1,
        hosts_up=1,
        total_open_ports=2,
        new_assets=1,
        changed_assets=0,
        offline_assets=0,
        ai_analyses_completed=1,
        duration_seconds=1.5,
    )
    summary_child = SimpleNamespace(
        hosts_scanned=2,
        hosts_up=2,
        total_open_ports=3,
        new_assets=0,
        changed_assets=1,
        offline_assets=1,
        ai_analyses_completed=0,
        duration_seconds=2.25,
    )
    worker_tasks._merge_scan_summary(summary_parent, summary_child)
    assert summary_parent.hosts_scanned == 3
    assert summary_parent.duration_seconds == 3.75

    child_done = SimpleNamespace(status="done", finished_at=None, control_action="pause", control_mode="x", result_summary=None)
    child_pending = SimpleNamespace(status="pending", finished_at=None, control_action="pause", control_mode="x", result_summary={})

    class _ChildDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([child_done, child_pending])

    child_db = _ChildDb()
    assert await worker_tasks._has_child_jobs(child_db, "parent") is True
    assert await worker_tasks._list_child_jobs(child_db, "parent") == [child_done, child_pending]
    await worker_tasks._cancel_remaining_child_jobs(child_db, "parent", message="stop")
    assert child_pending.status == "cancelled"
    assert child_pending.result_summary["message"] == "stop"
    assert child_db.committed is True

    runnable_job = SimpleNamespace(status="pending")
    assert await worker_tasks._get_runnable_job(_FakeDb(get_result=runnable_job), "job-1") is runnable_job
    assert await worker_tasks._get_runnable_job(_FakeDb(get_result=None), "missing") is None
    assert await worker_tasks._get_runnable_job(_FakeDb(get_result=SimpleNamespace(status="cancelled")), "cancelled") is None
    assert await worker_tasks._get_runnable_job(_FakeDb(get_result=SimpleNamespace(status="paused")), "paused") is None

    published = []
    monkeypatch.setattr(worker_tasks, "_publish_event", lambda payload: _completed_task(published.append(payload)))
    monkeypatch.setattr(worker_tasks, "_dispatch_next_scan_if_idle", lambda db: _completed_task(published.append({"event": "dispatch"})))
    failed_job = SimpleNamespace(status="pending", finished_at=None, control_action="pause", control_mode="x", resume_after=now, result_summary=None)
    await worker_tasks._fail_scan_job(_FakeDb(), failed_job, "job-1", "bad targets")
    assert failed_job.status == "failed"
    assert published[0]["data"]["status"] == "failed"

    running_job = SimpleNamespace(status="pending", queue_position=2, control_action="pause", started_at=None, result_summary=None, targets="192.168.1.0/24")
    db = _FakeDb()
    await worker_tasks._mark_job_running(db, running_job)
    assert running_job.status == "running"
    assert running_job.queue_position is None
    assert db.committed is True

    worker_tasks._resolve_scan_profile("polite", ScanProfile)
    assert worker_tasks._resolve_scan_profile("polite", ScanProfile) == ScanProfile.QUICK
    assert worker_tasks._resolve_scan_profile("missing", ScanProfile) == ScanProfile.BALANCED

    completed_job = SimpleNamespace(status="running", finished_at=None, result_summary=None)
    summary = SimpleNamespace(model_dump=lambda mode=None: {"hosts_scanned": 2})
    await worker_tasks._complete_scan_job(_FakeDb(), completed_job, "job-2", summary)
    assert completed_job.status == "done"
    assert completed_job.result_summary["hosts_scanned"] == 2


@pytest.mark.asyncio
async def test_worker_task_helpers_cover_interrupt_failure_and_dispatch_paths(monkeypatch):
    now = datetime.now(timezone.utc)
    queue_job = SimpleNamespace(
        status="running",
        control_mode="requeue",
        result_summary={"existing": True},
        resume_after=None,
        queue_position=None,
        control_action="pause",
    )
    summary = SimpleNamespace(model_dump=lambda mode=None: {"hosts_scanned": 4})
    monkeypatch.setattr(worker_tasks, "_next_queue_position", lambda db: _completed_task(3))
    exc = SimpleNamespace(status="paused", message="operator pause", resume_after=now.isoformat(), scanned_ips={"1.1.1.1"})
    await worker_tasks._apply_interrupt_result(_FakeDb(), queue_job, exc, summary)
    assert queue_job.status == "pending"
    assert queue_job.queue_position == 3
    assert queue_job.result_summary["stage"] == "queued"
    assert queue_job.control_action is None

    paused_job = SimpleNamespace(status="running", control_mode="preserve_discovery", result_summary={}, resume_after=None, queue_position=None, control_action="pause")
    await worker_tasks._apply_interrupt_result(_FakeDb(), paused_job, exc, summary)
    assert paused_job.status == "paused"
    assert paused_job.resume_after == now

    persist_calls = []
    published = []
    monkeypatch.setattr(worker_tasks, "_publish_event", lambda payload: _completed_task(published.append(payload)))
    monkeypatch.setattr(worker_tasks, "_apply_interrupt_result", lambda db, job, exc_obj, summary_obj: _completed_task(persist_calls.append(("apply", exc_obj.status))))
    interrupt = SimpleNamespace(
        status="paused",
        message="pause requested",
        resume_after=now.isoformat(),
        scanned_ips={"1.1.1.1"},
        partial_results=[HostScanResult(host=DiscoveredHost(ip_address="1.1.1.1"))],
        mark_missing_offline=False,
        summary=summary,
    )
    await worker_tasks._handle_scan_interrupt(
        _FakeDb(),
        SimpleNamespace(id=uuid4()),
        "job-3",
        interrupt,
        summary,
        lambda *args, **kwargs: _completed_task(persist_calls.append(("persist", kwargs["allow_discovery_only"]))),
    )
    assert ("persist", True) in persist_calls
    assert published[0]["data"]["status"] == "paused"

    failed_job = SimpleNamespace(status="running", finished_at=None, result_summary=None)
    failure_events = []
    monkeypatch.setattr(worker_tasks, "_publish_event", lambda payload: _completed_task(failure_events.append(payload)))
    await worker_tasks._publish_scan_failure(_FakeDb(), failed_job, "job-4", RuntimeError("boom"))
    assert failed_job.status == "failed"
    assert failure_events[0]["data"]["error"] == "boom"

    queued_a = SimpleNamespace(id=uuid4(), status="pending", queue_position=2, created_at=now)
    queued_b = SimpleNamespace(id=uuid4(), status="pending", queue_position=None, created_at=now + timedelta(seconds=1))

    class _QueueDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([queued_a, queued_b])

    queue_db = _QueueDb()
    assert await worker_tasks._next_queue_position(queue_db) == 3
    await worker_tasks._normalize_pending_queue(queue_db)
    assert queued_a.queue_position == 1
    assert queued_b.queue_position == 2
    next_job = await worker_tasks._get_next_queued_job(queue_db)
    assert next_job is queued_a

    started = []
    monkeypatch.setattr(worker_tasks, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(worker_tasks, "_get_next_queued_job", lambda db: _completed_task(SimpleNamespace(id=uuid4(), queue_position=1)))
    monkeypatch.setattr(worker_tasks.run_scan_job, "delay", lambda job_id: started.append(job_id))
    await worker_tasks._dispatch_next_scan_if_idle(_FakeDb())
    assert started


@pytest.mark.asyncio
async def test_worker_task_helpers_cover_scheduled_and_resume_entrypoints(monkeypatch):
    now = datetime.now(timezone.utc)
    config = SimpleNamespace(default_profile="balanced", last_scheduled_scan_at=None, scheduled_scans_enabled=True)
    run_calls = []

    class _Session:
        def __init__(self):
            self.db = SimpleNamespace(
                added=[],
                committed=False,
                refreshed=[],
                execute=lambda stmt: _completed_task(_ScalarResult([])),
                scalar=lambda stmt: _completed_task(None),
                flush=lambda: _completed_task(None),
                commit=lambda: _completed_task(None),
                refresh=lambda obj: _completed_task(None),
                add=lambda obj: self.db.added.append(obj),
            )

        async def __aenter__(self):
            return self.db

        async def __aexit__(self, exc_type, exc, tb):
            return None

    fake_engine = SimpleNamespace(dispose=lambda: _completed_task(None))
    monkeypatch.setattr(sys.modules["sqlalchemy.ext.asyncio"], "create_async_engine", lambda *args, **kwargs: fake_engine)
    monkeypatch.setattr(sys.modules["sqlalchemy.ext.asyncio"], "async_sessionmaker", lambda *args, **kwargs: (lambda: _Session()))
    monkeypatch.setattr(sys.modules["app.scanner.config"], "get_or_create_scanner_config", lambda db: _completed_task(config))
    monkeypatch.setattr(sys.modules["app.scanner.config"], "should_enqueue_scheduled_scan", lambda cfg: True)
    monkeypatch.setattr(sys.modules["app.scanner.config"], "resolve_scan_targets", lambda cfg, req: "192.168.1.0/24")
    monkeypatch.setattr(sys.modules["app.scanner.config"], "split_scan_targets", lambda targets: [targets])
    monkeypatch.setattr(worker_tasks, "_next_queue_position", lambda db: _completed_task(1))
    monkeypatch.setattr(worker_tasks, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(worker_tasks.run_scan_job, "delay", lambda job_id: run_calls.append(job_id))
    await worker_tasks._enqueue_scheduled_scan()
    assert run_calls

    duplicate_session = _Session()
    duplicate_session.db.scalar = lambda stmt: _completed_task(uuid4())
    monkeypatch.setattr(sys.modules["sqlalchemy.ext.asyncio"], "async_sessionmaker", lambda *args, **kwargs: (lambda: duplicate_session))
    run_calls.clear()
    await worker_tasks._enqueue_scheduled_scan()
    assert run_calls == []

    jobs = [
        SimpleNamespace(id=uuid4(), status="paused", resume_after=now - timedelta(minutes=1), control_action="pause", control_mode="preserve_discovery", result_summary={}),
    ]

    class _ResumeDb:
        def __init__(self):
            self.committed = False

        async def execute(self, stmt):
            return _ScalarResult(jobs)

        async def commit(self):
            self.committed = True

    class _ResumeSession:
        async def __aenter__(self):
            return _ResumeDb()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(sys.modules["sqlalchemy.ext.asyncio"], "async_sessionmaker", lambda *args, **kwargs: (lambda: _ResumeSession()))
    monkeypatch.setattr(worker_tasks, "_normalize_pending_queue", lambda db: _completed_task(None))
    monkeypatch.setattr(worker_tasks, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(worker_tasks, "_get_next_queued_job", lambda db: _completed_task(SimpleNamespace(id=uuid4())))
    run_calls.clear()
    await worker_tasks._resume_paused_scans_async()
    assert run_calls


@pytest.mark.asyncio
async def test_topology_resolution_and_upsert_helpers_cover_core_paths():
    source = Asset(id=uuid4(), ip_address="192.168.1.1", hostname="switch-a", mac_address="AA:AA:AA:AA:AA:AA", status="online")
    target = Asset(id=uuid4(), ip_address="192.168.1.2", hostname="host-a", mac_address="BB:BB:BB:BB:BB:BB", status="online")

    no_match_db = _FakeDb(execute_result=_ScalarResult([]))
    assert await topology_mod._resolve_asset(no_match_db, []) is None

    match_db = _FakeDb(execute_result=_ScalarResult([target]))
    assert await topology_mod._resolve_asset_by_ip_or_mac(match_db, "192.168.1.2", None) is target
    assert await topology_mod._resolve_asset_by_hostname_or_mac(match_db, None, "BB:BB:BB:BB:BB:BB") is target

    link_db = _FakeDb(execute_result=_ScalarResult([]))
    created = await topology_mod._upsert_topology_link(
        link_db,
        source.id,
        target.id,
        "snmp_arp",
        {"source": "snmp_arp"},
        vlan_id=10,
    )
    assert created == 1
    assert any(isinstance(item, topology_mod.TopologyLink) for item in link_db.added)

    existing_link = topology_mod.TopologyLink(
        source_id=source.id,
        target_id=target.id,
        link_type="wifi",
        vlan_id=None,
        link_metadata={"old": True},
    )
    update_db = _FakeDb(execute_result=_ScalarResult([existing_link]))
    created = await topology_mod._upsert_topology_link(
        update_db,
        source.id,
        target.id,
        "wifi",
        {"source": "wifi", "ssid": "Lab"},
        vlan_id=20,
    )
    assert created == 0
    assert existing_link.vlan_id == 20
    assert existing_link.link_metadata["ssid"] == "Lab"

    association_db = _FakeDb(execute_result=_ScalarResult([]))
    association, assoc_created = await topology_mod._upsert_wireless_association(
        association_db,
        source,
        {"mac": "CC:CC:CC:CC:CC:CC", "ip": "192.168.1.30", "ssid": "Argus", "band": "5GHz", "signal_dbm": -54},
        target,
    )
    assert assoc_created == 1
    assert association.client_asset_id == target.id
    assert any(isinstance(item, topology_mod.WirelessAssociation) for item in association_db.added)

    existing_assoc = topology_mod.WirelessAssociation(
        access_point_asset_id=source.id,
        client_asset_id=None,
        client_mac="CC:CC:CC:CC:CC:CC",
        client_ip=None,
        ssid=None,
        band=None,
        signal_dbm=None,
        source="snmp",
    )
    update_assoc_db = _FakeDb(execute_result=_ScalarResult([existing_assoc]))
    association, assoc_created = await topology_mod._upsert_wireless_association(
        update_assoc_db,
        source,
        {"mac": "CC:CC:CC:CC:CC:CC", "ip": "192.168.1.31", "ssid": "Argus", "band": "2.4GHz", "signal_dbm": -60, "source": "controller"},
        target,
    )
    assert assoc_created == 0
    assert association.client_ip == "192.168.1.31"
    assert association.source == "controller"


@pytest.mark.asyncio
async def test_topology_snmp_inference_covers_arp_neighbors_and_wireless(monkeypatch):
    source = Asset(id=uuid4(), ip_address="192.168.1.1", hostname="switch-a", mac_address="AA:AA:AA:AA:AA:AA", status="online")
    arp_target = Asset(id=uuid4(), ip_address="192.168.1.2", hostname="host-a", mac_address="BB:BB:BB:BB:BB:BB", status="online")
    neighbor_target = Asset(id=uuid4(), ip_address="192.168.1.3", hostname="core-sw", mac_address="CC:CC:CC:CC:CC:CC", status="online")
    wifi_target = Asset(id=uuid4(), ip_address="192.168.1.4", hostname="phone", mac_address="DD:DD:DD:DD:DD:DD", status="online")

    async def fake_resolve_ip_or_mac(db, ip_address, mac_address):
        if ip_address == "192.168.1.2":
            return arp_target
        if mac_address == "DD:DD:DD:DD:DD:DD":
            return wifi_target
        return None

    async def fake_resolve_hostname_or_mac(db, hostname, mac_address):
        if hostname == "core-sw" or mac_address == "CC:CC:CC:CC:CC:CC":
            return neighbor_target
        return None

    link_calls = []
    assoc_calls = []

    async def fake_upsert_link(db, source_id, target_id, link_type, metadata, vlan_id=None):
        link_calls.append((source_id, target_id, link_type, metadata, vlan_id))
        return 1

    async def fake_upsert_assoc(db, source_asset, client, client_asset):
        assoc = SimpleNamespace(
            source=client.get("source") or "snmp",
            ssid=client.get("ssid"),
            band=client.get("band"),
            signal_dbm=client.get("signal_dbm"),
        )
        assoc_calls.append((client, client_asset))
        return assoc, 1

    monkeypatch.setattr(topology_mod, "_resolve_asset_by_ip_or_mac", fake_resolve_ip_or_mac)
    monkeypatch.setattr(topology_mod, "_resolve_asset_by_hostname_or_mac", fake_resolve_hostname_or_mac)
    monkeypatch.setattr(topology_mod, "_upsert_topology_link", fake_upsert_link)
    monkeypatch.setattr(topology_mod, "_upsert_wireless_association", fake_upsert_assoc)

    snmp_data = {
        "arp_table": [
            {"ip": "192.168.1.2", "mac": "BB:BB:BB:BB:BB:BB", "if_index": 7},
            {"ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:AA", "if_index": 7},
        ],
        "interfaces": [{"if_index": 7, "name": "uplink0", "vlan_id": 20}],
        "neighbors": [
            {"remote_name": "core-sw", "remote_mac": "CC:CC:CC:CC:CC:CC", "protocol": "lldp", "local_port": "Gi0/1", "remote_port": "Gi0/24", "remote_platform": "Cisco"}
        ],
        "wireless_clients": [
            {"ip": "192.168.1.4", "mac": "DD:DD:DD:DD:DD:DD", "ssid": "Argus", "band": "5GHz", "signal_dbm": -48, "source": "ap"}
        ],
    }

    created = await topology_mod.infer_topology_links_from_snmp(_FakeDb(), source, snmp_data)
    assert created == 4
    assert any(call[2] == "snmp_arp" and call[3]["interface"] == "uplink0" and call[4] == 20 for call in link_calls)
    assert any(call[2] == "lldp" and call[3]["remote_platform"] == "Cisco" for call in link_calls)
    assert any(call[2] == "wifi" and call[3]["ssid"] == "Argus" for call in link_calls)
    assert assoc_calls

    assert await topology_mod.infer_topology_links_from_snmp(_FakeDb(), source, {}) == 0


def test_scanner_config_network_detection_and_route_parsing_helpers(monkeypatch):
    class _Sock:
        def fileno(self):
            return 7

        def close(self):
            return None

    monkeypatch.setattr(scanner_config.socket, "socket", lambda *args, **kwargs: _Sock())
    monkeypatch.setattr(
        scanner_config.fcntl,
        "ioctl",
        lambda fd, request, packed: (b"\x00" * 20) + scanner_config.socket.inet_aton("192.168.1.10") + (b"\x00" * 8),
    )
    assert scanner_config._ioctl_ipv4("eth0", scanner_config._SIOCGIFADDR) == "192.168.1.10"

    monkeypatch.setattr(scanner_config, "_ioctl_ipv4", lambda ifname, request: {"addr": "192.168.1.10", "mask": "255.255.255.0"}["addr" if request == scanner_config._SIOCGIFADDR else "mask"])
    assert scanner_config._get_ipv4_network("eth0") == "192.168.1.0/24"

    monkeypatch.setattr(scanner_config, "_ioctl_ipv4", lambda ifname, request: None)
    assert scanner_config._get_ipv4_network("eth0") is None

    monkeypatch.setattr(scanner_config, "_get_ipv4_network", lambda ifname: "10.0.0.0/24" if ifname == "eth0" else None)
    monkeypatch.setattr(scanner_config.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])

    from io import StringIO

    def fake_open_success(*args, **kwargs):
        return StringIO("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")

    monkeypatch.setattr("builtins.open", fake_open_success)
    assert scanner_config.detect_local_ipv4_cidr() == "10.0.0.0/24"

    def fake_open_error(*args, **kwargs):
        raise OSError("no route file")

    monkeypatch.setattr("builtins.open", fake_open_error)
    assert scanner_config.detect_local_ipv4_cidr() == "10.0.0.0/24"

    monkeypatch.setattr(
        "builtins.open",
        lambda *args, **kwargs: StringIO(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
            "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
            "eth1\tBAD\t00000000\t0001\t0\t0\t0\tBAD\t0\t0\t0\n"
        ),
    )
    routes = scanner_config._iter_ipv4_route_networks()
    assert [str(route) for route in routes] == ["192.168.1.0/24"]

    monkeypatch.setattr(scanner_config, "_get_ipv4_network", lambda ifname: "192.168.1.0/24")
    assert scanner_config._default_route_network("eth0 00000000 0101A8C0 0003 0 0 0 00FFFFFF 0 0 0") == "192.168.1.0/24"
    assert scanner_config._default_route_network("eth0 BAD 0101A8C0 ZZZZ 0 0 0 00FFFFFF 0 0 0") is None
    assert scanner_config._default_route_network("lo 00000000 0101A8C0 0003 0 0 0 00FFFFFF 0 0 0") is None
    assert scanner_config._target_is_routable("192.168.1.5", [scanner_config.ipaddress.ip_network("0.0.0.0/0")]) is True
    assert scanner_config._target_is_routable("not-a-target", [scanner_config.ipaddress.ip_network("192.168.1.0/24")]) is False

    chunks = []
    assert scanner_config._append_ip_group(chunks, [], "192.168.1.1", 1) == []
    assert chunks == ["192.168.1.1"]
    chunks = []
    ip_group = scanner_config._append_split_target(chunks, [], "10.0.0.0/24", max_network_prefix=24, max_ip_group_size=2)
    assert ip_group == ["10.0.0.0/24"]
    ip_group = scanner_config._append_split_target(chunks, ip_group, "bogus", max_network_prefix=24, max_ip_group_size=2)
    assert ip_group == []
    assert chunks[-1] == "10.0.0.0/24 bogus"


@pytest.mark.asyncio
async def test_scanner_config_bootstrap_create_update_and_effective_helpers(monkeypatch):
    monkeypatch.setattr(scanner_config.settings, "SCANNER_DEFAULT_TARGETS", "192.168.50.0/24")
    assert scanner_config._bootstrap_targets_from_env() == ("192.168.50.0/24", False)
    monkeypatch.setattr(scanner_config.settings, "SCANNER_DEFAULT_TARGETS", scanner_config.DEFAULT_TARGET_PLACEHOLDER)
    assert scanner_config._bootstrap_targets_from_env() == (None, True)

    monkeypatch.setattr(scanner_config.settings, "SCANNER_DEFAULT_PROFILE", "balanced")
    monkeypatch.setattr(scanner_config.settings, "SCANNER_INTERVAL_MINUTES", 45)
    monkeypatch.setattr(scanner_config.settings, "SCANNER_CONCURRENT_HOSTS", 6)
    monkeypatch.setattr(scanner_config.settings, "AI_ENABLE_PER_SCAN", True)
    monkeypatch.setattr(scanner_config.settings, "SCANNER_PASSIVE_ARP", True)
    monkeypatch.setattr(scanner_config.settings, "SCANNER_PASSIVE_ARP_INTERFACE", "eth9")
    monkeypatch.setattr(scanner_config.settings, "SNMP_VERSION", "3")
    monkeypatch.setattr(scanner_config.settings, "SNMP_COMMUNITY", "public")
    monkeypatch.setattr(scanner_config.settings, "SNMP_TIMEOUT", 9)
    monkeypatch.setattr(scanner_config.settings, "SNMP_V3_USERNAME", "snmp-user")
    monkeypatch.setattr(scanner_config.settings, "SNMP_V3_AUTH_KEY", "auth")
    monkeypatch.setattr(scanner_config.settings, "SNMP_V3_PRIV_KEY", "priv")
    monkeypatch.setattr(scanner_config.settings, "SNMP_V3_AUTH_PROTOCOL", "sha")
    monkeypatch.setattr(scanner_config.settings, "SNMP_V3_PRIV_PROTOCOL", "aes")
    monkeypatch.setattr(scanner_config.settings, "OLLAMA_MODEL", "qwen-test")

    db_existing = _FakeDb(execute_result=_ScalarResult([SimpleNamespace(id=1)]))
    assert (await scanner_config.get_or_create_scanner_config(db_existing)).id == 1

    db_new = _FakeDb(execute_result=_ScalarResult([]))
    created = await scanner_config.get_or_create_scanner_config(db_new)
    assert created.default_profile == "balanced"
    assert created.interval_minutes == 45
    assert created.passive_arp_interface == "eth9"
    assert created.scheduled_scans_enabled is False
    assert db_new.added[-1] is created

    config = SimpleNamespace(
        enabled=True,
        scheduled_scans_enabled=True,
        default_targets=None,
        auto_detect_targets=True,
        default_profile="fast",
        interval_minutes=60,
        concurrent_hosts=4,
        host_chunk_size=32,
        top_ports_count=100,
        deep_probe_timeout_seconds=5,
        ai_after_scan_enabled=False,
        passive_arp_enabled=True,
        passive_arp_interface="eth0",
        snmp_enabled=True,
        snmp_version="3",
        snmp_community="public",
        snmp_timeout=5,
        snmp_v3_username=None,
        snmp_v3_auth_key=None,
        snmp_v3_priv_key=None,
        snmp_v3_auth_protocol="sha",
        snmp_v3_priv_protocol="aes",
        fingerprint_ai_enabled=True,
        fingerprint_ai_model=None,
        fingerprint_ai_min_confidence=0.8,
        fingerprint_ai_prompt_suffix=None,
        internet_lookup_enabled=True,
        internet_lookup_allowed_domains=None,
        internet_lookup_budget=2,
        internet_lookup_timeout_seconds=3,
        last_scheduled_scan_at=None,
    )
    monkeypatch.setattr(scanner_config, "detect_local_ipv4_cidr", lambda: "192.168.88.0/24")
    effective = scanner_config.build_effective_scanner_config(config)
    assert effective.detected_targets == "192.168.88.0/24"
    assert effective.effective_targets == "192.168.88.0/24"
    assert effective.fingerprint_ai_model == "qwen-test"
    assert effective.snmp_v3_username == ""

    monkeypatch.setattr(scanner_config, "get_or_create_scanner_config", lambda db: _completed_task(config))
    cfg, eff = await scanner_config.read_effective_scanner_config(_FakeDb())
    assert cfg is config
    assert eff.effective_targets == "192.168.88.0/24"

    payload = ScannerConfigUpdateInput(
        enabled=False,
        scheduled_scans_enabled=False,
        default_targets=" 10.0.0.0/24 ",
        auto_detect_targets=False,
        default_profile="balanced",
        interval_minutes=30,
        concurrent_hosts=8,
        host_chunk_size=999,
        top_ports_count=70000,
        deep_probe_timeout_seconds=0,
        ai_after_scan_enabled=True,
        passive_arp_enabled=False,
        passive_arp_interface=" ",
        snmp_enabled=True,
        snmp_version="V3",
        snmp_community=" private ",
        snmp_timeout=0,
        snmp_v3_username=" user ",
        snmp_v3_auth_key=" auth ",
        snmp_v3_priv_key=" priv ",
        snmp_v3_auth_protocol="SHA",
        snmp_v3_priv_protocol="AES",
        fingerprint_ai_enabled=True,
        fingerprint_ai_model=" ",
        fingerprint_ai_min_confidence=-1.0,
        fingerprint_ai_prompt_suffix=" suffix ",
        internet_lookup_enabled=True,
        internet_lookup_allowed_domains=" example.com ",
        internet_lookup_budget=0,
        internet_lookup_timeout_seconds=0,
    )
    updated, effective_updated = await scanner_config.update_scanner_config(_FakeDb(), payload)
    assert updated.enabled is False
    assert updated.default_targets == "10.0.0.0/24"
    assert updated.host_chunk_size == 256
    assert updated.top_ports_count == 65535
    assert updated.deep_probe_timeout_seconds == 1
    assert updated.snmp_community == "private"
    assert updated.fingerprint_ai_min_confidence == 0.0
    assert updated.internet_lookup_allowed_domains == "example.com"
    assert effective_updated.effective_targets == "10.0.0.0/24"

    with pytest.raises(ValueError):
        await scanner_config.update_scanner_config(
            _FakeDb(),
            ScannerConfigUpdateInput(
                enabled=True,
                scheduled_scans_enabled=True,
                default_targets=" ",
                auto_detect_targets=False,
                default_profile="balanced",
                interval_minutes=1,
                concurrent_hosts=1,
                host_chunk_size=1,
                top_ports_count=10,
                deep_probe_timeout_seconds=1,
                ai_after_scan_enabled=False,
                passive_arp_enabled=False,
                passive_arp_interface="",
                snmp_enabled=False,
                snmp_version="2c",
                snmp_community=None,
                snmp_timeout=1,
                snmp_v3_username=None,
                snmp_v3_auth_key=None,
                snmp_v3_priv_key=None,
                snmp_v3_auth_protocol="sha",
                snmp_v3_priv_protocol="aes",
                fingerprint_ai_enabled=False,
                fingerprint_ai_model=None,
                fingerprint_ai_min_confidence=0.5,
                fingerprint_ai_prompt_suffix=None,
                internet_lookup_enabled=False,
                internet_lookup_allowed_domains=None,
                internet_lookup_budget=1,
                internet_lookup_timeout_seconds=1,
            ),
        )


def test_scanner_config_evidence_helper_additional_branches():
    assert scanner_config.has_meaningful_scan_evidence(
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.3"), reverse_hostname="printer.lan")
    ) is True
    assert scanner_config.has_meaningful_scan_evidence(
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.4"), mac_vendor="Canon")
    ) is True
    assert scanner_config.has_meaningful_scan_evidence(
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.5"), ports=[PortResult(port=80, protocol="tcp", state="open")])
    ) is True
    assert scanner_config.has_meaningful_scan_evidence(
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.6"), probes=[ProbeResult(probe_type="dns", success=True, data={"ptr": "x"})])
    ) is False
    assert scanner_config.has_meaningful_scan_evidence(
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.7"), ai_analysis=AIAnalysis(device_class=DeviceClass.UNKNOWN, confidence=0.95))
    ) is False


@pytest.mark.asyncio
async def test_scan_route_control_helpers_cover_pause_cancel_resume(monkeypatch):
    started = []

    class _Runner:
        @staticmethod
        def delay(job_id: str):
            started.append(job_id)

    monkeypatch.setattr(scans_routes, "run_scan_job", _Runner())

    with pytest.raises(HTTPException):
        await scans_routes._resume_scan_job(ScanJob(id=uuid4(), status="running"), _FakeDb())

    paused_job = ScanJob(id=uuid4(), status="paused", result_summary={"stage": "paused"})
    db = _FakeDb()
    resumed = await scans_routes._resume_scan_job(paused_job, db)
    assert resumed["status"] == "pending"
    assert paused_job.status == "pending"
    assert started == [str(paused_job.id)]
    assert db.committed is True

    with pytest.raises(HTTPException):
        await scans_routes._pause_scan_job(ScanJob(id=uuid4(), status="pending"), scans_routes.ScanControlRequest(action="pause", resume_in_minutes=5), _FakeDb())

    pending_job = ScanJob(id=uuid4(), status="pending")
    pause_result = await scans_routes._pause_scan_job(pending_job, scans_routes.ScanControlRequest(action="pause", resume_in_minutes=15), _FakeDb())
    assert pause_result["status"] == "paused"
    assert pending_job.control_action == "pause"

    cancel_db = _FakeDb(execute_result=_ScalarResult([]))
    pending_cancel = ScanJob(id=uuid4(), status="pending")
    terminated, orphaned = await scans_routes._cancel_scan_job(pending_cancel, "discard", cancel_db)
    assert (terminated, orphaned) == (False, False)
    assert pending_cancel.status == "cancelled"
    assert cancel_db.committed is True

    revoked = []
    monkeypatch.setattr(scans_routes, "_get_active_scan_task_ids", lambda job_id: ["task-1"])
    monkeypatch.setattr(scans_routes, "revoke_active_scan_job", lambda job_id: revoked.append(job_id))
    running_cancel = ScanJob(id=uuid4(), status="running")
    terminated, orphaned = await scans_routes._cancel_scan_job(running_cancel, "discard", _FakeDb(execute_result=_ScalarResult([])))
    assert (terminated, orphaned) == (True, False)
    assert revoked == [str(running_cancel.id)]

    monkeypatch.setattr(scans_routes, "_get_active_scan_task_ids", lambda job_id: [])
    stale_running = ScanJob(id=uuid4(), status="running")
    terminated, orphaned = await scans_routes._cancel_scan_job(stale_running, "discard", _FakeDb(execute_result=_ScalarResult([])))
    assert (terminated, orphaned) == (False, True)
    assert stale_running.status == "cancelled"


@pytest.mark.asyncio
async def test_scan_route_queue_helpers_cover_reorder_and_start_now(monkeypatch):
    now = datetime.now(timezone.utc)
    queue = [
        ScanJob(id=uuid4(), status="pending", queue_position=1, created_at=now),
        ScanJob(id=uuid4(), status="pending", queue_position=2, created_at=now),
        ScanJob(id=uuid4(), status="pending", queue_position=3, created_at=now),
    ]
    scans_routes._move_queue_item(queue, 1, "move_up")
    assert queue[0].queue_position == 2
    scans_routes._move_queue_item(queue, 0, "move_down")
    scans_routes._move_queue_item(queue, 1, "move_to_front")
    assert queue[0].status == "pending"
    assert len(scans_routes._serialize_queue(queue)) == 3
    assert scans_routes._scan_sort_key(ScanJob(status="running", queue_position=2, created_at=now))[0] == 0

    active = ScanJob(id=uuid4(), status="running")

    class _StartNowDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([active])

    await scans_routes._handle_start_now(queue, _StartNowDb())
    assert active.control_action == "requeue"
    assert active.control_mode == "preserve_discovery"

    class _IdleDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([])

    await scans_routes._handle_start_now(queue, _IdleDb())
    assert queue[0].queue_position == 1

    job = ScanJob(id=uuid4(), status="done", finished_at=None, control_action="pause", control_mode="discard", result_summary={})
    scans_routes._mark_job_cancelled(job, finished_at=now, message="test cancel")
    assert job.status == "cancelled"
    assert job.result_summary["preserved_hosts"] == 0


@pytest.mark.asyncio
async def test_scan_route_clear_pending_queue_cancels_all():
    queued_a = ScanJob(id=uuid4(), status="pending", queue_position=1, created_at=datetime.now(timezone.utc))
    queued_b = ScanJob(id=uuid4(), status="pending", queue_position=2, created_at=datetime.now(timezone.utc))

    class _QueueDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([queued_a, queued_b])

    db = _QueueDb()
    cleared = await scans_routes._clear_pending_scan_queue(db)
    assert cleared == 2
    assert queued_a.status == "cancelled"
    assert queued_b.status == "cancelled"
    assert db.committed is True

    response = await scans_routes.clear_scan_queue(_QueueDb(), object())
    assert response == {"status": "ok", "cancelled": 2}


@pytest.mark.asyncio
async def test_pipeline_helpers_cover_discovery_control_and_early_return(monkeypatch):
    payload = _progress_payload("job-1", "discovery", 0.1, ScanSummary(job_id="job-1", targets="x", profile=ScanProfile.BALANCED), message="hi")
    assert payload["data"]["message"] == "hi"

    hosts = [DiscoveredHost(ip_address="192.168.1.10")]
    summary = ScanSummary(job_id="job-1", targets="x", profile=ScanProfile.BALANCED)
    results = _build_investigation_tasks(hosts, {}, ScanProfile.BALANCED, None, False, 5, asyncio.Semaphore(1), None, "job-1")
    assert len(results) == 1
    for task in results:
        task.cancel()
    await asyncio.gather(*results, return_exceptions=True)
    assert _port_details_for_host({}, "192.168.1.10")[0] == []

    pending_task = asyncio.create_task(asyncio.sleep(10))
    with pytest.raises(Exception):
        await _check_control(
            lambda: _completed_task(ScanControlDecision(action="pause", mode="preserve_discovery")),
            stage="investigation",
            summary=summary,
            hosts=hosts,
            completed_results=[],
            tasks=[pending_task],
        )
    assert pending_task.cancelled()
    await _cancel_pending_tasks(None)

    broadcasts = []
    persisted = []

    async def fake_broadcast(_broadcast_fn, payload):
        broadcasts.append(payload)

    async def fake_persist(*args, **kwargs):
        persisted.append((args, kwargs))

    monkeypatch.setattr("app.scanner.pipeline._broadcast", fake_broadcast)
    monkeypatch.setattr("app.scanner.pipeline._call_persist_results", fake_persist)
    monkeypatch.setattr("app.scanner.stages.discovery.sweep", lambda targets: _completed_task([]))
    discovered = await _run_discovery_stage("192.168.1.0/24", "job-1", summary, db_session="db", broadcast_fn=None, control_fn=None, scanned_ips_buffer=set())
    assert discovered == []
    assert len(broadcasts) == 1
    assert persisted == []

    monkeypatch.setattr("app.scanner.pipeline._run_discovery_stage", lambda *args, **kwargs: _completed_task([]))
    early_summary = await run_scan("job-2", "192.168.1.0/24", db_session=None, broadcast_fn=None)
    assert early_summary.hosts_up == 0


@pytest.mark.asyncio
async def test_upsert_helpers_cover_evidence_candidates_ports_and_mark_offline(monkeypatch):
    evidence_items = [
        SimpleNamespace(source="snmp", category="device_type", key="type", value="router", confidence=0.7, details={"a": 1}),
        SimpleNamespace(source="upnp", category="device_type", key="type", value="router", confidence=0.65, details={"b": 2}),
        SimpleNamespace(source="ai", category="vendor", key="vendor", value="Netgate", confidence=0.9, details={}),
    ]
    candidate_trace = _build_device_type_candidate_trace(evidence_items)
    assert candidate_trace[0]["value"] == "router"
    assert candidate_trace[0]["accepted"] is True
    assert _best_device_type_confidence(evidence_items) == 0.7

    weak_result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.30"),
        os_fingerprint=OSFingerprint(os_name="Linux"),
        ai_analysis=AIAnalysis(device_class=DeviceClass.UNKNOWN, confidence=0.1),
    )
    assert _has_probe_evidence(weak_result) is False
    assert _should_persist_os_name(weak_result) is False
    assert _should_persist_ai_fields(weak_result) is False

    rich_result = _sample_result("192.168.1.31")
    assert _has_probe_evidence(rich_result) is True
    assert _should_persist_os_name(rich_result) is True
    assert _should_persist_ai_fields(rich_result) is True

    db = _FakeDb()
    asset = _sample_asset("192.168.1.31")
    _record_discovery_history(db, asset, rich_result)
    assert db.added[0].change_type == "discovered"

    existing_open = SimpleNamespace(port_number=22, protocol="tcp", state="open", service="ssh", version=None)
    existing_closed = SimpleNamespace(port_number=443, protocol="tcp", state="closed", service="https", version=None)
    execute_results = [_ScalarResult([existing_open, existing_closed])]

    async def fake_execute(_stmt):
        return execute_results.pop(0)

    db.execute = fake_execute
    changes = await _upsert_ports(
        db,
        asset,
        HostScanResult(
            host=DiscoveredHost(ip_address=asset.ip_address),
            ports=[PortResult(port=443, protocol="tcp", state="open", service="https")],
        ),
    )
    assert changes["port_22/tcp"]["new"] == "closed"

    online_asset = Asset(id=uuid4(), ip_address="192.168.1.40", status="online")
    offline_db = _FakeDb()
    offline_results = [_ScalarResult([online_asset]), _ScalarResult([])]

    async def fake_offline_execute(_stmt):
        return offline_results.pop(0)

    offline_db.execute = fake_offline_execute
    count, marked = await mark_offline(offline_db, ["192.168.1.40", "192.168.1.41"])
    assert count == 1
    assert marked == [online_asset]


@pytest.mark.asyncio
async def test_upsert_helper_ai_lookup_and_autopsy_paths(monkeypatch):
    asset = _sample_asset("192.168.1.50")
    evidence_items = [
        SimpleNamespace(source="probe_http", category="device_type", key="title", value="router", confidence=0.4, details={}),
        SimpleNamespace(source="probe_snmp", category="device_type", key="sys_descr", value="router", confidence=0.5, details={}),
        SimpleNamespace(source="probe_upnp", category="vendor", key="manufacturer", value="Netgate", confidence=0.8, details={}),
    ]

    autopsy_db = _FakeDb(execute_result=_ScalarResult([]))
    await _upsert_autopsy(autopsy_db, asset, {"trace": True})
    assert autopsy_db.added

    existing_autopsy = SimpleNamespace(trace=None)
    update_db = _FakeDb(execute_result=_ScalarResult([existing_autopsy]))
    await _upsert_autopsy(update_db, asset, {"trace": "updated"})
    assert existing_autopsy.trace == {"trace": "updated"}

    monkeypatch.setattr("app.db.upsert.get_or_create_scanner_config", lambda db: _completed_task(SimpleNamespace(
        fingerprint_ai_enabled=True,
        fingerprint_ai_min_confidence=0.8,
        fingerprint_ai_model="model-x",
        fingerprint_ai_prompt_suffix="suffix",
        internet_lookup_enabled=True,
        internet_lookup_allowed_domains="example.com",
        internet_lookup_timeout_seconds=5,
        internet_lookup_budget=2,
    )))
    monkeypatch.setattr("app.db.upsert.synthesize_fingerprint", lambda **kwargs: _completed_task({
        "summary": "Likely router",
        "device_type": "router",
        "vendor": "Netgate",
        "confidence": 0.72,
        "supporting_evidence": ["probe_http"],
        "prompt_version": "v2",
        "model_used": "model-x",
    }))
    monkeypatch.setattr("app.db.upsert.normalize_allowed_domains", lambda value: ["example.com"])
    monkeypatch.setattr("app.db.upsert.build_lookup_query", lambda asset_payload, evidence_payload: "netgate router")
    monkeypatch.setattr("app.db.upsert.search_lookup", lambda *args, **kwargs: _completed_task([
        {"domain": "example.com", "url": "https://example.com/router", "title": "Netgate Router", "snippet": "router"},
    ]))

    db = _FakeDb()
    await _upsert_fingerprint_hypothesis(db, asset, evidence_items)
    await _upsert_internet_lookup(db, asset, evidence_items)
    assert len(db.added) == 3


@pytest.mark.asyncio
async def test_pipeline_full_run_tallies_summary_and_persists(monkeypatch):
    host = DiscoveredHost(ip_address="192.168.1.200", discovery_method="arp")
    result = HostScanResult(
        host=host,
        ports=[PortResult(port=80, protocol="tcp", state="open", service="http")],
        probes=[ProbeResult(probe_type="http", success=True, data={"title": "ok"})],
        ai_analysis=AIAnalysis(device_class=DeviceClass.ROUTER, confidence=0.9),
        scan_profile=ScanProfile.BALANCED,
    )
    broadcasts = []
    persist_calls = []

    async def fake_discovery(*args, **kwargs):
        return [host]

    async def fake_port_stage(*args, **kwargs):
        return {host.ip_address: (result.ports, OSFingerprint(), None, None)}

    monkeypatch.setattr("app.scanner.pipeline._run_discovery_stage", fake_discovery)
    monkeypatch.setattr("app.scanner.pipeline._run_port_scan_stage", fake_port_stage)
    monkeypatch.setattr("app.scanner.pipeline._build_investigation_tasks", lambda *args, **kwargs: [asyncio.create_task(_completed_task(result))])
    monkeypatch.setattr("app.scanner.pipeline._broadcast_investigation_start", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr("app.scanner.pipeline._collect_investigation_results", lambda *args, **kwargs: _completed_task(([result], 1, 1)))
    monkeypatch.setattr("app.scanner.pipeline._check_control", lambda *args, **kwargs: _completed_task(None))

    async def fake_persist_results(*args, **kwargs):
        persist_calls.append((args, kwargs))

    async def fake_broadcast(_broadcast_fn, payload):
        broadcasts.append(payload["event"])

    monkeypatch.setattr("app.scanner.pipeline._call_persist_results", fake_persist_results)
    monkeypatch.setattr("app.scanner.pipeline._broadcast", fake_broadcast)

    summary = await run_scan("job-100", "192.168.1.0/24", db_session="db", broadcast_fn=object())
    assert summary.total_open_ports == 1
    assert summary.ai_analyses_completed == 1
    assert persist_calls
    assert broadcasts[-1] == "scan_complete"


@pytest.mark.asyncio
async def test_upsert_scan_result_covers_new_updated_and_unchanged_paths(monkeypatch):
    result = _sample_result("192.168.1.210")
    new_db = _FakeDb(execute_result=_ScalarResult([]))

    async def fake_create_asset(db, result_obj, now, *_args):
        return Asset(id=uuid4(), ip_address=result_obj.host.ip_address, status="online", first_seen=now, last_seen=now)

    monkeypatch.setattr("app.db.upsert._create_asset", fake_create_asset)
    monkeypatch.setattr("app.db.upsert._persist_asset_context", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr("app.db.upsert._upsert_ports", lambda *args, **kwargs: _completed_task({}))
    asset, change = await upsert_scan_result(new_db, result)
    assert change == "discovered"
    assert asset.ip_address == "192.168.1.210"

    unchanged_result = _sample_result("192.168.1.211")
    existing = Asset(
        id=uuid4(),
        ip_address="192.168.1.211",
        status="online",
        hostname=unchanged_result.reverse_hostname,
        vendor=unchanged_result.mac_vendor,
        os_name="FreeBSD",
        device_type="firewall",
        device_type_source="ai",
        mac_address=unchanged_result.host.mac_address,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    unchanged_db = _FakeDb(execute_result=_ScalarResult([existing]))
    monkeypatch.setattr("app.db.upsert._persist_asset_context", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr("app.db.upsert._upsert_ports", lambda *args, **kwargs: _completed_task({}))
    monkeypatch.setattr("app.db.upsert._apply_asset_updates", lambda *args, **kwargs: None)
    _, unchanged = await upsert_scan_result(unchanged_db, unchanged_result)
    assert unchanged == "unchanged"

    updated = Asset(
        id=uuid4(),
        ip_address="192.168.1.212",
        status="offline",
        hostname="old",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    updated_db = _FakeDb(execute_result=_ScalarResult([updated]))
    monkeypatch.setattr("app.db.upsert._persist_asset_context", lambda *args, **kwargs: _completed_task(None))
    monkeypatch.setattr("app.db.upsert._upsert_ports", lambda *args, **kwargs: _completed_task({"port_80/tcp": {"old": None, "new": "open"}}))
    _, updated_change = await upsert_scan_result(updated_db, _sample_result("192.168.1.212"))
    assert updated_change == "updated"
    assert any(getattr(entry, "change_type", "").endswith("_changed") or getattr(entry, "change_type", "") == "status_change" for entry in updated_db.added)


@pytest.mark.asyncio
async def test_scans_routes_cover_ingest_get_scan_control_and_reorder(monkeypatch):
    observed = [
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.10", mac_address="AA"), reverse_hostname="router"),
        HostScanResult(host=DiscoveredHost(ip_address="192.168.1.11", mac_address="BB"), reverse_hostname="nas"),
    ]
    assets = [
        SimpleNamespace(ip_address="192.168.1.10", mac_address="AA", hostname="router", effective_device_type="router"),
        SimpleNamespace(ip_address="192.168.1.11", mac_address="BB", hostname="nas", effective_device_type="nas"),
    ]
    changes = iter(["discovered", "updated"])
    notifications = []
    passive = []
    monkeypatch.setattr(scans_routes, "parse_dns_dhcp_logs", lambda content: observed)
    monkeypatch.setattr(scans_routes, "upsert_scan_result", lambda db, row: _completed_task((assets[len(passive)], next(changes))))
    monkeypatch.setattr(scans_routes, "record_passive_observation", lambda *args, **kwargs: _completed_task(passive.append(kwargs)))
    monkeypatch.setattr(scans_routes, "notify_new_device", lambda payload: _completed_task(notifications.append(payload)))
    ingest_db = _FakeDb()
    ingest = await scans_routes.ingest_logs(scans_routes.IngestLogsRequest(content="lease"), ingest_db, object())
    assert ingest == {"records_parsed": 2, "new_assets": 1, "changed_assets": 1}
    assert len(notifications) == 1
    assert ingest_db.committed is True

    parent = ScanJob(id=uuid4(), status="running", created_at=datetime.now(timezone.utc))
    child = ScanJob(id=uuid4(), parent_id=parent.id, status="pending", created_at=datetime.now(timezone.utc), chunk_index=1)

    class _GetScanDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([child])

    get_db = _GetScanDb(get_result=parent)
    parent_scan = await scans_routes.get_scan(parent.id, get_db, object())
    assert len(parent_scan["child_jobs"]) == 1

    published = []
    started = []
    monkeypatch.setattr(scans_routes, "_cancel_scan_job", lambda job, mode, db: _completed_task((True, False)))
    monkeypatch.setattr(scans_routes, "_publish_event", lambda payload: _completed_task(published.append(payload)))
    monkeypatch.setattr(scans_routes, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(scans_routes, "_get_next_queued_job", lambda db: _completed_task(SimpleNamespace(id=uuid4())))
    class _Runner:
        @staticmethod
        def delay(job_id: str):
            started.append(job_id)
    monkeypatch.setattr(scans_routes, "run_scan_job", _Runner())
    control_db = _FakeDb(get_result=parent)
    control = await scans_routes.control_scan(parent.id, scans_routes.ScanControlRequest(action="cancel", mode="discard"), control_db, object())
    assert control["status"] == parent.status
    assert published and started

    queue_items = [
        ScanJob(id=uuid4(), status="pending", created_at=datetime.now(timezone.utc), queue_position=1),
        ScanJob(id=uuid4(), status="pending", created_at=datetime.now(timezone.utc), queue_position=2),
    ]
    reorder_target = queue_items[1]

    class _ReorderDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult(queue_items)

    reorder_db = _ReorderDb(get_result=reorder_target)
    monkeypatch.setattr(scans_routes, "_normalize_pending_queue", lambda db: _completed_task(None))
    monkeypatch.setattr(scans_routes, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(scans_routes, "_get_next_queued_job", lambda db: _completed_task(reorder_target))
    reordered = await scans_routes.reorder_scan_queue(reorder_target.id, scans_routes.ScanQueueRequest(action="start_now"), reorder_db, object())
    assert reordered["status"] == "ok"
    assert reordered["action"] == "start_now"


@pytest.mark.asyncio
async def test_worker_startup_resume_dispatches_first_pending_job(monkeypatch):
    started = []

    class _Runner:
        @staticmethod
        def delay(job_id: str):
            started.append(job_id)

    class _Engine:
        async def dispose(self):
            return None

    class _ContextSessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return _FakeDb()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    job = SimpleNamespace(id=uuid4(), queue_position=1)
    monkeypatch.setattr(worker_tasks, "run_scan_job", _Runner())
    monkeypatch.setattr(worker_tasks, "_has_active_scan", lambda db: _completed_task(False))
    monkeypatch.setattr(worker_tasks, "_get_next_queued_job", lambda db: _completed_task(job))
    monkeypatch.setattr("sqlalchemy.ext.asyncio.create_async_engine", lambda *args, **kwargs: _Engine())
    monkeypatch.setattr("sqlalchemy.ext.asyncio.async_sessionmaker", lambda *args, **kwargs: _ContextSessionFactory())

    await worker_tasks._resume_pending_queue_on_startup()
    assert started == [str(job.id)]


@pytest.mark.asyncio
async def test_assets_routes_cover_update_tags_backups_and_reports(monkeypatch):
    now = datetime.now(timezone.utc)
    asset = Asset(id=uuid4(), ip_address="192.168.1.220", status="online", first_seen=now, last_seen=now, hostname="edge")
    asset.tags = [AssetTag(tag="core")]
    asset.ports = []
    asset.ai_analysis = None
    asset.evidence = []
    asset.probe_runs = []
    asset.observations = []
    asset.fingerprint_hypotheses = []
    asset.internet_lookup_results = []
    asset.lifecycle_records = []
    asset.autopsy = None

    class _AssetOpsDb(_FakeDb):
        async def execute(self, stmt):
            return _ScalarResult([asset])

    ops_db = _AssetOpsDb(get_result=asset)
    updated = await assets_routes.update_asset(asset.id, {"hostname": "new-edge", "device_type": "router"}, ops_db, object())
    assert updated["hostname"] == "new-edge"
    assert asset.device_type_override == "router"

    with pytest.raises(HTTPException):
        await assets_routes.update_asset(asset.id, {"device_type": "bad-type"}, ops_db, object())

    history_db = _AssetOpsDb(get_result=asset)
    history = await assets_routes.get_asset_history(asset.id, history_db, object())
    assert history[0] is asset
    ports = await assets_routes.get_asset_ports(asset.id, history_db, object())
    assert ports[0] is asset

    blank_tag_db = _FakeDb(get_result=asset, execute_result=_ScalarResult([]))
    with pytest.raises(HTTPException):
        await assets_routes.add_asset_tag(asset.id, assets_routes.AssetTagRequest(tag=" "), blank_tag_db, object())

    existing_tag_db = _FakeDb(get_result=asset, execute_result=_ScalarResult([AssetTag(tag="core")]))
    with pytest.raises(HTTPException):
        await assets_routes.add_asset_tag(asset.id, assets_routes.AssetTagRequest(tag="core"), existing_tag_db, object())

    fresh_tag_db = _FakeDb(get_result=asset, execute_result=_ScalarResult([]))
    tag = await assets_routes.add_asset_tag(asset.id, assets_routes.AssetTagRequest(tag=" NewTag "), fresh_tag_db, object())
    assert tag.tag == "newtag"

    bulk_delete_db = _AssetOpsDb()
    deleted = await assets_routes.bulk_delete_assets(
        assets_routes.BulkDeleteAssetsRequest(asset_ids=[asset.id]),
        bulk_delete_db,
        object(),
    )
    assert deleted == {"deleted": 1}
    assert bulk_delete_db.committed is True

    delete_tag_db = _FakeDb(execute_result=_ScalarResult([AssetTag(asset_id=asset.id, tag="core")]))
    await assets_routes.delete_asset_tag(asset.id, "CORE", delete_tag_db, object())
    assert delete_tag_db.committed is True

    monkeypatch.setattr(assets_routes, "get_backup_target", lambda db, asset_id: _completed_task(None))
    assert await assets_routes.read_config_backup_target(asset.id, _FakeDb(get_result=asset), object()) is None

    backup_target = SimpleNamespace(
        id=1, asset_id=asset.id, driver="ssh", username="admin", password_env_var="PW", port=22, host_override=None, enabled=True,
        created_at=now, updated_at=now,
    )
    monkeypatch.setattr(assets_routes, "upsert_backup_target", lambda *args, **kwargs: _completed_task(backup_target))
    written = await assets_routes.write_config_backup_target(
        asset.id,
        assets_routes.ConfigBackupTargetRequest(driver="ssh", username=" admin ", password_env_var=" PW ", host_override=" ", enabled=True),
        _FakeDb(get_result=asset),
        object(),
    )
    assert written["driver"] == "ssh"

    monkeypatch.setattr(assets_routes, "list_backup_snapshots", lambda db, asset_id: _completed_task([SimpleNamespace(
        id=1, asset_id=asset.id, target_id=1, status="done", driver="ssh", command="show run", content="cfg", error=None, captured_at=now,
    )]))
    backups = await assets_routes.get_config_backups(asset.id, _FakeDb(get_result=asset), object())
    assert backups[0]["status"] == "done"

    monkeypatch.setattr(assets_routes, "capture_backup_for_asset", lambda db, asset_id: _completed_task(SimpleNamespace(
        id=1, asset_id=asset.id, target_id=1, status="done", driver="ssh", command="show run", content="cfg", error=None, captured_at=now,
    )))
    captured = await assets_routes.trigger_config_backup(asset.id, _FakeDb(), object())
    assert captured["id"] == 1

    monkeypatch.setattr(assets_routes, "capture_backup_for_asset", lambda db, asset_id: (_ for _ in ()).throw(LookupError("missing")))
    with pytest.raises(HTTPException):
        await assets_routes.trigger_config_backup(asset.id, _FakeDb(), object())

    monkeypatch.setattr(assets_routes, "get_backup_snapshot", lambda db, asset_id, snapshot_id: _completed_task(SimpleNamespace(content="cfg")))
    downloaded = await assets_routes.download_config_backup(asset.id, 1, _FakeDb(), object())
    assert downloaded.body == b"cfg"

    monkeypatch.setattr(assets_routes, "generate_backup_diff", lambda *args, **kwargs: _completed_task(""))
    diff = await assets_routes.diff_config_backup(asset.id, 1, None, _FakeDb(), object())
    assert diff.body == b"No diff\n"

    monkeypatch.setattr(assets_routes, "generate_restore_assist", lambda *args, **kwargs: _completed_task({"steps": ["restore"]}))
    restore = await assets_routes.get_restore_assist(asset.id, 1, _FakeDb(), object())
    assert restore["steps"] == ["restore"]


@pytest.mark.asyncio
async def test_pipeline_persistence_helpers_cover_offline_ai_and_broadcast_paths(monkeypatch):
    summary = ScanSummary(job_id="job-300", targets="x", profile=ScanProfile.BALANCED)
    result = _sample_result("192.168.1.230")
    offline_asset = Asset(
        id=uuid4(),
        ip_address="192.168.1.250",
        hostname="old-host",
        status="offline",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    events = []
    topology = []
    notifications = []

    async def fake_broadcast(_payload):
        events.append(_payload)

    monkeypatch.setattr("app.scanner.pipeline._broadcast", lambda fn, payload: fake_broadcast(payload))

    from app.scanner import pipeline as pipeline_mod

    assert pipeline_mod._resolve_hostname_from_probes([
        ProbeResult(probe_type="dns", success=True, data={"hostname": "dns-host"}),
    ]) == "dns-host"
    assert pipeline_mod._resolve_hostname_from_probes([
        ProbeResult(probe_type="mdns", success=True, data={"services": [{"host": "mdns-host"}]}),
    ]) == "mdns-host"
    assert pipeline_mod._resolve_hostname_from_probes([
        ProbeResult(probe_type="snmp", success=True, data={"sys_name": "snmp-host"}),
    ]) == "snmp-host"
    assert pipeline_mod._extract_probe_hostname(ProbeResult(probe_type="http", success=True, data={})) is None

    analyst = SimpleNamespace(investigate=lambda row: _completed_task(AIAnalysis(device_class=DeviceClass.ROUTER, confidence=0.8, vendor="Cisco")))
    host_result = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.240"))
    await pipeline_mod._run_ai_investigation(analyst, host_result, object(), "job-300", "192.168.1.240")
    assert host_result.ai_analysis is not None

    weak = HostScanResult(host=DiscoveredHost(ip_address="192.168.1.241"))
    await pipeline_mod._persist_result(
        "db",
        weak,
        summary,
        object(),
        "job-300",
        "investigation",
        False,
        lambda row: False,
        lambda db, row: _completed_task((offline_asset, "discovered")),
        lambda *args, **kwargs: _completed_task(None),
        lambda *args, **kwargs: _completed_task(None),
        lambda *args, **kwargs: _completed_task(None),
    )
    assert summary.new_assets == 0

    async def fake_upsert(_db, _result):
        return offline_asset, "discovered"

    async def fake_topology(_db, _asset, data):
        topology.append(data)

    async def fake_notify(_db, payload):
        notifications.append(payload)

    snmp_result = HostScanResult(
        host=DiscoveredHost(ip_address="192.168.1.242"),
        reverse_hostname="edge",
        probes=[ProbeResult(probe_type="snmp", success=True, data={"sys_name": "edge"})],
        ai_analysis=AIAnalysis(device_class=DeviceClass.ROUTER, confidence=0.9),
    )
    await pipeline_mod._persist_result(
        "db",
        snmp_result,
        summary,
        object(),
        "job-300",
        "investigation",
        True,
        lambda row: True,
        fake_upsert,
        fake_topology,
        lambda *args, **kwargs: _completed_task(None),
        fake_notify,
    )
    assert summary.new_assets == 1
    assert topology == [{"sys_name": "edge"}]
    assert notifications
    assert events[-1]["event"] == "device_discovered"

    await pipeline_mod._update_summary(summary, object(), "job-300", snmp_result, "updated", "db", fake_notify, "investigation")
    assert summary.changed_assets == 1
    assert events[-1]["event"] == "device_updated"

    assert pipeline_mod._offline_notification_payload(offline_asset)["hostname"] == "old-host"

    offline_notifications = []
    await pipeline_mod._persist_offline_assets(
        "db",
        ["192.168.1.250"],
        summary,
        True,
        lambda db, ips: _completed_task((1, [offline_asset])),
        lambda db, payloads: _completed_task(offline_notifications.extend(payloads)),
    )
    assert summary.offline_assets == 1
    assert offline_notifications[0]["ip"] == "192.168.1.250"

    class _SelectStub:
        def where(self, *_args, **_kwargs):
            return self

    assert await pipeline_mod._get_offline_ips(
        SimpleNamespace(execute=lambda stmt: _completed_task(_ScalarResult([("192.168.1.1",), ("192.168.1.2",)]))),
        lambda value: _SelectStub(),
        SimpleNamespace(ip_address="ip_address", status="status"),
        {"192.168.1.2"},
        True,
    ) == ["192.168.1.1"]


@pytest.mark.asyncio
async def test_scanner_config_clear_inventory_counts_and_audits(monkeypatch):
    audit_calls = []
    scalar_values = iter([5, 2])

    class _ClearDb(_FakeDb):
        async def scalar(self, stmt):
            return next(scalar_values)

    async def fake_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(scanner_config, "log_audit_event", fake_audit)
    db = _ClearDb()
    result = await scanner_config.clear_inventory(db, include_scan_history=True, actor=SimpleNamespace(id=uuid4()))
    assert result == {"assets_deleted": 5, "scans_deleted": 2}
    assert len(db.executed) >= 7
    assert audit_calls


def test_tplink_deco_normalizers_and_log_helpers_cover_more_branches():
    client = tplink_deco.normalize_deco_client(
        {
            "mac_addr": "aa-bb-cc-dd-ee-ff",
            "client_ip": "192.168.1.50",
            "host_name": "VGVzdCBDbGllbnQ=",
            "alias": "Laptop",
            "brand": "MacBook",
            "connect_type": "wireless",
            "slave_name": "Deco Office",
        }
    )
    assert client.mac == "AA:BB:CC:DD:EE:FF"
    assert client.hostname == "Test Client"
    assert client.nickname == "Laptop"
    assert client.access_point_name == "Deco Office"

    device = tplink_deco.normalize_deco_device(
        {
            "mac_addr": "11-22-33-44-55-66",
            "device_ip": "192.168.1.2",
            "custom_nickname": "RGVjbyBPZmZpY2U=",
            "device_model": "Deco X55",
            "role": "ap",
            "software_ver": "1.0",
            "hardware_ver": "2.0",
        }
    )
    assert device.mac == "11:22:33:44:55:66"
    assert device.hostname == "Deco Office"
    assert device.model == "Deco X55"

    assert tplink_deco._normalize_mac("bad-mac") is None
    assert tplink_deco._coalesce_str({"a": " ", "b": "x"}, ["a", "b"]) == "x"
    assert tplink_deco._md5_hex("abc")
    assert tplink_deco._parse_cookie_sysauth(httpx.Headers({"set-cookie": "sysauth=token123; Path=/"})) == "token123"

    issue_map, macs = tplink_deco._collect_deco_log_matches(
        [
            "Cannot find aa:bb:cc:dd:ee:ff in apinfo list",
            "Invalid message len: 12 bytes",
            "AP-STA-CONNECTED AA:BB:CC:DD:EE:11",
        ],
        tplink_deco._deco_log_pattern_catalog(),
    )
    issues, penalty = tplink_deco._build_deco_issues(issue_map)
    recs = tplink_deco._build_deco_recommendations(issues)
    assert macs
    assert penalty > 0
    assert recs

    assert tplink_deco._augment_logs_with_summary(None) is None
    assert "# Parsed Deco Log Summary" in tplink_deco._augment_logs_with_summary("AP-STA-CONNECTED AA:BB:CC:DD:EE:11")


@pytest.mark.asyncio
async def test_tplink_deco_sync_helpers_cover_serializers_fetch_and_finalize(monkeypatch):
    now = datetime.now(timezone.utc)
    config = SimpleNamespace(
        id=1,
        enabled=True,
        base_url="http://tplinkdeco.net",
        owner_username=" ",
        owner_password="secret",
        fetch_connected_clients=True,
        fetch_portal_logs=True,
        request_timeout_seconds=10,
        verify_tls=False,
        last_tested_at=now,
        last_sync_at=now,
        last_status="healthy",
        last_error=None,
        last_client_count=2,
        created_at=now,
        updated_at=now,
    )
    serialized = tplink_deco.serialize_tplink_deco_config(config)
    assert serialized["effective_owner_username"] == "admin"

    run = SimpleNamespace(
        id=9,
        status="done",
        client_count=2,
        clients_payload=[{"a": 1}],
        logs_excerpt="log",
        log_analysis={"health_score": 90},
        error=None,
        started_at=now,
        finished_at=now,
    )
    assert tplink_deco.serialize_tplink_deco_sync_run(run)["id"] == 9

    html_response = httpx.Response(200, text="plain log text")
    json_ok = httpx.Response(200, json={"error_code": 0, "foo": "bar"})
    json_error = httpx.Response(200, json={"error_code": 1})
    assert tplink_deco._parse_log_export_response(html_response) == "plain log text"
    assert '"foo": "bar"' in tplink_deco._parse_log_export_response(json_ok)
    assert tplink_deco._parse_log_export_response(json_error) is None

    fake_client = object.__new__(tplink_deco.TplinkDecoClient)
    fake_client.stok = "stok"
    fake_client.sysauth = "sysauth"
    pages = iter([
        tplink_deco.DecoLogPage(entries=["a", "b"], total_pages=2, current_index=0),
        tplink_deco.DecoLogPage(entries=["b", "c"], total_pages=2, current_index=1),
    ])

    async def fake_page(*args, **kwargs):
        return next(pages)

    async def fake_save():
        return None

    fake_client._fetch_feedback_log_page = fake_page
    fake_client._attempt_save_log_export = fake_save
    assembled = await tplink_deco.TplinkDecoClient.fetch_portal_logs(fake_client)
    assert assembled == "a\nb\nc"

    run_model = SimpleNamespace(status="running", client_count=0, clients_payload=None, logs_excerpt=None, log_analysis=None, finished_at=None, id=7)
    config_state = SimpleNamespace(last_sync_at=None, last_status=None, last_error="oops", last_client_count=0, owner_username=None)
    clients = [tplink_deco.DecoClientRecord(mac=None, ip="192.168.1.5", hostname="laptop", nickname=None, device_model=None, connection_type=None, access_point_name=None, raw={"a": 1})]
    log_analysis = {"health_score": 88, "issues": [{"key": "x"}]}
    tplink_deco._finalize_tplink_sync_run(run_model, config_state, clients, "logs", log_analysis)
    result = tplink_deco._serialize_tplink_sync_result(run_model, config_state, [], clients, 1, log_analysis)
    assert result["status"] == "done"
    assert result["health_score"] == 88


@pytest.mark.asyncio
async def test_tplink_deco_asset_enrichment_helpers_cover_tags_and_records(monkeypatch):
    asset = Asset(id=uuid4(), ip_address="192.168.1.60", status="offline", custom_fields={})
    client = tplink_deco.DecoClientRecord(
        mac="AA:BB:CC:DD:EE:FF",
        ip="192.168.1.60",
        hostname="laptop",
        nickname="macbook",
        device_model="MacBook",
        connection_type="wireless",
        access_point_name="Deco Office",
        raw={"client": True},
    )
    device = tplink_deco.DecoDeviceRecord(
        mac="11:22:33:44:55:66",
        ip="192.168.1.2",
        hostname="Deco Office",
        nickname="Office",
        model="Deco X55",
        role="ap",
        software_version="1.0",
        hardware_version="2.0",
        raw={"device": True},
    )
    observed = []
    monkeypatch.setattr(tplink_deco, "record_passive_observation", lambda *args, **kwargs: _completed_task(observed.append(kwargs)))
    monkeypatch.setattr(tplink_deco, "_existing_asset_tags", lambda db, asset_obj: _completed_task(set()))
    db = _FakeDb()
    await tplink_deco._enrich_asset_from_client(db, asset, client)
    await tplink_deco._enrich_asset_from_deco_device(db, asset, device)
    assert asset.status == "online"
    assert asset.custom_fields["tplink_deco"]["access_point_name"] == "Deco Office"
    assert asset.custom_fields["tplink_deco_device"]["model"] == "Deco X55"
    assert any(isinstance(item, AssetTag) for item in db.added)
    assert len(observed) == 2


def test_tplink_deco_crypto_and_misc_helpers_cover_roundtrips():
    private_key = tplink_deco.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    modulus_hex = format(numbers.n, "x")
    exponent_hex = format(numbers.e, "x")

    encrypted_hex = tplink_deco._rsa_encrypt_pkcs1_v15_hex(modulus_hex, exponent_hex, "secret")
    decrypted = private_key.decrypt(bytes.fromhex(encrypted_hex), tplink_deco.asym_padding.PKCS1v15()).decode("utf-8")
    assert decrypted == "secret"

    payload = {"hello": "world", "count": 2}
    encrypted = tplink_deco._aes_encrypt_base64("0123456789abcdef", "abcdef0123456789", '{"hello":"world","count":2}')
    assert tplink_deco._aes_decrypt_json("0123456789abcdef", "abcdef0123456789", encrypted.decode("utf-8")) == payload

    assert len(tplink_deco._rand16()) == 16
    assert tplink_deco._normalize_base_url("   ") == "http://tplinkdeco.net"
    assert tplink_deco._normalize_base_url(None) == "http://tplinkdeco.net"
    assert tplink_deco._decode_deco_label("") is None
    assert tplink_deco._empty_log_analysis()["health_score"] == 100


@pytest.mark.asyncio
async def test_tplink_deco_client_request_helpers_cover_bootstrap_and_wrappers(monkeypatch):
    calls = []

    class _Response:
        def __init__(self, payload, *, status_code=200, headers=None, text=None):
            self._payload = payload
            self.status_code = status_code
            self.headers = httpx.Headers(headers or {})
            self.text = payload if isinstance(payload, str) else (text or "")

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError("boom", request=httpx.Request("POST", "http://tplinkdeco.net"), response=httpx.Response(self.status_code))

        def json(self):
            return self._payload

    class _AsyncClient:
        def __init__(self, *args, **kwargs):
            self.closed = False

        async def post(self, path, **kwargs):
            calls.append((path, kwargs))
            form = (kwargs.get("params") or {}).get("form")
            if form == "keys":
                return _Response({"result": {"password": ["mod-pass", "10001"]}, "error_code": 0})
            if form == "auth":
                return _Response({"result": {"key": ["mod-req", "10001"], "seq": "7"}, "error_code": 0})
            if form == "login":
                return _Response({"data": "enc-login"}, headers={"set-cookie": "sysauth=cookie-token; Path=/"})
            if form == "client_list":
                return _Response({"data": "enc-clients"})
            if form == "device_list":
                return _Response({"data": "enc-devices"})
            if form == "feedback_log":
                return _Response(
                    {
                        "error_code": 0,
                        "logList": [{"content": " first "}, {"content": ""}, "skip"],
                        "totalNum": "2",
                        "currentIndex": "1",
                    }
                )
            if form == "save_log":
                data = kwargs.get("data") or {}
                if data.get("operation") == "save":
                    return _Response("exported text", text="exported text")
            if form == "logout":
                return _Response({})
            raise AssertionError(f"Unexpected form: {form}")

        async def aclose(self):
            self.closed = True

    decrypt_values = iter(
        [
            {"result": {"stok": "stok-1"}},
            {"result": {"client_list": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.7"}]}, "error_code": 0},
            {"result": {"device_list": [{"mac": "11:22:33:44:55:66", "ip": "192.168.1.2"}]}, "error_code": 0},
        ]
    )

    monkeypatch.setattr(tplink_deco.httpx, "AsyncClient", _AsyncClient)
    monkeypatch.setattr(tplink_deco, "_rand16", lambda: "0123456789abcdef")
    monkeypatch.setattr(tplink_deco, "_rsa_encrypt_pkcs1_v15_hex", lambda *args, **kwargs: "RSA")
    monkeypatch.setattr(tplink_deco, "_aes_encrypt_base64", lambda *args, **kwargs: b"ciphertext")
    monkeypatch.setattr(tplink_deco, "_aes_decrypt_json", lambda *args, **kwargs: next(decrypt_values))

    client = tplink_deco.TplinkDecoClient(base_url="tplinkdeco.net", owner_username=" ", owner_password="secret", timeout_seconds=1, verify_tls=True)
    assert client.base_url == "http://tplinkdeco.net"
    assert client.owner_username == "admin"
    assert client.timeout_seconds == 3

    await client.bootstrap()
    sign, payload = client._build_login_payload()
    assert sign == "RSARSA"
    assert payload == b"ciphertext"

    login_payload = await client.login()
    assert login_payload["result"]["stok"] == "stok-1"
    assert client.stok == "stok-1"
    assert client.sysauth == "cookie-token"

    clients = await client.fetch_connected_clients()
    devices = await client.fetch_deco_devices()
    assert clients[0].ip == "192.168.1.7"
    assert devices[0].ip == "192.168.1.2"

    page = await client._fetch_feedback_log_page()
    assert page.entries == ["first"]
    assert page.total_pages == 2

    exported = await client._attempt_save_log_export()
    assert exported == "exported text"

    assert await client.__aenter__() is client
    await client.logout()
    assert client.stok is None
    await client.__aexit__(None, None, None)
    assert client._client.closed is True


@pytest.mark.asyncio
async def test_tplink_deco_config_and_resolution_helpers_cover_crud_and_asset_resolution(monkeypatch):
    created_config = tplink_deco.TplinkDecoConfig(created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    db_existing = _FakeDb(execute_result=_ScalarResult([created_config]))
    assert await tplink_deco.get_or_create_tplink_deco_config(db_existing) is created_config

    db_new = _FakeDb(execute_result=_ScalarResult([]))
    new_config = await tplink_deco.get_or_create_tplink_deco_config(db_new)
    assert isinstance(new_config, tplink_deco.TplinkDecoConfig)
    assert db_new.added[-1] is new_config

    run_one = SimpleNamespace(id=1)
    run_two = SimpleNamespace(id=2)
    listed = await tplink_deco.list_recent_tplink_deco_sync_runs(_FakeDb(execute_result=_ScalarResult([run_one, run_two])), limit=2)
    assert listed == [run_one, run_two]

    holder = SimpleNamespace(
        enabled=False,
        base_url=None,
        owner_username="",
        owner_password="",
        fetch_connected_clients=False,
        fetch_portal_logs=False,
        request_timeout_seconds=0,
        verify_tls=False,
    )
    monkeypatch.setattr(tplink_deco, "get_or_create_tplink_deco_config", lambda db: _completed_task(holder))
    updated = await tplink_deco.update_tplink_deco_config(
        _FakeDb(),
        enabled=True,
        base_url="tplinkdeco.net",
        owner_username=" owner ",
        owner_password=" pass ",
        fetch_connected_clients=True,
        fetch_portal_logs=True,
        request_timeout_seconds=1,
        verify_tls=True,
    )
    assert updated.enabled is True
    assert updated.base_url == "http://tplinkdeco.net"
    assert updated.owner_username == "owner"
    assert updated.owner_password == "pass"
    assert updated.request_timeout_seconds == 3

    existing_asset = Asset(id=uuid4(), ip_address="192.168.1.50", mac_address="AA:BB:CC:DD:EE:FF", status="offline")
    pending_results = iter([_ScalarResult([existing_asset]), _ScalarResult([]), _ScalarResult([existing_asset])])

    class _ResolveDb(_FakeDb):
        async def execute(self, stmt):
            self.executed.append(stmt)
            return next(pending_results)

    resolve_db = _ResolveDb()
    client_with_mac = tplink_deco.DecoClientRecord(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.51", hostname="host", nickname=None, device_model=None, connection_type=None, access_point_name=None, raw={})
    assert await tplink_deco._resolve_asset_for_client(resolve_db, client_with_mac) is existing_asset

    client_new = tplink_deco.DecoClientRecord(mac=None, ip="192.168.1.60", hostname="new-host", nickname="nick", device_model=None, connection_type=None, access_point_name=None, raw={})
    created_asset = await tplink_deco._resolve_asset_for_client(resolve_db, client_new)
    assert created_asset.ip_address == "192.168.1.60"
    assert created_asset.hostname == "new-host"

    device_with_ip = tplink_deco.DecoDeviceRecord(mac=None, ip="192.168.1.50", hostname="deco", nickname=None, model=None, role=None, software_version=None, hardware_version=None, raw={})
    assert await tplink_deco._resolve_asset_for_deco_device(resolve_db, device_with_ip) is existing_asset

    device_none = tplink_deco.DecoDeviceRecord(mac=None, ip=None, hostname=None, nickname=None, model=None, role=None, software_version=None, hardware_version=None, raw={})
    assert await tplink_deco._resolve_asset_for_deco_device(resolve_db, device_none) is None

    assert str(tplink_deco.func_lower("ABC")).lower().find("lower") >= 0
    assert await tplink_deco._existing_asset_tags(_FakeDb(execute_result=_ScalarResult([SimpleNamespace(tag="wifi")])), Asset(id=uuid4())) == {"wifi"}
    tag_names = {"wifi"}
    tag_db = _FakeDb()
    tplink_deco._ensure_asset_tag(tag_db, Asset(id=uuid4()), "wifi", tag_names)
    tplink_deco._ensure_asset_tag(tag_db, Asset(id=uuid4()), "tplink-deco", tag_names)
    assert len(tag_db.added) == 1


@pytest.mark.asyncio
async def test_tplink_deco_top_level_wrappers_cover_connection_sync_and_audit(monkeypatch):
    config = SimpleNamespace(
        id=7,
        enabled=True,
        base_url="http://tplinkdeco.net",
        owner_username="owner",
        owner_password="secret",
        fetch_connected_clients=True,
        fetch_portal_logs=True,
        request_timeout_seconds=5,
        verify_tls=False,
        last_tested_at=None,
        last_sync_at=None,
        last_status=None,
        last_error="old",
        last_client_count=0,
    )

    class _CtxClient:
        def __init__(self, **kwargs):
            self.logged_out = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def login(self):
            return {"ok": True}

        async def fetch_deco_devices(self):
            return [tplink_deco.DecoDeviceRecord(mac=None, ip="192.168.1.2", hostname="Deco", nickname=None, model=None, role=None, software_version=None, hardware_version=None, raw={})]

        async def fetch_connected_clients(self):
            return [tplink_deco.DecoClientRecord(mac=None, ip="192.168.1.5", hostname="Laptop", nickname=None, device_model=None, connection_type=None, access_point_name=None, raw={"client": True})]

        async def fetch_portal_logs(self):
            return "AP-STA-CONNECTED AA:BB:CC:DD:EE:11"

        async def logout(self):
            self.logged_out = True

    audit_calls = []

    async def fake_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(tplink_deco, "TplinkDecoClient", _CtxClient)
    monkeypatch.setattr(tplink_deco, "get_or_create_tplink_deco_config", lambda db: _completed_task(config))
    monkeypatch.setattr(tplink_deco, "log_audit_event", fake_audit)

    db = _FakeDb()
    connection_result = await tplink_deco.test_tplink_deco_connection(db)
    assert connection_result["status"] == "healthy"
    assert connection_result["client_count"] == 1
    assert config.last_status == "healthy"

    async def fake_fetch_payload(cfg):
        return (
            [tplink_deco.DecoDeviceRecord(mac=None, ip="192.168.1.2", hostname="Deco", nickname=None, model=None, role=None, software_version=None, hardware_version=None, raw={})],
            [tplink_deco.DecoClientRecord(mac=None, ip="192.168.1.8", hostname="Phone", nickname=None, device_model=None, connection_type=None, access_point_name=None, raw={"client": True})],
            "AP-STA-CONNECTED AA:BB:CC:DD:EE:11",
        )

    async def fake_ingest(db_obj, devices, clients):
        return len(devices) + len(clients)

    monkeypatch.setattr(tplink_deco, "_fetch_tplink_sync_payload", fake_fetch_payload)
    monkeypatch.setattr(tplink_deco, "_ingest_tplink_records", fake_ingest)

    sync_result = await tplink_deco.sync_tplink_deco_module(db)
    assert sync_result["status"] == "done"
    assert sync_result["ingested_assets"] == 2
    assert sync_result["issue_count"] >= 0

    config.enabled = False
    with pytest.raises(ValueError):
        await tplink_deco.sync_tplink_deco_module(db)
    config.enabled = True
    config.owner_password = None
    with pytest.raises(ValueError):
        await tplink_deco.test_tplink_deco_connection(db)
    with pytest.raises(ValueError):
        await tplink_deco.sync_tplink_deco_module(db)

    config.owner_password = "secret"
    failing_db = _FakeDb()

    async def boom_fetch(cfg):
        raise RuntimeError("sync failed")

    monkeypatch.setattr(tplink_deco, "_fetch_tplink_sync_payload", boom_fetch)
    with pytest.raises(RuntimeError):
        await tplink_deco.sync_tplink_deco_module(failing_db)
    assert any(isinstance(item, tplink_deco.TplinkDecoSyncRun) for item in failing_db.added)
    assert config.last_status == "error"
    assert config.last_error == "sync failed"

    await tplink_deco.audit_tplink_config_change(_FakeDb(), user=SimpleNamespace(id=uuid4()), config=SimpleNamespace(id=9, enabled=True, base_url="http://tplinkdeco.net"))
    assert audit_calls[0]["action"] == "module.tplink_deco.updated"
