from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.db.models import ScanJob
from app.db.session import AsyncSessionLocal
from app.scanner.models import AIAnalysis, DeviceClass, DiscoveredHost, OSFingerprint, PortResult, ProbeResult, ScanProfile
from app.scanner.pipeline import ScanControlInterrupt, _persist_results, run_scan
from app.scanner.stages.discovery import sweep
from app.scanner.stages.fingerprint import classify, probe_priority
from app.scanner.stages.portscan import build_escalated_args
from app.workers.tasks import _run_job_async


@pytest.mark.asyncio
async def test_discovery_sweep_merges_results_and_prefers_arp_mac(monkeypatch):
    async def fake_arp(_targets: str, _timeout: int):
        return [DiscoveredHost(ip_address="192.168.96.10", mac_address="AA:BB:CC:DD:EE:FF", discovery_method="arp")]

    async def fake_ping(_targets: str, _timeout: int):
        return [
            DiscoveredHost(ip_address="192.168.96.10", discovery_method="ping"),
            DiscoveredHost(ip_address="192.168.96.11", discovery_method="ping", ttl=64),
        ]

    monkeypatch.setattr("app.scanner.stages.discovery._arp_sweep", fake_arp)
    monkeypatch.setattr("app.scanner.stages.discovery._ping_sweep", fake_ping)

    hosts = await sweep("192.168.96.0/24")
    host_map = {host.ip_address: host for host in hosts}

    assert len(hosts) == 2
    assert host_map["192.168.96.10"].mac_address == "AA:BB:CC:DD:EE:FF"
    assert host_map["192.168.96.11"].ttl == 64


def test_fingerprint_rules_capture_homelab_firewall_signals():
    host = DiscoveredHost(ip_address="192.168.100.1", nmap_hostname="firewalla.lan")
    ports = [
        PortResult(port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH"),
        PortResult(port=53, protocol="tcp", state="open", service="domain", product="dnsmasq"),
        PortResult(port=443, protocol="tcp", state="open", service="https"),
    ]
    os_fp = OSFingerprint(os_name="Linux 5.x", device_type="general purpose|router")

    hint = classify(host, ports, os_fp, mac_vendor="Firewalla")
    priorities = probe_priority(host, ports, hint)

    assert hint.device_class == DeviceClass.FIREWALL
    assert hint.confidence >= 0.95
    assert "tls" in priorities
    assert "ssh" in priorities
    assert "dns" in priorities


def test_build_escalated_args_targets_only_detected_services():
    args = build_escalated_args(
        [
            PortResult(port=22, protocol="tcp", state="open", service="ssh"),
            PortResult(port=80, protocol="tcp", state="open", service="http"),
            PortResult(port=161, protocol="udp", state="open", service="snmp"),
        ]
    )

    assert "-p 161,22,80" in args or "-p 22,80,161" in args or "-p 22,161,80" in args
    assert "ssh2-enum-algos" in args
    assert "http-title" in args
    assert "snmp-info" in args


@pytest.mark.asyncio
async def test_run_scan_emits_progress_and_tallies_summary(monkeypatch):
    discovered_hosts = [
        DiscoveredHost(ip_address="192.168.96.10", mac_address="AA:BB:CC:DD:EE:01", discovery_method="arp"),
        DiscoveredHost(ip_address="192.168.96.11", mac_address="AA:BB:CC:DD:EE:02", discovery_method="arp"),
    ]
    persisted: list[tuple[str, set[str]]] = []
    broadcasts: list[dict] = []

    async def fake_sweep(_targets: str):
        return discovered_hosts

    async def fake_scan_hosts(hosts: list[DiscoveredHost], _profile: ScanProfile, _custom_args=None):
        return [
            ([PortResult(port=idx + 21, protocol="tcp", state="open", service="ssh")], OSFingerprint(os_name="Linux"), host.ip_address, f"host-{idx}.lan", "Firewalla")
            for idx, host in enumerate(hosts, start=1)
        ]

    class FakeAnalyst:
        async def investigate(self, result):
            return AIAnalysis(
                device_class=DeviceClass.FIREWALL,
                confidence=0.87,
                vendor=result.mac_vendor,
                model="Lab Gateway",
                os_guess=result.os_fingerprint.os_name,
                investigation_notes="Synthetic test analysis",
            )

    async def fake_persist(db_session, results, scanned_ips, summary, _broadcast_fn, _job_id):
        persisted.append((db_session, scanned_ips))
        summary.new_assets = 2
        summary.changed_assets = 1

    async def fake_investigate_host(**kwargs):
        host = kwargs["host"]
        ports = kwargs["ports"]
        return SimpleNamespace(
            host=host,
            ports=ports,
            open_ports=ports,
            probes=[ProbeResult(probe_type="snmp", success=True, data={"neighbors": []})],
            ai_analysis=AIAnalysis(
                device_class=DeviceClass.FIREWALL,
                confidence=0.87,
                vendor="Firewalla",
                model="Lab Gateway",
                os_guess="Linux",
                investigation_notes="Synthetic test analysis",
            ),
        )

    async def fake_broadcast(payload: dict):
        broadcasts.append(payload)

    monkeypatch.setattr("app.scanner.stages.discovery.sweep", fake_sweep)
    monkeypatch.setattr("app.scanner.stages.portscan.scan_hosts", fake_scan_hosts)
    monkeypatch.setattr("app.scanner.agent.get_analyst", lambda: FakeAnalyst())
    monkeypatch.setattr("app.scanner.pipeline._persist_results", fake_persist)
    monkeypatch.setattr("app.scanner.pipeline._investigate_host", fake_investigate_host)

    summary = await run_scan(
        job_id="job-1",
        targets="192.168.96.0/24",
        profile=ScanProfile.BALANCED,
        enable_ai=True,
        concurrent_hosts=2,
        db_session="db-marker",
        broadcast_fn=fake_broadcast,
    )

    assert summary.hosts_scanned == 2
    assert summary.hosts_up == 2
    assert summary.total_open_ports == 2
    assert summary.ai_analyses_completed == 2
    assert summary.new_assets == 2
    assert summary.changed_assets == 1
    assert persisted == [("db-marker", {"192.168.96.10", "192.168.96.11"})]
    assert [payload["event"] for payload in broadcasts].count("scan_progress") >= 4
    assert broadcasts[-1]["event"] == "scan_complete"


@pytest.mark.asyncio
async def test_persist_results_skips_weak_hosts_and_marks_offline(monkeypatch):
    upserted: list[str] = []
    topology_inference: list[str] = []
    notifications: list[list[dict]] = []

    weak = SimpleNamespace(host=DiscoveredHost(ip_address="192.168.96.20"), probes=[], ai_analysis=None)
    strong = SimpleNamespace(
        host=DiscoveredHost(ip_address="192.168.96.21"),
        probes=[ProbeResult(probe_type="snmp", success=True, data={"neighbors": []})],
        ai_analysis=AIAnalysis(device_class=DeviceClass.ROUTER, confidence=0.9),
        reverse_hostname="gateway.lan",
    )

    class FakeAsset:
        def __init__(self, ip_address: str, hostname: str | None = None):
            self.ip_address = ip_address
            self.hostname = hostname
            self.last_seen = None
            self.effective_device_type = "router"

    class FakeResult:
        def all(self):
            return [("192.168.96.30",), ("192.168.96.21",)]

    class FakeDb:
        async def execute(self, _stmt):
            return FakeResult()

        async def commit(self):
            return None

    async def fake_upsert_scan_result(_db, result):
        upserted.append(result.host.ip_address)
        return FakeAsset(result.host.ip_address, hostname="gateway.lan"), "discovered"

    async def fake_mark_offline(_db, offline_ips):
        return len(offline_ips), [FakeAsset(ip) for ip in offline_ips]

    async def fake_notify_new_device_if_enabled(_db, payload):
        notifications.append([payload])

    async def fake_notify_devices_offline_if_enabled(_db, payload):
        notifications.append(payload)

    async def fake_infer_topology_links_from_snmp(_db, asset, _probe_data):
        topology_inference.append(asset.ip_address)

    monkeypatch.setattr("app.scanner.config.has_meaningful_scan_evidence", lambda result: result is strong)
    monkeypatch.setattr("app.db.upsert.upsert_scan_result", fake_upsert_scan_result)
    monkeypatch.setattr("app.db.upsert.mark_offline", fake_mark_offline)
    monkeypatch.setattr("app.alerting.notify_new_device_if_enabled", fake_notify_new_device_if_enabled)
    monkeypatch.setattr("app.alerting.notify_devices_offline_if_enabled", fake_notify_devices_offline_if_enabled)
    monkeypatch.setattr("app.scanner.topology.infer_topology_links_from_snmp", fake_infer_topology_links_from_snmp)

    from app.scanner.models import ScanSummary

    summary = ScanSummary(job_id="job-2", targets="192.168.96.0/24", profile=ScanProfile.BALANCED)
    await _persist_results(
        FakeDb(),
        results=[weak, strong],
        scanned_ips={"192.168.96.21"},
        summary=summary,
        broadcast_fn=None,
        job_id="job-2",
    )

    assert upserted == ["192.168.96.21"]
    assert summary.new_assets == 1
    assert summary.offline_assets == 1
    assert topology_inference == ["192.168.96.21"]
    assert notifications[0][0]["ip"] == "192.168.96.21"
    assert notifications[1][0]["ip"] == "192.168.96.30"


@pytest.mark.asyncio
async def test_run_job_async_marks_cancelled_when_scan_interrupts(monkeypatch):
    async with AsyncSessionLocal() as db:
        job = ScanJob(
            targets="192.168.96.0/24",
            scan_type="balanced",
            triggered_by="manual",
            status="pending",
            queue_position=1,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = str(job.id)

    async def fake_get_or_create_scanner_config(_db):
        return SimpleNamespace(concurrent_hosts=2)

    def fake_materialize_scan_targets(targets: str) -> str:
        return targets

    async def fake_persist(*args, **kwargs):
        return None

    async def fake_publish_event(_payload: dict):
        return None

    async def fake_dispatch_next_scan_if_idle(_db):
        return None

    monkeypatch.setattr("app.workers.tasks.get_or_create_scanner_config", fake_get_or_create_scanner_config, raising=False)
    monkeypatch.setattr("app.scanner.config.get_or_create_scanner_config", fake_get_or_create_scanner_config)
    monkeypatch.setattr("app.scanner.config.materialize_scan_targets", fake_materialize_scan_targets)

    from app.scanner.models import ScanSummary

    async def fake_run_scan_with_summary(**kwargs):
        raise ScanControlInterrupt(
            status="cancelled",
            message="Operator cancelled scan",
            summary=ScanSummary(job_id=kwargs["job_id"], targets=kwargs["targets"], profile=kwargs["profile"]),
            partial_results=[],
            scanned_ips=set(),
        )

    monkeypatch.setattr("app.scanner.pipeline.run_scan", fake_run_scan_with_summary)
    monkeypatch.setattr("app.scanner.pipeline._persist_results", fake_persist)
    monkeypatch.setattr("app.workers.tasks._publish_event", fake_publish_event)
    monkeypatch.setattr("app.workers.tasks._dispatch_next_scan_if_idle", fake_dispatch_next_scan_if_idle)

    await _run_job_async(job_id)

    async with AsyncSessionLocal() as db:
        refreshed = await db.get(ScanJob, job.id)

    assert refreshed is not None
    assert refreshed.status == "cancelled"
    assert refreshed.result_summary["message"] == "Operator cancelled scan"
