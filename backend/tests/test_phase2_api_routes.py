from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.db.models import (
    Asset,
    AssetAIAnalysis,
    AssetAutopsy,
    AssetEvidence,
    AssetTag,
    FingerprintHypothesis,
    InternetLookupResult,
    LifecycleRecord,
    PassiveObservation,
    Port,
    ProbeRun,
    ScanJob,
    User,
)
from app.db.session import AsyncSessionLocal


@pytest.mark.asyncio
async def test_auth_routes_support_login_identity_and_admin_only_actions(api_client, admin_user, viewer_user):
    # Exercise the live auth stack instead of overriding dependencies so the
    # coverage reflects the real request path used by the frontend.
    login = await api_client.post(
        "/api/v1/auth/token",
        data={"username": admin_user["username"], "password": admin_user["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    me = await api_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"

    viewer_attempt = await api_client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
        json={"username": "blocked", "password": "x", "role": "viewer"},
    )
    assert viewer_attempt.status_code == 403

    created = await api_client.post(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": "new-viewer",
            "password": "new-viewer-pass",
            "role": "viewer",
            "email": "new-viewer@example.com",
        },
    )
    assert created.status_code == 201
    created_user = created.json()

    updated = await api_client.patch(
        f"/api/v1/auth/users/{created_user['id']}",
        headers={"Authorization": f"Bearer {token}"},
        json={"role": "admin", "is_active": True},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_initial_admin_setup_creates_first_user_and_then_locks(api_client):
    status_before = await api_client.get("/api/v1/auth/setup/status")
    assert status_before.status_code == 200
    assert status_before.json()["needs_setup"] is True

    created = await api_client.post(
        "/api/v1/auth/setup/initialize",
        json={"username": "owner", "password": "supersecure123", "email": "owner@example.com"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["user"]["username"] == "owner"
    assert body["user"]["role"] == "admin"
    assert body["access_token"]

    status_after = await api_client.get("/api/v1/auth/setup/status")
    assert status_after.status_code == 200
    assert status_after.json()["needs_setup"] is False
    assert status_after.json()["user_count"] == 1

    locked = await api_client.post(
        "/api/v1/auth/setup/initialize",
        json={"username": "owner2", "password": "supersecure123"},
    )
    assert locked.status_code == 409


@pytest.mark.asyncio
async def test_scanner_config_routes_persist_runtime_settings(api_client, admin_user):
    headers = {"Authorization": f"Bearer {admin_user['token']}"}

    invalid = await api_client.put(
        "/api/v1/system/scanner-config",
        headers=headers,
        json={
            "enabled": True,
            "scheduled_scans_enabled": True,
            "default_targets": None,
            "auto_detect_targets": False,
            "default_profile": "balanced",
            "interval_minutes": 30,
            "concurrent_hosts": 64,
            "passive_arp_enabled": True,
            "passive_arp_interface": "eth0",
            "snmp_enabled": True,
            "snmp_version": "2c",
            "snmp_community": "public",
            "snmp_timeout": 5,
            "snmp_v3_username": None,
            "snmp_v3_auth_key": None,
            "snmp_v3_priv_key": None,
            "snmp_v3_auth_protocol": "sha",
            "snmp_v3_priv_protocol": "aes",
            "fingerprint_ai_enabled": False,
            "fingerprint_ai_model": "qwen2.5:7b",
            "fingerprint_ai_min_confidence": 0.75,
            "fingerprint_ai_prompt_suffix": None,
            "internet_lookup_enabled": False,
            "internet_lookup_allowed_domains": None,
            "internet_lookup_budget": 3,
            "internet_lookup_timeout_seconds": 5,
        },
    )
    assert invalid.status_code == 400

    payload = {
        "enabled": True,
        "scheduled_scans_enabled": True,
        "default_targets": "192.168.96.0/20",
        "auto_detect_targets": False,
        "default_profile": "deep",
        "interval_minutes": 45,
        "concurrent_hosts": 32,
        "passive_arp_enabled": True,
        "passive_arp_interface": "en0",
        "snmp_enabled": True,
        "snmp_version": "3",
        "snmp_community": None,
        "snmp_timeout": 8,
        "snmp_v3_username": "argus",
        "snmp_v3_auth_key": "auth-secret",
        "snmp_v3_priv_key": "priv-secret",
        "snmp_v3_auth_protocol": "sha",
        "snmp_v3_priv_protocol": "aes",
        "fingerprint_ai_enabled": True,
        "fingerprint_ai_model": "qwen2.5:7b",
        "fingerprint_ai_min_confidence": 0.8,
        "fingerprint_ai_prompt_suffix": "Prefer infrastructure labels.",
        "internet_lookup_enabled": True,
        "internet_lookup_allowed_domains": "docs.firewalla.com,nmap.org",
        "internet_lookup_budget": 4,
        "internet_lookup_timeout_seconds": 7,
    }
    updated = await api_client.put("/api/v1/system/scanner-config", headers=headers, json=payload)
    assert updated.status_code == 200
    body = updated.json()
    assert body["effective_targets"] == "192.168.96.0/20"
    assert body["scheduled_scans_enabled"] is True
    assert body["snmp_version"] == "3"
    assert body["snmp_v3_username"] == "argus"
    assert body["fingerprint_ai_enabled"] is True
    assert body["internet_lookup_enabled"] is True
    assert body["next_scheduled_scan_at"] is not None

    fetched = await api_client.get("/api/v1/system/scanner-config", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["passive_arp_interface"] == "en0"


@pytest.mark.asyncio
async def test_running_scan_cancel_discard_hard_revokes_and_releases_queue(api_client, admin_user, monkeypatch):
    queued_job_id: str | None = None
    published: list[dict] = []
    delayed: list[str] = []

    async with AsyncSessionLocal() as db:
        running = ScanJob(
            targets="192.168.96.0/20",
            scan_type="balanced",
            triggered_by="manual",
            status="running",
            started_at=datetime.now(timezone.utc),
            result_summary={"stage": "discovery", "progress": 0.05},
        )
        queued = ScanJob(
            targets="192.168.100.0/23",
            scan_type="balanced",
            triggered_by="manual",
            status="pending",
            queue_position=1,
        )
        db.add_all([running, queued])
        await db.commit()
        await db.refresh(running)
        await db.refresh(queued)
        running_id = str(running.id)
        queued_job_id = str(queued.id)

    monkeypatch.setattr("app.api.routes.scans._get_active_scan_task_ids", lambda job_id: ["task-1"] if job_id == running_id else [])
    monkeypatch.setattr("app.api.routes.scans.revoke_active_scan_job", lambda job_id: job_id == running_id)

    async def fake_publish_event(payload: dict):
        published.append(payload)

    class DelaySpy:
        def delay(self, job_id: str):
            delayed.append(job_id)

    monkeypatch.setattr("app.api.routes.scans._publish_event", fake_publish_event)
    monkeypatch.setattr("app.api.routes.scans.run_scan_job", DelaySpy())

    response = await api_client.post(
        f"/api/v1/scans/{running_id}/control",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"action": "cancel", "mode": "discard"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"

    async with AsyncSessionLocal() as db:
        refreshed = await db.get(ScanJob, UUID(running_id))

    assert refreshed is not None
    assert refreshed.status == "cancelled"
    assert refreshed.control_action is None
    assert refreshed.control_mode is None
    assert refreshed.finished_at is not None
    assert refreshed.result_summary["message"] == "Operator terminated scan"
    assert delayed == [queued_job_id]
    assert published and published[0]["event"] == "scan_complete"


@pytest.mark.asyncio
async def test_trigger_scan_rejects_unroutable_targets(api_client, admin_user, monkeypatch):
    monkeypatch.setattr("app.api.routes.scans.validate_scan_targets_routable", lambda targets: f"Unroutable: {targets}")

    response = await api_client.post(
        "/api/v1/scans/trigger",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"targets": "192.168.96.0/20", "scan_type": "balanced"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unroutable: 192.168.96.0/20"


@pytest.mark.asyncio
async def test_asset_routes_serialize_nested_inventory_context(api_client, admin_user):
    async with AsyncSessionLocal() as db:
        asset = Asset(
            ip_address="192.168.100.1",
            mac_address="20:6D:31:41:56:2A",
            hostname="firewalla.lan",
            vendor="Firewalla",
            os_name="Ubuntu Linux",
            os_version="22.04",
            device_type="firewall",
            device_type_source="rule",
            status="online",
            notes="Gateway appliance",
            custom_fields={"site": "lab"},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(asset)
        await db.flush()

        # Build a representative asset so serialization coverage catches
        # regressions in the detail page payload rather than just the happy path.
        db.add_all(
            [
                Port(asset_id=asset.id, port_number=22, protocol="tcp", service="ssh", version="OpenSSH", state="open"),
                AssetTag(asset_id=asset.id, tag="gateway"),
                AssetAIAnalysis(
                    asset_id=asset.id,
                    device_class="firewall",
                    confidence=0.92,
                    vendor="Firewalla",
                    model="Gold",
                    os_guess="Ubuntu Linux",
                    device_role="gateway",
                    open_services_summary=["SSH", "dnsmasq"],
                    security_findings=["SSH exposed on LAN"],
                    investigation_notes="Strong gateway fingerprint.",
                    suggested_tags=["security"],
                    ai_backend="ollama",
                    model_used="qwen2.5:7b",
                    agent_steps=4,
                ),
                AssetEvidence(
                    asset_id=asset.id,
                    source="mac_oui",
                    category="vendor",
                    key="vendor",
                    value="Firewalla",
                    confidence=0.99,
                    details={"oui": "20:6D:31"},
                ),
                ProbeRun(
                    asset_id=asset.id,
                    probe_type="tls",
                    target_port=443,
                    success=True,
                    duration_ms=21.5,
                    summary="Collected certificate metadata",
                    details={"cn": "firewalla.lan"},
                ),
                PassiveObservation(
                    asset_id=asset.id,
                    source="arp",
                    event_type="seen",
                    summary="Observed gateway traffic",
                    details={"interface": "en0"},
                ),
                FingerprintHypothesis(
                    asset_id=asset.id,
                    source="ollama",
                    device_type="firewall",
                    vendor="Firewalla",
                    model="Gold",
                    os_guess="Ubuntu Linux",
                    confidence=0.88,
                    summary="Vendor OUI and service mix align with Firewalla.",
                    supporting_evidence=["mac_oui", "dnsmasq"],
                ),
                InternetLookupResult(
                    asset_id=asset.id,
                    query="Firewalla dnsmasq OpenSSH Ubuntu",
                    domain="docs.firewalla.com",
                    url="https://docs.firewalla.com/example",
                    title="Firewalla service reference",
                    snippet="Firewalla ships dnsmasq for DNS services.",
                    confidence=0.74,
                ),
                LifecycleRecord(
                    asset_id=asset.id,
                    product="Firewalla Gold",
                    version="1.0",
                    support_status="supported",
                    eol_date=None,
                    reference="https://firewalla.com",
                    details={"channel": "stable"},
                ),
                AssetAutopsy(
                    asset_id=asset.id,
                    trace={"stages": [{"stage": "classification", "decision": "firewall"}]},
                ),
            ]
        )
        await db.commit()
        asset_id = str(asset.id)

    headers = {"Authorization": f"Bearer {admin_user['token']}"}
    listing = await api_client.get("/api/v1/assets/", headers=headers)
    assert listing.status_code == 200
    summary = next(row for row in listing.json() if row["id"] == asset_id)
    assert summary["device_type"] == "firewall"
    assert summary["open_ports_count"] == 1
    assert "evidence" not in summary
    assert "probe_runs" not in summary

    expanded = await api_client.get("/api/v1/assets/?include=ports,tags,ai,probe_runs", headers=headers)
    assert expanded.status_code == 200
    expanded_summary = next(row for row in expanded.json() if row["id"] == asset_id)
    assert expanded_summary["ports"][0]["port_number"] == 22
    assert expanded_summary["tags"][0]["tag"] == "gateway"
    assert expanded_summary["ai_analysis"]["vendor"] == "Firewalla"
    assert expanded_summary["probe_runs"][0]["probe_type"] == "tls"

    stats = await api_client.get("/api/v1/assets/stats?new_since=1970-01-01T00:00:00Z", headers=headers)
    assert stats.status_code == 200
    assert stats.json()["total"] >= 1
    assert stats.json()["online"] >= 1
    assert stats.json()["new_today"] >= 1

    detail = await api_client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["hostname"] == "firewalla.lan"
    assert body["ai_analysis"]["vendor"] == "Firewalla"
    assert body["evidence"][0]["source"] == "mac_oui"
    assert body["probe_runs"][0]["probe_type"] == "tls"
    assert body["autopsy"]["trace"]["stages"][0]["decision"] == "firewall"


@pytest.mark.asyncio
async def test_scan_and_inventory_routes_handle_permissions_and_side_effects(api_client, admin_user, viewer_user, monkeypatch):
    calls: list[str] = []

    class StubTask:
        @staticmethod
        def delay(job_id: str):
            calls.append(job_id)

    monkeypatch.setattr("app.api.routes.scans.run_scan_job", StubTask)

    viewer_trigger = await api_client.post(
        "/api/v1/scans/trigger",
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
        json={"targets": "192.168.96.0/24", "scan_type": "balanced"},
    )
    assert viewer_trigger.status_code == 403

    valid_trigger = await api_client.post(
        "/api/v1/scans/trigger",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"targets": "192.168.96.0/24", "scan_type": "balanced"},
    )
    assert valid_trigger.status_code == 200
    queued_job_id = valid_trigger.json()["job_id"]
    assert calls == [queued_job_id]

    async with AsyncSessionLocal() as db:
        job = await db.get(ScanJob, UUID(queued_job_id))
        assert job is not None
        assert job.targets == "192.168.96.0/24"
        db.add(Asset(ip_address="192.168.96.10", status="online"))
        await db.commit()

    bad_reset = await api_client.post(
        "/api/v1/system/inventory/reset",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"confirm": "nope", "include_scan_history": False},
    )
    assert bad_reset.status_code == 400

    good_reset = await api_client.post(
        "/api/v1/system/inventory/reset",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"confirm": "reset inventory", "include_scan_history": True},
    )
    assert good_reset.status_code == 200
    assert good_reset.json()["assets_deleted"] >= 1

    async with AsyncSessionLocal() as db:
        users = (await db.execute(User.__table__.select())).all()
        # Inventory resets should not wipe user accounts while clearing scan data.
        assert len(users) == 2
