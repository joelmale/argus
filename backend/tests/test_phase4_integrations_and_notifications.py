from __future__ import annotations

import pytest
from sqlalchemy import select

from app.alerting import ensure_default_alert_rules, notify_devices_offline_if_enabled, notify_new_device_if_enabled
from app.db.models import AlertRule, Asset, AssetTag, PassiveObservation, TplinkDecoSyncRun
from app.db.session import AsyncSessionLocal
from app.modules.tplink_deco import (
    DecoClientRecord,
    DecoDeviceRecord,
    sync_tplink_deco_module,
    test_tplink_deco_connection as run_tplink_deco_connection_test,
    update_tplink_deco_config,
)
from app.notifications import notify_devices_offline, notify_new_device


@pytest.mark.asyncio
async def test_notifications_only_call_enabled_channels(monkeypatch):
    webhook_calls: list[dict] = []
    email_calls: list[tuple[str, str]] = []

    async def fake_webhook(payload: dict):
        webhook_calls.append(payload)

    async def fake_email(subject: str, body: str):
        email_calls.append((subject, body))

    monkeypatch.setattr("app.notifications._send_webhook", fake_webhook)
    monkeypatch.setattr("app.notifications._send_email", fake_email)

    # Cover both fan-out helpers with explicit channel combinations so future
    # changes do not silently flip alert routing behavior.
    await notify_new_device({"ip": "192.168.96.10", "hostname": "lab-node"}, webhook=True, email=False)
    await notify_devices_offline(
        [{"ip": "192.168.96.11", "hostname": "offline-node"}],
        webhook=False,
        email=True,
    )

    assert webhook_calls == [{"event": "new_device", "data": {"ip": "192.168.96.10", "hostname": "lab-node"}}]
    assert email_calls[0][0] == "Argus offline devices: 1"
    assert "offline-node" in email_calls[0][1]


@pytest.mark.asyncio
async def test_alert_rules_gate_notification_dispatch(monkeypatch):
    new_device_calls: list[dict] = []
    offline_calls: list[list[dict]] = []

    async def fake_notify_new_device(payload: dict, *, webhook: bool = True, email: bool = True):
        new_device_calls.append({"payload": payload, "webhook": webhook, "email": email})

    async def fake_notify_devices_offline(devices: list[dict], *, webhook: bool = True, email: bool = True):
        offline_calls.append([*devices, {"webhook": webhook, "email": email}])

    monkeypatch.setattr("app.alerting.notify_new_device", fake_notify_new_device)
    monkeypatch.setattr("app.alerting.notify_devices_offline", fake_notify_devices_offline)

    async with AsyncSessionLocal() as db:
        await ensure_default_alert_rules(db)
        rules = (await db.execute(select(AlertRule).order_by(AlertRule.event_type.asc()))).scalars().all()
        assert {rule.event_type for rule in rules} == {"devices_offline", "new_device"}

        new_device_rule = next(rule for rule in rules if rule.event_type == "new_device")
        new_device_rule.notify_email = False
        offline_rule = next(rule for rule in rules if rule.event_type == "devices_offline")
        offline_rule.enabled = False
        await db.commit()

        await notify_new_device_if_enabled(db, {"ip": "192.168.96.20"})
        await notify_devices_offline_if_enabled(db, [{"ip": "192.168.96.21"}])

    assert new_device_calls == [{"payload": {"ip": "192.168.96.20"}, "webhook": True, "email": False}]
    assert offline_calls == []


@pytest.mark.asyncio
async def test_tplink_connection_and_sync_update_inventory(monkeypatch):
    class FakeTplinkClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def login(self):
            return {"result": {"stok": "stok"}}

        async def fetch_deco_devices(self):
            return [
                DecoDeviceRecord(
                    mac="AA:BB:CC:DD:EE:FF",
                    ip="192.168.100.1",
                    hostname="deco-office",
                    nickname="Deco Office",
                    model="Deco X55",
                    role="ap",
                    software_version="1.0.0",
                    hardware_version="1.0",
                    raw={"name": "Deco Office", "device_model": "Deco X55"},
                )
            ]

        async def fetch_connected_clients(self):
            return [
                DecoClientRecord(
                    mac="20:6D:31:41:56:2A",
                    ip="192.168.100.25",
                    hostname="joels-macbook",
                    nickname="Joel MacBook",
                    device_model="MacBook Pro",
                    connection_type="wireless",
                    access_point_name="Deco Office",
                    raw={"name": "joels-macbook", "device_model": "MacBook Pro"},
                )
            ]

        async def fetch_portal_logs(self):
            return "2026-03-19 client joined network"

        async def logout(self):
            return None

    monkeypatch.setattr("app.modules.tplink_deco.TplinkDecoClient", FakeTplinkClient)

    async with AsyncSessionLocal() as db:
        await update_tplink_deco_config(
            db,
            enabled=True,
            base_url="tplinkdeco.net",
            owner_username="owner",
            owner_password="secret",
            fetch_connected_clients=True,
            fetch_portal_logs=True,
            request_timeout_seconds=15,
            verify_tls=False,
        )
        await db.commit()

        test_result = await run_tplink_deco_connection_test(db)
        assert test_result["status"] == "healthy"
        assert test_result["client_count"] == 1

        sync_result = await sync_tplink_deco_module(db)
        await db.commit()

        assert sync_result["status"] == "done"
        assert sync_result["client_count"] == 1
        assert sync_result["ingested_assets"] == 1
        assert sync_result["log_excerpt_present"] is True

        asset = (
            await db.execute(select(Asset).where(Asset.ip_address == "192.168.100.25"))
        ).scalar_one()
        tags = (
            await db.execute(select(AssetTag).where(AssetTag.asset_id == asset.id).order_by(AssetTag.tag.asc()))
        ).scalars().all()
        observations = (
            await db.execute(select(PassiveObservation).where(PassiveObservation.asset_id == asset.id))
        ).scalars().all()
        run = (await db.execute(select(TplinkDecoSyncRun))).scalar_one()

    assert asset.mac_address == "20:6D:31:41:56:2A"
    assert asset.hostname == "joels-macbook"
    assert asset.custom_fields["tplink_deco"]["access_point_name"] == "Deco Office"
    assert [tag.tag for tag in tags] == ["tplink-deco", "wifi"]
    assert observations[0].source == "tplink_deco"
    assert run.status == "done"
    assert run.logs_excerpt.startswith("2026-03-19")


@pytest.mark.asyncio
async def test_tplink_connection_requires_password():
    async with AsyncSessionLocal() as db:
        await update_tplink_deco_config(
            db,
            enabled=True,
            base_url="http://tplinkdeco.net",
            owner_username="owner",
            owner_password=None,
            fetch_connected_clients=True,
            fetch_portal_logs=False,
            request_timeout_seconds=10,
            verify_tls=False,
        )
        await db.commit()

        with pytest.raises(ValueError, match="owner password"):
            await run_tplink_deco_connection_test(db)
