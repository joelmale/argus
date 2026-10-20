"""Finding lifecycle: reopen, escalate, suppress, resolve-by-source, acknowledge."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.db.models import Asset
from app.db.session import AsyncSessionLocal

INGEST = "/api/v1/findings/ingest"


@pytest.fixture
async def two_assets():
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        db.add_all([
            Asset(ip_address="192.168.88.10", hostname="homepod", status="online", first_seen=now, last_seen=now),
            Asset(ip_address="192.168.88.11", hostname="nas", status="online", first_seen=now, last_seen=now),
        ])
        await db.commit()


def _h(user):
    return {"Authorization": f"Bearer {user['token']}"}


def _item(key, severity="medium", ip="192.168.88.10", title="Container restarts endlessly"):
    return {"ip_address": ip, "external_id": key, "title": title, "severity": severity}


async def _ingest(api_client, user, items, resolved=None, source="insoc"):
    response = await api_client.post(
        INGEST, json={"source_tool": source, "findings": items, "resolved_external_ids": resolved or []}, headers=_h(user)
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _one(api_client, user, key, source="insoc"):
    rows = (await api_client.get("/api/v1/findings/", params={"source_tool": source, "external_id": key}, headers=_h(user))).json()
    assert len(rows) == 1, rows
    return rows[0]


@pytest.mark.asyncio
async def test_stable_key_survives_title_changes_and_counts_occurrences(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("docker:stump:crash_loop")])
    result = await _ingest(api_client, admin_user, [_item("docker:stump:crash_loop", title="Stump keeps crashing")])
    assert result["created"] == 0 and result["updated"] == 1
    row = await _one(api_client, admin_user, "docker:stump:crash_loop")
    assert row["occurrences"] == 2 and row["title"] == "Stump keeps crashing" and row["state"] == "open"


@pytest.mark.asyncio
async def test_same_key_on_different_assets_stays_separate(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("plugin-1234", ip="192.168.88.10"), _item("plugin-1234", ip="192.168.88.11")], source="nessus")
    rows = (await api_client.get("/api/v1/findings/", params={"source_tool": "nessus"}, headers=_h(admin_user))).json()
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_resolve_by_source_then_reopen(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("net:192.168.88.11:offline", ip="192.168.88.11")])
    result = await _ingest(api_client, admin_user, [], resolved=["net:192.168.88.11:offline", "unknown-key"])
    assert result["resolved"] == 1
    row = await _one(api_client, admin_user, "net:192.168.88.11:offline")
    assert row["state"] == "resolved" and row["resolved_at"]

    result = await _ingest(api_client, admin_user, [_item("net:192.168.88.11:offline", ip="192.168.88.11")])
    assert result["reopened"] == 1
    row = await _one(api_client, admin_user, "net:192.168.88.11:offline")
    assert row["state"] == "open" and row["resolved_at"] is None


@pytest.mark.asyncio
async def test_ack_holds_until_escalation(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("docker:radarr:unhealthy", severity="medium")])
    row = await _one(api_client, admin_user, "docker:radarr:unhealthy")

    ack = await api_client.post(f"/api/v1/findings/{row['id']}/ack", json={"hours": 24, "note": "known, fixing Friday"}, headers=_h(admin_user))
    assert ack.status_code == 200 and ack.json()["state"] == "acknowledged" and ack.json()["acked_by"] == "admin"

    await _ingest(api_client, admin_user, [_item("docker:radarr:unhealthy", severity="medium")])
    assert (await _one(api_client, admin_user, "docker:radarr:unhealthy"))["state"] == "acknowledged"

    result = await _ingest(api_client, admin_user, [_item("docker:radarr:unhealthy", severity="critical")])
    assert result["escalated"] == 1
    row = await _one(api_client, admin_user, "docker:radarr:unhealthy")
    assert row["state"] == "open" and row["ack_until"] is None


@pytest.mark.asyncio
async def test_unack_and_summary_counts(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("a:b:other"), _item("a:c:other")])
    row = await _one(api_client, admin_user, "a:b:other")
    await api_client.post(f"/api/v1/findings/{row['id']}/ack", json={}, headers=_h(admin_user))
    summary = (await api_client.get("/api/v1/findings/summary", headers=_h(admin_user))).json()
    assert summary["open"] == 1 and summary["acknowledged"] == 1

    unack = await api_client.post(f"/api/v1/findings/{row['id']}/unack", headers=_h(admin_user))
    assert unack.json()["state"] == "open"


@pytest.mark.asyncio
async def test_ignored_findings_stay_suppressed(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("sec:nas:exposure", ip="192.168.88.11")])
    row = await _one(api_client, admin_user, "sec:nas:exposure")
    patched = await api_client.patch(f"/api/v1/findings/{row['id']}", json={"status": "ignored"}, headers=_h(admin_user))
    assert patched.status_code == 200
    await _ingest(api_client, admin_user, [_item("sec:nas:exposure", ip="192.168.88.11", severity="critical")])
    assert (await _one(api_client, admin_user, "sec:nas:exposure"))["state"] == "ignored"
    # Only the documented statuses are accepted.
    bad = await api_client.patch(f"/api/v1/findings/{row['id']}", json={"status": "whatever"}, headers=_h(admin_user))
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_viewer_cannot_ack(api_client, admin_user, viewer_user, two_assets):
    await _ingest(api_client, admin_user, [_item("x:y:other")])
    row = await _one(api_client, admin_user, "x:y:other")
    response = await api_client.post(f"/api/v1/findings/{row['id']}/ack", json={}, headers=_h(viewer_user))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_cannot_ack_resolved(api_client, admin_user, two_assets):
    await _ingest(api_client, admin_user, [_item("p:q:other")])
    await _ingest(api_client, admin_user, [], resolved=["p:q:other"])
    row = await _one(api_client, admin_user, "p:q:other")
    response = await api_client.post(f"/api/v1/findings/{row['id']}/ack", json={}, headers=_h(admin_user))
    assert response.status_code == 409
