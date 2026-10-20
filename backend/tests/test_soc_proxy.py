"""Security page proxy to InSOC: config, filtering, validation, admin-only approvals, audit."""
from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from app.api.routes import soc
from app.core.config import settings
from app.db.models import AuditLog
from app.db.session import AsyncSessionLocal

IID = "INC-20261020-abc123"


def _h(user):
    return {"Authorization": f"Bearer {user['token']}"}


@pytest.fixture
def insoc(monkeypatch):
    monkeypatch.setattr(settings, "INSOC_URL", "http://insoc.test:8765")
    monkeypatch.setattr(settings, "INSOC_API_TOKEN", "insoc-secret")
    seen: list[httpx.Request] = []
    state = {"status": 200}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={"detail": "nope"})
        path = request.url.path
        if path == "/healthz":
            return httpx.Response(200, json={"ok": True})
        if path == "/incidents":
            return httpx.Response(200, json=[{"id": IID, "status": "awaiting_approval", "severity": "warning",
                                               "trigger": {"type": "sweep"}, "input_tokens": 999, "cost_usd": 0.01}])
        if path == f"/incidents/{IID}":
            return httpx.Response(200, json={"id": IID, "status": "awaiting_approval", "report": "Radarr down",
                                              "pending_approval": {"actions": [{"id": "a1b2c3d4", "action": "restart_container", "target": "radarr"}]},
                                              "ledger": [{"secret": "internal"}]})
        if path == f"/incidents/{IID}/resume":
            return httpx.Response(200, json={"id": IID, "status": "running", "echo": json.loads(request.content)})
        return httpx.Response(404, json={"detail": "not found"})

    real = httpx.AsyncClient
    monkeypatch.setattr(soc.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return seen, state


@pytest.mark.asyncio
async def test_not_configured(api_client, admin_user, monkeypatch):
    monkeypatch.setattr(settings, "INSOC_URL", "")
    assert (await api_client.get("/api/v1/soc/status", headers=_h(admin_user))).json() == {"configured": False, "reachable": False}
    assert (await api_client.get("/api/v1/soc/incidents", headers=_h(admin_user))).status_code == 503


@pytest.mark.asyncio
async def test_list_and_detail_are_filtered_and_use_server_token(api_client, viewer_user, insoc):
    seen, _ = insoc
    status = (await api_client.get("/api/v1/soc/status", headers=_h(viewer_user))).json()
    assert status == {"configured": True, "reachable": True}

    rows = (await api_client.get("/api/v1/soc/incidents", headers=_h(viewer_user))).json()
    assert rows[0]["id"] == IID and "input_tokens" not in rows[0]

    detail = (await api_client.get(f"/api/v1/soc/incidents/{IID}", headers=_h(viewer_user))).json()
    assert detail["report"] == "Radarr down" and "ledger" not in detail
    assert seen[-1].headers["authorization"] == "Bearer insoc-secret"


@pytest.mark.asyncio
async def test_rejects_malformed_incident_ids(api_client, admin_user, insoc):
    seen, _ = insoc
    for bad in ("..%2Fhealthz", "INC-1", "INC-20261020-ABC123"):
        assert (await api_client.get(f"/api/v1/soc/incidents/{bad}", headers=_h(admin_user))).status_code in (404, 422)
    assert seen == []


@pytest.mark.asyncio
async def test_resume_is_admin_only_validated_and_audited(api_client, admin_user, viewer_user, insoc):
    url = f"/api/v1/soc/incidents/{IID}/resume"
    assert (await api_client.post(url, json={"approve": ["a1b2c3d4"]}, headers=_h(viewer_user))).status_code == 403
    assert (await api_client.post(url, json={}, headers=_h(admin_user))).status_code == 400
    assert (await api_client.post(url, json={"approve": ["../x"]}, headers=_h(admin_user))).status_code == 400
    assert (await api_client.post(url, json={"approve": ["a1b2c3d4"], "deny": ["a1b2c3d4"]}, headers=_h(admin_user))).status_code == 400

    ok = await api_client.post(url, json={"approve": ["a1b2c3d4"]}, headers=_h(admin_user))
    assert ok.status_code == 200 and ok.json()["echo"] == {"approve": ["a1b2c3d4"], "deny": []}

    async with AsyncSessionLocal() as db:
        entry = (await db.execute(select(AuditLog).where(AuditLog.action == "soc.incident_resumed"))).scalar_one()
    assert entry.target_id == IID and entry.details == {"approve": ["a1b2c3d4"], "deny": []}


@pytest.mark.asyncio
async def test_insoc_errors_map_to_gateway_errors(api_client, admin_user, insoc):
    _, state = insoc
    state["status"] = 401
    assert (await api_client.get("/api/v1/soc/incidents", headers=_h(admin_user))).status_code == 502
    state["status"] = 409
    response = await api_client.post(f"/api/v1/soc/incidents/{IID}/resume", json={"approve": ["a1b2c3d4"]}, headers=_h(admin_user))
    assert response.status_code == 409
