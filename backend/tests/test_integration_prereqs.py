"""Phase 0 of the Argus × InSOC integration: nmap hardening, service role, webhook auth/events."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db.models import Asset, User
from app.db.session import AsyncSessionLocal, engine
from app.notifications import _send_webhook
from app.scanner.validation import validate_nmap_args


# ── nmap validation ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("args", ["-sV --script vuln", "-sC -T4", "--script=default,safe", "--script http-title -p 80"])
def test_nmap_allows_named_scripts(args):
    validate_nmap_args(args)


@pytest.mark.parametrize(
    "args",
    [
        "--script /tmp/evil.nse",
        "--script=../evil",
        "--script ./x",
        "--script C:\\x.nse",
        "--script ~/x",
        "--excludefile /etc/hosts",
        "--resume /tmp/scan.log",
        "--stylesheet /tmp/x.xsl",
    ],
)
def test_nmap_blocks_file_access(args):
    with pytest.raises(ValueError):
        validate_nmap_args(args)


# ── service role ─────────────────────────────────────────────────────────────

@pytest.fixture
async def service_token():
    async with engine.begin() as conn:
        result = await conn.execute(
            User.__table__.insert().values(
                username="insoc",
                hashed_password=hash_password("service-pass"),
                role="service",
                is_active=True,
            ).returning(User.__table__.c.id)
        )
        user_id = result.scalar_one()
    return create_access_token(str(user_id))


@pytest.mark.asyncio
async def test_service_role_can_ingest_and_read_but_not_admin(api_client, service_token, monkeypatch):
    sent: list[dict] = []

    async def fake_notify(db, data):
        sent.append(data)

    monkeypatch.setattr("app.api.routes.findings.notify_new_findings_if_enabled", fake_notify)
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        db.add(Asset(ip_address="192.168.77.5", status="online", first_seen=now, last_seen=now))
        await db.commit()

    headers = {"Authorization": f"Bearer {service_token}"}
    payload = {"source_tool": "insoc", "findings": [{"ip_address": "192.168.77.5", "title": "SSH brute force", "severity": "high"}]}

    ingest = await api_client.post("/api/v1/findings/ingest", json=payload, headers=headers)
    assert ingest.status_code == 200
    assert ingest.json()["created"] == 1
    assert sent and sent[0]["findings"][0]["title"] == "SSH brute force"

    again = await api_client.post("/api/v1/findings/ingest", json=payload, headers=headers)
    assert again.json()["updated"] == 1
    assert len(sent) == 1  # updates don't re-alert

    assert (await api_client.get("/api/v1/findings/", headers=headers)).status_code == 200
    assert (await api_client.get("/api/v1/auth/users", headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_ingest(api_client, viewer_user):
    response = await api_client.post(
        "/api/v1/findings/ingest",
        json={"findings": []},
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
    )
    assert response.status_code == 403


# ── webhook ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_webhook_sends_bearer_token_and_envelope(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = request.read()
        return httpx.Response(200)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "app.notifications.httpx.AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(settings, "NOTIFY_WEBHOOK_URL", "http://insoc.test/hooks/argus")
    monkeypatch.setattr(settings, "NOTIFY_WEBHOOK_TOKEN", "s3cret")

    await _send_webhook({"event": "ports_changed", "data": {"ip": "10.0.0.1"}})

    assert captured["auth"] == "Bearer s3cret"
    assert b'"source":"argus"' in captured["body"].replace(b" ", b"")


@pytest.mark.asyncio
async def test_webhook_failure_is_swallowed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "app.notifications.httpx.AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(settings, "NOTIFY_WEBHOOK_URL", "http://insoc.test/hooks/argus")

    await _send_webhook({"event": "new_device", "data": {}})  # must not raise
