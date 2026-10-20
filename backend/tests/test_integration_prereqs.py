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


# ── admin-created API keys for other users ───────────────────────────────────

@pytest.fixture
async def service_user_id():
    async with engine.begin() as conn:
        result = await conn.execute(
            User.__table__.insert().values(
                username="insoc",
                hashed_password=hash_password("service-pass"),
                role="service",
                is_active=True,
            ).returning(User.__table__.c.id)
        )
        return str(result.scalar_one())


@pytest.mark.asyncio
async def test_admin_creates_key_for_service_user(api_client, admin_user, service_user_id):
    admin_headers = {"Authorization": f"Bearer {admin_user['token']}"}
    created = await api_client.post(
        "/api/v1/auth/api-keys", json={"name": "insoc", "user_id": service_user_id}, headers=admin_headers
    )
    assert created.status_code == 201
    body = created.json()
    assert body["user_id"] == service_user_id
    assert body["owner_username"] == "insoc"

    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        db.add(Asset(ip_address="192.168.77.9", status="online", first_seen=now, last_seen=now))
        await db.commit()

    key_headers = {"X-API-Key": body["token"]}
    ingest = await api_client.post(
        "/api/v1/findings/ingest",
        json={"source_tool": "insoc", "findings": [{"ip_address": "192.168.77.9", "title": "t", "severity": "low"}]},
        headers=key_headers,
    )
    assert ingest.status_code == 200
    assert (await api_client.get("/api/v1/findings/", headers=key_headers)).status_code == 200
    assert (await api_client.get("/api/v1/auth/users", headers=key_headers)).status_code == 403
    assert (await api_client.get("/api/v1/auth/api-keys", headers=key_headers)).status_code == 403

    listed = await api_client.get("/api/v1/auth/api-keys", headers=admin_headers)
    assert [k["owner_username"] for k in listed.json()] == ["insoc"]
    filtered = await api_client.get(f"/api/v1/auth/api-keys?user_id={admin_user['id']}", headers=admin_headers)
    assert filtered.json() == []

    deleted = await api_client.delete(f"/api/v1/auth/api-keys/{body['id']}", headers=admin_headers)
    assert deleted.status_code == 204
    assert (await api_client.get("/api/v1/findings/", headers=key_headers)).status_code == 401

    logs = await api_client.get("/api/v1/auth/audit-logs", headers=admin_headers)
    assert logs.status_code == 200
    created_log = next(e for e in logs.json() if e["action"] == "auth.api_key_created")
    assert created_log["details"]["owner_username"] == "insoc"


@pytest.mark.asyncio
async def test_api_key_defaults_to_caller_and_rejects_unknown_owner(api_client, admin_user):
    headers = {"Authorization": f"Bearer {admin_user['token']}"}
    own = await api_client.post("/api/v1/auth/api-keys", json={"name": "mine"}, headers=headers)
    assert own.json()["user_id"] == admin_user["id"]
    missing = await api_client.post(
        "/api/v1/auth/api-keys",
        json={"name": "x", "user_id": "00000000-0000-0000-0000-000000000000"},
        headers=headers,
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_non_admin_cannot_create_key_for_others(api_client, viewer_user, service_user_id):
    response = await api_client.post(
        "/api/v1/auth/api-keys",
        json={"name": "x", "user_id": service_user_id},
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
    )
    assert response.status_code == 403
