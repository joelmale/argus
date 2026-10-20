import pytest

from app.core.config import settings
from app.core.security import (
    create_password_reset_token,
    decode_password_reset_token,
    hash_password,
    password_reset_token_matches,
    verify_password,
)

FORGOT = "/api/v1/auth/password/forgot"
RESET = "/api/v1/auth/password/reset"


@pytest.fixture
def smtp(monkeypatch):
    sent = []

    async def fake_send(recipient, subject, body):
        sent.append((recipient, subject, body))

    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "argus@test")
    monkeypatch.setattr(settings, "APP_BASE_URL", "http://argus.test")
    monkeypatch.setattr("app.api.routes.auth.send_email_to", fake_send)
    return sent


def test_reset_token_round_trip_and_single_use():
    hashed = hash_password("old-password")
    token = create_password_reset_token("user-1", hashed)

    user_id, fingerprint = decode_password_reset_token(token)
    assert user_id == "user-1"
    assert password_reset_token_matches(hashed, fingerprint) is True
    assert password_reset_token_matches(hash_password("new-password"), fingerprint) is False
    assert decode_password_reset_token(f"{token}x") is None


def test_access_token_is_not_a_reset_token():
    from app.core.security import create_access_token

    assert decode_password_reset_token(create_access_token("user-1")) is None


@pytest.mark.asyncio
async def test_forgot_password_sends_link_by_username_or_email(api_client, admin_user, smtp):
    for identifier in ("admin", "ADMIN@example.com"):
        response = await api_client.post(FORGOT, json={"identifier": identifier})
        assert response.status_code == 202

    assert len(smtp) == 2
    recipient, _, body = smtp[0]
    assert recipient == "admin@example.com"
    assert "http://argus.test/reset-password?token=" in body


@pytest.mark.asyncio
async def test_forgot_password_does_not_reveal_unknown_accounts(api_client, admin_user, smtp):
    known = await api_client.post(FORGOT, json={"identifier": "admin"})
    unknown = await api_client.post(FORGOT, json={"identifier": "nobody"})

    assert known.json() == unknown.json()
    assert len(smtp) == 1


@pytest.mark.asyncio
async def test_reset_password_flow_is_single_use(api_client, admin_user, smtp):
    await api_client.post(FORGOT, json={"identifier": "admin"})
    token = smtp[0][2].split("token=")[1].split()[0]

    bad = await api_client.post(RESET, json={"token": token, "password": "x"})
    assert bad.status_code == 400

    ok = await api_client.post(RESET, json={"token": token, "password": "brand-new-pass"})
    assert ok.status_code == 200

    login = await api_client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "brand-new-pass"}
    )
    assert login.status_code == 200

    reuse = await api_client.post(RESET, json={"token": token, "password": "another-pass-1"})
    assert reuse.status_code == 400


@pytest.mark.asyncio
async def test_reset_rejects_garbage_token(api_client):
    response = await api_client.post(RESET, json={"token": "nope", "password": "whatever-long"})
    assert response.status_code == 400


def test_verify_helper_sanity():
    assert verify_password("a", hash_password("a"))


def test_reset_token_is_not_a_login_token():
    from app.core.security import decode_token

    assert decode_token(create_password_reset_token("user-1", hash_password("pw"))) is None


@pytest.mark.asyncio
async def test_reset_token_cannot_authenticate_api_requests(api_client, admin_user):
    from app.db.models import User
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        user = await db.get(User, admin_user["id"])
        token = create_password_reset_token(admin_user["id"], user.hashed_password)

    response = await api_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
