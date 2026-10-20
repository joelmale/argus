"""Security pass: httpOnly session cookie, token revocation, real client address for rate limits."""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.limiter import FailureThrottle
from app.core.security import create_access_token, create_password_reset_token
from app.db.models import User
from app.db.session import AsyncSessionLocal

COOKIE = settings.SESSION_COOKIE_NAME


async def _login(api_client, username="admin", password="changeme"):
    return await api_client.post("/api/v1/auth/token", data={"username": username, "password": password})


# ── session cookie ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_sets_httponly_strict_cookie(api_client, admin_user):
    response = await _login(api_client)
    assert response.status_code == 200
    header = response.headers["set-cookie"].lower()
    assert f"{COOKIE}=" in header and "httponly" in header and "samesite=strict" in header


@pytest.mark.asyncio
async def test_cookie_alone_authenticates_and_logout_clears_it(api_client, admin_user):
    await _login(api_client)
    assert (await api_client.get("/api/v1/auth/me")).status_code == 200  # cookie jar, no header

    assert (await api_client.post("/api/v1/auth/logout")).status_code == 204
    assert (await api_client.get("/api/v1/auth/me")).status_code == 401


@pytest.mark.asyncio
async def test_bad_cookie_is_rejected(api_client, admin_user):
    api_client.cookies.set(COOKIE, "garbage")
    assert (await api_client.get("/api/v1/auth/me")).status_code == 401


# ── revocation ───────────────────────────────────────────────────────────────

async def _me(api_client, token):
    return await api_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})


@pytest.mark.asyncio
async def test_sign_out_everywhere_revokes_old_tokens(api_client, admin_user):
    old = admin_user["token"]
    assert (await _me(api_client, old)).status_code == 200

    revoke = await api_client.post("/api/v1/auth/sessions/revoke", headers={"Authorization": f"Bearer {old}"})
    assert revoke.status_code == 204
    assert (await _me(api_client, old)).status_code == 401

    fresh = (await _login(api_client)).json()["access_token"]
    api_client.cookies.clear()
    assert (await _me(api_client, fresh)).status_code == 200


@pytest.mark.asyncio
async def test_password_reset_revokes_existing_sessions(api_client, admin_user):
    old = admin_user["token"]
    async with AsyncSessionLocal() as db:
        user = await db.get(User, admin_user["id"])
        reset = create_password_reset_token(admin_user["id"], user.hashed_password)

    response = await api_client.post("/api/v1/auth/password/reset", json={"token": reset, "password": "new-password-1"})
    assert response.status_code == 200
    assert (await _me(api_client, old)).status_code == 401


@pytest.mark.asyncio
async def test_deactivating_a_user_revokes_their_tokens(api_client, admin_user, viewer_user):
    admin = {"Authorization": f"Bearer {admin_user['token']}"}
    assert (await api_client.patch(f"/api/v1/auth/users/{viewer_user['id']}", json={"is_active": False}, headers=admin)).status_code == 200
    assert (await api_client.patch(f"/api/v1/auth/users/{viewer_user['id']}", json={"is_active": True}, headers=admin)).status_code == 200
    # Re-enabling doesn't resurrect tokens issued before the deactivation.
    assert (await _me(api_client, viewer_user["token"])).status_code == 401


@pytest.mark.asyncio
async def test_token_with_stale_version_is_rejected(api_client, admin_user):
    async with AsyncSessionLocal() as db:
        user = await db.get(User, admin_user["id"])
        user.token_version = 3
        await db.commit()
    assert (await _me(api_client, create_access_token(admin_user["id"], token_version=2))).status_code == 401
    assert (await _me(api_client, create_access_token(admin_user["id"], token_version=3))).status_code == 200


# ── per-account brute-force throttle ────────────────────────────────────────

def test_failure_throttle_window():
    throttle = FailureThrottle(max_failures=3, window_s=60)
    for second in range(3):
        assert throttle.retry_after("Alice", now=second) == 0
        throttle.record_failure("alice", now=second)
    assert throttle.retry_after("ALICE", now=10) > 0   # keys are case-insensitive
    assert throttle.retry_after("bob", now=10) == 0    # other accounts unaffected
    assert throttle.retry_after("alice", now=61) == 0  # oldest failure aged out


@pytest.mark.asyncio
async def test_login_lockout_is_per_account(api_client, admin_user, viewer_user):
    for _ in range(10):
        assert (await _login(api_client, "admin", "wrong")).status_code == 401
    locked = await _login(api_client, "admin", "changeme")
    assert locked.status_code == 429 and "Retry-After" in locked.headers
    # Everyone else still signs in from the same (proxy) address.
    assert (await _login(api_client, "viewer", "changeme")).status_code == 200


@pytest.mark.asyncio
async def test_successful_login_clears_failures(api_client, admin_user):
    for _ in range(9):
        await _login(api_client, "admin", "wrong")
    assert (await _login(api_client)).status_code == 200
    for _ in range(9):
        await _login(api_client, "admin", "wrong")
    assert (await _login(api_client)).status_code == 200
