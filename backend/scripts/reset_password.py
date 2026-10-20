"""
Break-glass account recovery for Argus.

Runs inside the backend container, so it can only be used by someone who
already has Docker access to the host:

    docker exec -it argus_backend python scripts/reset_password.py --list
    docker exec -it argus_backend python scripts/reset_password.py --username admin
    docker exec -it argus_backend python scripts/reset_password.py --username admin --generate
    docker exec -it argus_backend python scripts/reset_password.py --username admin --make-admin

The password is prompted for (not echoed) unless --generate is used, in which
case a random one is printed once. Resetting also re-activates the account and
writes an audit log entry.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.audit import log_audit_event  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import AsyncSessionLocal, engine  # noqa: E402

from app.core.config import settings  # noqa: E402

MIN_PASSWORD_LENGTH = settings.PASSWORD_MIN_LENGTH


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reset an Argus user's password (break-glass).")
    parser.add_argument("--list", action="store_true", help="List users and exit")
    parser.add_argument("--username", help="Username to reset")
    parser.add_argument("--generate", action="store_true", help="Generate a random password and print it")
    parser.add_argument("--make-admin", action="store_true", help="Also set the user's role to admin")
    return parser.parse_args()


def _read_password() -> str:
    while True:
        password = getpass.getpass("New password: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            continue
        if password != getpass.getpass("Confirm password: "):
            print("Passwords do not match.")
            continue
        return password


async def _list_users() -> None:
    async with AsyncSessionLocal() as db:
        users = (await db.scalars(select(User).order_by(User.created_at))).all()
    if not users:
        print("No users found. Open the web UI to run initial setup.")
        return
    print(f"{'USERNAME':<24}{'ROLE':<10}{'ACTIVE':<8}EMAIL")
    for user in users:
        print(f"{user.username:<24}{user.role:<10}{str(user.is_active):<8}{user.email or ''}")


async def _reset(username: str, generate: bool, make_admin: bool) -> int:
    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if user is None:
            print(f"No user named '{username}'. Use --list to see existing users.")
            return 1

        if generate:
            password = secrets.token_urlsafe(16)
        else:
            password = _read_password()

        user.hashed_password = hash_password(password)
        user.token_version = (user.token_version or 0) + 1  # sign out existing sessions
        user.is_active = True
        if make_admin:
            user.role = "admin"
        await log_audit_event(
            db,
            action="auth.password_reset_cli",
            target_type="user",
            target_id=str(user.id),
            details={"username": user.username, "role": user.role, "made_admin": make_admin},
        )
        await db.commit()

    print(f"Password reset for '{username}' (role: {user.role}, active).")
    if generate:
        print(f"New password: {password}")
    return 0


async def _main() -> int:
    args = _parse_args()
    try:
        if args.list:
            await _list_users()
            return 0
        if not args.username:
            print("Specify --username (or --list).")
            return 2
        return await _reset(args.username.strip(), args.generate, args.make_admin)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
