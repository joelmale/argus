import asyncio
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

os.environ.setdefault("APP_ENV", "test")
_database_url_test = os.environ.get("DATABASE_URL_TEST")
if _database_url_test:
    # Keep pytest off the runtime database by preferring a dedicated test DSN.
    os.environ["DATABASE_URL"] = _database_url_test
    os.environ["DATABASE_URL_DOCKER"] = _database_url_test

from app.core.security import create_access_token, hash_password
from app.db.models import Base, User
from app.db.session import engine
from app.main import app


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(autouse=True)
async def reset_async_engine():
    await engine.dispose()
    yield
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    # Keep every test hermetic so route-level coverage can safely exercise the
    # real app and persistence layer without leaking state into the next test.
    table_names = ", ".join(table.name for table in reversed(Base.metadata.sorted_tables))
    await engine.dispose()
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE"))
    yield
    await engine.dispose()
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def api_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture
async def admin_user():
    async with engine.begin() as conn:
        result = await conn.execute(
            User.__table__.insert().values(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password("changeme"),
                role="admin",
                is_active=True,
            ).returning(User.__table__.c.id)
        )
        user_id = result.scalar_one()
    return {
        "id": str(user_id),
        "username": "admin",
        "password": "changeme",
        "token": create_access_token(str(user_id)),
    }


@pytest_asyncio.fixture
async def viewer_user():
    async with engine.begin() as conn:
        result = await conn.execute(
            User.__table__.insert().values(
                username="viewer",
                email="viewer@example.com",
                hashed_password=hash_password("changeme"),
                role="viewer",
                is_active=True,
            ).returning(User.__table__.c.id)
        )
        user_id = result.scalar_one()
    return {
        "id": str(user_id),
        "username": "viewer",
        "password": "changeme",
        "token": create_access_token(str(user_id)),
    }
