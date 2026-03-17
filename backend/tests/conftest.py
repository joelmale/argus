import asyncio

import pytest
import pytest_asyncio

from app.db.session import engine


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
