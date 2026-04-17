from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.db.models import ScanJob

SCAN_QUEUE_LOCK_KEY = "argus:scan_queue_lock"
SCAN_QUEUE_LOCK_FALLBACK_KEY = 6_178_231_911_204_913
SCAN_QUEUE_LOCK_TTL_SECONDS = 60
SCAN_QUEUE_LOCK_WAIT_SECONDS = 30
_scan_queue_lock_client: redis.Redis | None = None
_scan_queue_lock_client_loop_id: int | None = None
_scan_queue_lock_engine = None


def _get_scan_queue_lock_client() -> redis.Redis:
    global _scan_queue_lock_client, _scan_queue_lock_client_loop_id
    try:
        loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        loop_id = None
    if _scan_queue_lock_client is None or loop_id != _scan_queue_lock_client_loop_id:
        _scan_queue_lock_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        _scan_queue_lock_client_loop_id = loop_id
    return _scan_queue_lock_client


def _get_scan_queue_lock_engine():
    global _scan_queue_lock_engine
    if _scan_queue_lock_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        _scan_queue_lock_engine = create_async_engine(
            settings.DATABASE_URL.get_secret_value(),
            echo=False,
            poolclass=NullPool,
        )
    return _scan_queue_lock_engine


async def dispose_scan_queue_lock() -> None:
    global _scan_queue_lock_client
    if _scan_queue_lock_client is not None:
        await _scan_queue_lock_client.aclose()
    _scan_queue_lock_client = None

    global _scan_queue_lock_engine
    if _scan_queue_lock_engine is not None:
        await _scan_queue_lock_engine.dispose()
    _scan_queue_lock_engine = None


async def dispose_scan_queue_lock_engine() -> None:
    await dispose_scan_queue_lock()


@asynccontextmanager
async def acquire_scan_queue_lock(db: AsyncSession) -> AsyncIterator[None]:
    bind = getattr(db, "bind", None)
    if bind is None:
        await db.execute(select(func.pg_advisory_xact_lock(SCAN_QUEUE_LOCK_FALLBACK_KEY)))
        yield
        return

    try:
        token = await _acquire_redis_scan_queue_lock()
    except RedisError:
        async with _acquire_postgres_scan_queue_lock():
            yield
        return

    try:
        yield
    finally:
        await _release_redis_scan_queue_lock(token)


async def _acquire_redis_scan_queue_lock() -> str:
    client = _get_scan_queue_lock_client()
    token = uuid4().hex
    deadline = asyncio.get_running_loop().time() + SCAN_QUEUE_LOCK_WAIT_SECONDS

    while True:
        if await client.set(SCAN_QUEUE_LOCK_KEY, token, nx=True, ex=SCAN_QUEUE_LOCK_TTL_SECONDS):
            return token
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("Timed out waiting for scan queue lock")
        await asyncio.sleep(0.05)


async def _release_redis_scan_queue_lock(token: str) -> None:
    client = _get_scan_queue_lock_client()
    try:
        await client.eval(
            """
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            end
            return 0
            """,
            1,
            SCAN_QUEUE_LOCK_KEY,
            token,
        )
    except RedisError:
        pass


@asynccontextmanager
async def _acquire_postgres_scan_queue_lock() -> AsyncIterator[None]:
    async with _get_scan_queue_lock_engine().connect() as conn:
        await conn.execute(select(func.pg_advisory_lock(SCAN_QUEUE_LOCK_FALLBACK_KEY)))
        try:
            yield
        finally:
            await conn.execute(select(func.pg_advisory_unlock(SCAN_QUEUE_LOCK_FALLBACK_KEY)))


async def has_active_scan(db: AsyncSession) -> bool:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status.in_(("running", "paused")))
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def next_queue_position(db: AsyncSession) -> int:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    jobs = list(result.scalars().all())
    if not jobs:
        return 1
    max_position = max((job.queue_position or index + 1) for index, job in enumerate(jobs))
    return max_position + 1


async def normalize_pending_queue(db: AsyncSession) -> None:
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc().nullslast(), ScanJob.created_at.asc())
    )
    jobs = list(result.scalars().all())
    for index, job in enumerate(jobs, start=1):
        job.queue_position = index


async def get_next_queued_job(db: AsyncSession) -> ScanJob | None:
    await normalize_pending_queue(db)
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.parent_id.is_(None), ScanJob.status == "pending")
        .order_by(ScanJob.queue_position.asc(), ScanJob.created_at.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def enqueue_scan_job(
    db: AsyncSession,
    *,
    targets: str,
    scan_type: str,
    triggered_by: str,
    result_summary: dict | None = None,
) -> tuple[ScanJob, bool]:
    async with acquire_scan_queue_lock(db):
        job = ScanJob(
            targets=targets,
            scan_type=scan_type,
            triggered_by=triggered_by,
            queue_position=await next_queue_position(db),
            result_summary=result_summary,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)

        should_start = not await has_active_scan(db) and job.queue_position == 1
        return job, should_start
