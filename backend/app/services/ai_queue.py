"""The AI investigation queue.

Scans no longer wait on the model. They push assets into a Redis sorted set (score = priority,
see ``app.scanner.ai_gate``), and the ``run_ai_queue`` Celery task on the dedicated ``ai`` queue
works through it one asset at a time:

- highest priority first (on-demand > new > changed > stale; less certain hosts first);
- one investigation in flight across all workers (Redis lock);
- spaced by AI_QUEUE_MIN_INTERVAL_SECONDS and capped at AI_QUEUE_MAX_PER_HOUR;
- paused while the circuit breaker is open — the asset goes back on the queue.

The investigation reuses evidence already stored for the asset (ports, latest probe runs),
so the queue never re-scans the network.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.models import Asset
from app.scanner.ai_gate import ai_input_signature
from app.scanner.ai_runtime import AIUnavailable
from app.scanner.models import DiscoveredHost, HostScanResult, OSFingerprint, PortResult, ProbeResult

log = logging.getLogger(__name__)

QUEUE_KEY = "argus:ai:pending"
LOCK_KEY = "argus:ai:drain_lock"
HOURLY_KEY = "argus:ai:hourly"
SIGNATURES_KEY = "argus:ai:signatures"  # asset id -> evidence signature seen by the scan that queued it
LOCK_SECONDS = 15 * 60


def _redis() -> redis.Redis:
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


async def enqueue(priorities: dict[str, float], conn: redis.Redis | None = None) -> int:
    """Add asset ids with priorities. A re-queued asset keeps the higher of its two priorities."""
    if not priorities:
        return 0
    own = conn is None
    conn = conn or _redis()
    try:
        # GT adds new members and only ever raises an existing member's score.
        await conn.zadd(QUEUE_KEY, {str(k): float(v) for k, v in priorities.items()}, gt=True)
        return int(await conn.zcard(QUEUE_KEY))
    finally:
        if own:
            await conn.aclose()


async def queue_position(asset_id: str, conn: redis.Redis | None = None) -> int | None:
    own = conn is None
    conn = conn or _redis()
    try:
        rank = await conn.zrevrank(QUEUE_KEY, str(asset_id))
        return None if rank is None else int(rank) + 1
    finally:
        if own:
            await conn.aclose()


async def queue_depth(conn: redis.Redis | None = None) -> int:
    own = conn is None
    conn = conn or _redis()
    try:
        return int(await conn.zcard(QUEUE_KEY))
    finally:
        if own:
            await conn.aclose()


async def enqueue_scan_candidates(db: AsyncSession, candidates: dict[str, tuple[float, str]]) -> int:
    """Map scanned IPs to asset ids and queue them. Returns the queue depth.

    The scan's evidence signature is kept alongside, so the stored analysis matches what the
    next scan computes (stored evidence lacks some scan-only fields, such as nmap product names).
    """
    if not candidates:
        return 0
    rows = (await db.execute(select(Asset.id, Asset.ip_address).where(Asset.ip_address.in_(list(candidates))))).all()
    priorities = {str(asset_id): candidates[ip][0] for asset_id, ip in rows}
    signatures = {str(asset_id): candidates[ip][1] for asset_id, ip in rows}
    conn = _redis()
    try:
        if signatures:
            await conn.hset(SIGNATURES_KEY, mapping=signatures)
        depth = await enqueue(priorities, conn)
    finally:
        await conn.aclose()
    log.info("Queued %d host(s) for AI investigation (queue depth %d)", len(priorities), depth)
    return depth


def kick(countdown: int = 0) -> None:
    """Ask the AI worker to look at the queue."""
    from app.workers.tasks import run_ai_queue

    run_ai_queue.apply_async(countdown=max(0, int(countdown)))


# ── Rebuilding a scan result from stored evidence ─────────────────────────────

def _latest_probe_runs(probe_runs) -> list:
    latest: dict[tuple[str, int | None], object] = {}
    for run in sorted(probe_runs, key=lambda r: r.observed_at or datetime.min.replace(tzinfo=timezone.utc)):
        latest[(run.probe_type, run.target_port)] = run
    return list(latest.values())


async def load_scan_result(db: AsyncSession, asset_id: uuid.UUID) -> tuple[Asset, HostScanResult] | None:
    asset = (await db.execute(
        select(Asset)
        .where(Asset.id == asset_id)
        .options(selectinload(Asset.ports), selectinload(Asset.probe_runs))
    )).scalar_one_or_none()
    if asset is None:
        return None
    result = HostScanResult(
        host=DiscoveredHost(
            ip_address=asset.ip_address,
            mac_address=asset.mac_address,
            discovery_method="stored",
            nmap_hostname=asset.hostname,
        ),
        ports=[
            PortResult(port=p.port_number, protocol=p.protocol, state=p.state, service=p.service, version=p.version)
            for p in asset.ports
            if p.state == "open"
        ],
        os_fingerprint=OSFingerprint(os_name=asset.os_name, os_version=asset.os_version),
        probes=[
            ProbeResult(
                probe_type=run.probe_type,
                target_port=run.target_port,
                success=run.success,
                duration_ms=run.duration_ms,
                data=run.details or {},
                raw=run.raw_excerpt,
            )
            for run in _latest_probe_runs(asset.probe_runs)
        ],
        mac_vendor=asset.vendor,
        reverse_hostname=asset.hostname,
    )
    return asset, result


# ── One drain step ────────────────────────────────────────────────────────────

@dataclass
class DrainOutcome:
    status: str                 # investigated | empty | busy | paused | rate_limited | missing | requeued
    asset_id: str | None = None
    next_run_in: int | None = None  # seconds until the queue should be looked at again


async def drain_one(db: AsyncSession, *, analyst_factory=None, conn: redis.Redis | None = None) -> DrainOutcome:
    """Investigate the highest-priority queued asset, if the guards allow it."""
    from app.scanner.ai_runtime import AICircuitBreaker
    from app.db.upsert import apply_deferred_ai_analysis

    own = conn is None
    conn = conn or _redis()
    token = uuid.uuid4().hex
    try:
        if not await conn.set(LOCK_KEY, token, nx=True, ex=LOCK_SECONDS):
            return DrainOutcome("busy")
        try:
            breaker = AICircuitBreaker(conn)
            state = await breaker.state()
            if state.open:
                return DrainOutcome("paused", next_run_in=state.retry_after)

            used = int(await conn.get(HOURLY_KEY) or 0)
            if used >= max(1, settings.AI_QUEUE_MAX_PER_HOUR):
                return DrainOutcome("rate_limited", next_run_in=max(60, await conn.ttl(HOURLY_KEY)))

            popped = await conn.zpopmax(QUEUE_KEY)
            if not popped:
                return DrainOutcome("empty")
            asset_id, score = popped[0]

            loaded = await load_scan_result(db, uuid.UUID(asset_id))
            if loaded is None:
                await conn.hdel(SIGNATURES_KEY, asset_id)
                return DrainOutcome("missing", asset_id, next_run_in=0)
            asset, result = loaded

            if analyst_factory is None:
                from app.scanner.agent import get_analyst
                from app.scanner.config import read_effective_scanner_config

                _, runtime_config = await read_effective_scanner_config(db)
                analyst = get_analyst(runtime_config)
            else:
                analyst = analyst_factory()

            hourly = await conn.incr(HOURLY_KEY)
            if hourly == 1:
                await conn.expire(HOURLY_KEY, 3600)

            started = time.monotonic()
            try:
                result.ai_analysis = await analyst.investigate(result)
            except AIUnavailable as exc:
                await conn.zadd(QUEUE_KEY, {asset_id: score}, gt=True)
                return DrainOutcome("requeued", asset_id, next_run_in=exc.retry_after)

            result.ai_input_signature = await conn.hget(SIGNATURES_KEY, asset_id) or ai_input_signature(result)
            await conn.hdel(SIGNATURES_KEY, asset_id)
            await apply_deferred_ai_analysis(db, asset, result)
            await db.commit()
            log.info("AI investigation done for %s (%s, %.0f%%) in %.0fs; %d left in queue",
                     asset.ip_address, result.ai_analysis.device_class.value,
                     result.ai_analysis.confidence * 100, time.monotonic() - started,
                     await conn.zcard(QUEUE_KEY))
            return DrainOutcome("investigated", asset_id, next_run_in=settings.AI_QUEUE_MIN_INTERVAL_SECONDS)
        finally:
            if await conn.get(LOCK_KEY) == token:
                await conn.delete(LOCK_KEY)
    finally:
        if own:
            await conn.aclose()
