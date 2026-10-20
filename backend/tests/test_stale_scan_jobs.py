"""Orphaned/stale scan jobs must not block the scan queue forever."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.db.models import ScanJob
from app.db.session import AsyncSessionLocal
from app.workers import tasks as worker_tasks


def _ago(minutes: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


async def _add(db, **kwargs) -> ScanJob:
    job = ScanJob(targets=kwargs.pop("targets", "192.168.50.0/24"), **kwargs)
    db.add(job)
    await db.flush()
    return job


async def _status(job_id) -> str:
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(ScanJob.status).where(ScanJob.id == job_id))).scalar_one()


@pytest.mark.asyncio
async def test_interrupt_all_running_jobs_and_cancel_their_pending_chunks():
    async with AsyncSessionLocal() as db:
        parent = await _add(db, status="running", triggered_by="schedule", started_at=_ago(5))
        chunk_running = await _add(db, parent_id=parent.id, status="running", chunk_index=1, started_at=_ago(5))
        chunk_pending = await _add(db, parent_id=parent.id, status="pending", chunk_index=2)
        paused = await _add(db, status="paused", started_at=_ago(5))
        queued = await _add(db, status="pending", triggered_by="manual")
        await db.commit()

        ids = await worker_tasks._interrupt_orphaned_jobs(db, reason="restart")
        await db.commit()

    assert set(ids) == {str(parent.id), str(chunk_running.id)}
    assert await _status(parent.id) == "failed"
    assert await _status(chunk_running.id) == "failed"
    assert await _status(chunk_pending.id) == "cancelled"
    assert await _status(paused.id) == "paused"      # paused scans are resumed by their own task
    assert await _status(queued.id) == "pending"     # unrelated queued scans stay queued

    async with AsyncSessionLocal() as db:
        summary = (await db.execute(select(ScanJob.result_summary).where(ScanJob.id == parent.id))).scalar_one()
    assert summary["stage"] == "interrupted" and summary["error"] == "restart"


@pytest.mark.asyncio
async def test_stale_guard_spares_jobs_with_recent_progress():
    cutoff = _ago(180)
    async with AsyncSessionLocal() as db:
        stale = await _add(db, status="running", started_at=_ago(400), result_summary={"last_progress_at": _ago(300).isoformat()})
        busy = await _add(db, status="running", started_at=_ago(400), result_summary={"last_progress_at": _ago(2).isoformat()})
        # Parent with no progress of its own, but a child chunk that is still working.
        parent = await _add(db, status="running", started_at=_ago(400))
        await _add(db, parent_id=parent.id, status="running", started_at=_ago(1), chunk_index=1)
        await db.commit()

        ids = await worker_tasks._interrupt_orphaned_jobs(db, reason="stale", stale_before=cutoff)
        await db.commit()

    assert ids == [str(stale.id)]
    assert await _status(busy.id) == "running"
    assert await _status(parent.id) == "running"


@pytest.mark.asyncio
async def test_progress_updates_record_a_heartbeat():
    class _Db:
        async def commit(self):
            return None

    job = ScanJob(targets="10.0.0.0/24", result_summary={})
    await worker_tasks._record_job_progress(
        _Db(), job, {"event": "scan_progress", "data": {"stage": "discovery"}}, {"last_flush": 0.0, "last_stage": None}
    )
    assert worker_tasks._job_last_activity(job) >= _ago(1)


@pytest.mark.asyncio
async def test_startup_interrupts_orphans_and_starts_next_queued_scan(monkeypatch):
    started: list[str] = []
    monkeypatch.setattr(worker_tasks.run_scan_job, "delay", lambda job_id: started.append(job_id))
    monkeypatch.setattr(settings, "SCAN_INTERRUPT_ORPHANS_ON_STARTUP", True)

    async with AsyncSessionLocal() as db:
        orphan = await _add(db, status="running", triggered_by="schedule", started_at=_ago(1))
        queued = await _add(db, status="pending", triggered_by="manual", queue_position=1)
        await db.commit()

    await worker_tasks._resume_pending_queue_on_startup()

    assert await _status(orphan.id) == "failed"
    assert started == [str(queued.id)]


@pytest.mark.asyncio
async def test_startup_can_be_told_not_to_interrupt(monkeypatch):
    started: list[str] = []
    monkeypatch.setattr(worker_tasks.run_scan_job, "delay", lambda job_id: started.append(job_id))
    monkeypatch.setattr(settings, "SCAN_INTERRUPT_ORPHANS_ON_STARTUP", False)

    async with AsyncSessionLocal() as db:
        running = await _add(db, status="running", started_at=_ago(1))
        await _add(db, status="pending", queue_position=1)
        await db.commit()

    await worker_tasks._resume_pending_queue_on_startup()

    assert await _status(running.id) == "running"
    assert started == []
