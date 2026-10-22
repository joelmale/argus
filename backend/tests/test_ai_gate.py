"""AI investigation gating: skip hosts with no evidence or unchanged evidence, and cap concurrency."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Asset, AssetAIAnalysis
from app.db.session import AsyncSessionLocal
from app.db.upsert import _upsert_ai_analysis
from app.scanner import pipeline as pipeline_mod
from app.scanner.ai_gate import SKIP_NO_EVIDENCE, SKIP_UNCHANGED, AIGate, ai_input_signature, has_ai_evidence
from app.scanner.models import AIAnalysis, DiscoveredHost, HostScanResult, PortResult, ProbeResult


def _result(ip="192.168.1.50", ports=(), probes=(), vendor="Acme", hostname="nas"):
    return HostScanResult(
        host=DiscoveredHost(ip_address=ip, mac_address="AA:BB:CC:DD:EE:FF"),
        ports=[PortResult(port=p, service="http" if p == 80 else None) for p in ports],
        probes=list(probes),
        mac_vendor=vendor,
        reverse_hostname=hostname,
    )


class _Analyst:
    def __init__(self, delay=0.0):
        self.calls = 0
        self.active = 0
        self.peak = 0
        self.delay = delay

    async def investigate(self, result):
        self.calls += 1
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(self.delay)
        self.active -= 1
        return AIAnalysis(confidence=0.9, ai_backend="ollama")


async def _noop_broadcast(payload):
    return None


# ── evidence and signature ───────────────────────────────────────────────────

def test_evidence_requires_open_port_or_successful_probe():
    assert not has_ai_evidence(_result())
    assert not has_ai_evidence(_result(probes=[ProbeResult(probe_type="http", target_port=80, success=False)]))
    assert has_ai_evidence(_result(ports=[22]))
    assert has_ai_evidence(_result(probes=[ProbeResult(probe_type="upnp", target_port=1400, success=True)]))


def test_signature_tracks_evidence_not_probe_payloads():
    base = ai_input_signature(_result(ports=[22, 80]))
    assert base == ai_input_signature(_result(ports=[80, 22]))                     # order-independent
    assert base != ai_input_signature(_result(ports=[22, 80, 443]))                 # new port
    assert base != ai_input_signature(_result(ports=[22, 80], vendor="Other"))      # identity change
    a = _result(ports=[80], probes=[ProbeResult(probe_type="http", target_port=80, success=True, data={"t": 1})])
    b = _result(ports=[80], probes=[ProbeResult(probe_type="http", target_port=80, success=True, data={"t": 2})])
    assert ai_input_signature(a) == ai_input_signature(b)                           # volatile payload ignored


def test_gate_skips_unchanged_until_stale():
    result = _result(ports=[22])
    sig = ai_input_signature(result)
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    gate = AIGate(prior={"192.168.1.50": (sig, now - timedelta(days=2))}, reinvestigate_after=timedelta(days=7))
    assert gate.skip_reason(result, sig, now) == SKIP_UNCHANGED
    assert gate.skip_reason(result, "different", now) is None
    assert gate.skip_reason(result, sig, now + timedelta(days=6)) is None
    assert gate.skip_reason(_result(), ai_input_signature(_result()), now) == SKIP_NO_EVIDENCE
    assert AIGate(skip_no_evidence=False).skip_reason(_result(), "x", now) is None


# ── pipeline integration ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_skips_and_records_signature():
    analyst = _Analyst()
    gate = AIGate()

    empty = _result()
    await pipeline_mod._run_ai_investigation(analyst, empty, _noop_broadcast, "job", empty.host.ip_address, ai_gate=gate)
    assert analyst.calls == 0 and empty.ai_analysis is None

    busy = _result(ports=[80])
    await pipeline_mod._run_ai_investigation(analyst, busy, _noop_broadcast, "job", busy.host.ip_address, ai_gate=gate)
    assert analyst.calls == 1 and busy.ai_analysis is not None
    assert busy.ai_input_signature == ai_input_signature(busy)

    gate.prior[busy.host.ip_address] = (busy.ai_input_signature, datetime.now(timezone.utc))
    again = _result(ports=[80])
    await pipeline_mod._run_ai_investigation(analyst, again, _noop_broadcast, "job", again.host.ip_address, ai_gate=gate)
    assert analyst.calls == 1 and again.ai_analysis is None


@pytest.mark.asyncio
async def test_ai_concurrency_is_capped():
    analyst = _Analyst(delay=0.02)
    gate = AIGate(max_concurrent=1)
    results = [_result(ip=f"10.0.0.{i}", ports=[22]) for i in range(5)]
    await asyncio.gather(*[
        pipeline_mod._run_ai_investigation(analyst, r, _noop_broadcast, "job", r.host.ip_address, ai_gate=gate)
        for r in results
    ])
    assert analyst.calls == 5 and analyst.peak == 1


@pytest.mark.asyncio
async def test_without_gate_behaviour_is_unchanged():
    analyst = _Analyst()
    empty = _result()
    await pipeline_mod._run_ai_investigation(analyst, empty, _noop_broadcast, "job", empty.host.ip_address)
    assert analyst.calls == 1


@pytest.mark.asyncio
async def test_signature_persists_and_loads_as_prior():
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        asset = Asset(ip_address="192.168.1.60", status="online", first_seen=now, last_seen=now)
        db.add(asset)
        await db.flush()
        result = _result(ip="192.168.1.60", ports=[22])
        result.ai_analysis = AIAnalysis(confidence=0.8, ai_backend="ollama")
        result.ai_input_signature = ai_input_signature(result)
        await _upsert_ai_analysis(db, asset, result)
        await db.commit()

        stored = await db.get(AssetAIAnalysis, (await db.execute(
            AssetAIAnalysis.__table__.select().where(AssetAIAnalysis.asset_id == asset.id)
        )).first().id)
        assert stored.input_signature == result.ai_input_signature

        gate = await pipeline_mod._build_ai_gate(db)
    assert gate.prior["192.168.1.60"][0] == result.ai_input_signature
    assert gate.max_concurrent == 1


def test_analyst_step_cap_defaults_low():
    from app.scanner.agent.base import BaseAnalyst

    assert BaseAnalyst.MAX_STEPS == 5
