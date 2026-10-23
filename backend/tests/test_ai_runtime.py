"""AI runtime guards: bounded client, circuit breaker, Ollama swap/CPU-spill detection,
single local model, single-shot mode, the deferred AI queue and on-demand investigation."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis
from openai import APITimeoutError

from app.core.config import settings
from app.db.models import Asset, AssetAIAnalysis, Port, ProbeRun, ScannerConfig
from app.db.session import AsyncSessionLocal
from app.scanner import ai_runtime
from app.scanner import pipeline as pipeline_mod
from app.scanner.agent.openai_compatible_analyst import OpenAICompatibleAnalyst
from app.scanner.ai_gate import PRIORITY_CHANGED, PRIORITY_NEW, PRIORITY_ON_DEMAND, PRIORITY_STALE, AIGate, ai_input_signature
from app.scanner.ai_runtime import AICircuitBreaker, AIUnavailable, OllamaGuard, guarded_chat, make_openai_client
from app.scanner.config import resolve_fingerprint_model
from app.scanner.models import AIAnalysis, DiscoveredHost, HostScanResult, PortResult, ProbeResult
from app.services import ai_queue

OLLAMA = "http://ollama.test:11434/v1"


@pytest_asyncio.fixture
async def conn():
    client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    keys = [k async for k in client.scan_iter("argus:ai:*")]
    if keys:
        await client.delete(*keys)
    yield client
    keys = [k async for k in client.scan_iter("argus:ai:*")]
    if keys:
        await client.delete(*keys)
    await client.aclose()


@pytest.fixture(autouse=True)
def no_celery(monkeypatch):
    kicks = []
    monkeypatch.setattr(ai_queue, "kick", lambda countdown=0: kicks.append(countdown))
    return kicks


def _result(ip="192.168.1.50", ports=(22,), probes=()):
    return HostScanResult(
        host=DiscoveredHost(ip_address=ip, mac_address="AA:BB:CC:DD:EE:FF"),
        ports=[PortResult(port=p, service="ssh" if p == 22 else "http") for p in ports],
        probes=list(probes),
        mac_vendor="Acme",
    )


def _completion(content: str):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=None))])


class _FakeClient:
    def __init__(self, *responses, delay_error=None):
        self.requests = []
        self._responses = list(responses)
        self._error = delay_error
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **request):
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._responses.pop(0)


def _ps(*models):
    return [{"name": name, "size": size, "size_vram": vram} for name, size, vram in models]


# ── Client and breaker ────────────────────────────────────────────────────────

def test_local_client_never_retries():
    client = make_openai_client(OLLAMA, "ollama")
    assert client.max_retries == 0
    assert client.timeout == float(settings.AI_REQUEST_TIMEOUT_SECONDS)


@pytest.mark.asyncio
async def test_breaker_opens_after_repeated_failures_and_resets(conn):
    breaker = AICircuitBreaker(conn)
    for _ in range(settings.AI_BREAKER_FAILURES - 1):
        await breaker.record_failure("timeout")
    await breaker.ensure_closed()
    await breaker.record_failure("timeout")
    with pytest.raises(AIUnavailable):
        await breaker.ensure_closed()
    state = await breaker.state()
    assert state.open and state.retry_after > 0

    await breaker.reset()
    await breaker.ensure_closed()


@pytest.mark.asyncio
async def test_success_clears_failure_count(conn):
    breaker = AICircuitBreaker(conn)
    await breaker.record_failure("timeout")
    await breaker.record_success()
    assert (await breaker.state()).failures == 0


@pytest.mark.asyncio
async def test_guarded_chat_counts_timeouts_and_refuses_when_open(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(None))
    breaker = AICircuitBreaker(conn)
    error = APITimeoutError(request=httpx.Request("POST", OLLAMA))
    client = _FakeClient(delay_error=error)
    for _ in range(settings.AI_BREAKER_FAILURES):
        with pytest.raises(APITimeoutError):
            await guarded_chat(client, backend="ollama", base_url=OLLAMA, breaker=breaker, model="m", messages=[])
    with pytest.raises(AIUnavailable):
        await guarded_chat(client, backend="ollama", base_url=OLLAMA, breaker=breaker, model="m", messages=[])
    assert len(client.requests) == settings.AI_BREAKER_FAILURES  # nothing sent while open


@pytest.mark.asyncio
async def test_slow_call_counts_as_failure(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(None))
    monkeypatch.setattr(settings, "AI_SLOW_CALL_SECONDS", -1)
    breaker = AICircuitBreaker(conn)
    await guarded_chat(_FakeClient(_completion("{}")), backend="ollama", base_url=OLLAMA, breaker=breaker, model="m", messages=[])
    assert (await breaker.state()).failures == 1


# ── Ollama placement guard ────────────────────────────────────────────────────

def _async_return(value):
    async def _fn(*args, **kwargs):
        return value
    return _fn


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds


@pytest.mark.asyncio
async def test_guard_waits_for_other_model_to_unload_without_counting_a_swap(conn, monkeypatch):
    answers = iter([_ps(("gemma3:4b", 3, 3)), _ps(("gemma3:4b", 3, 3)), []])
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", lambda base: _async_return(next(answers))())
    clock = _Clock()
    await OllamaGuard(AICircuitBreaker(conn), sleep=clock.sleep, clock=clock).before_call(OLLAMA, "qwen2.5:7b")
    assert clock.now == 2 * ai_runtime.SWAP_POLL_SECONDS
    assert await conn.get(ai_runtime.SWAPS_KEY) is None


@pytest.mark.asyncio
async def test_guard_ignores_requests_for_the_loaded_model(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(_ps(("llama3.2:latest", 2, 2))))
    clock = _Clock()
    await OllamaGuard(AICircuitBreaker(conn), sleep=clock.sleep, clock=clock).before_call(OLLAMA, "llama3.2")
    assert clock.now == 0


@pytest.mark.asyncio
async def test_repeated_forced_swaps_trip_the_breaker(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(_ps(("gemma3:4b", 3, 3))))
    monkeypatch.setattr(settings, "AI_MODEL_SWAP_LIMIT_PER_HOUR", 2)
    breaker = AICircuitBreaker(conn)
    clock = _Clock()
    guard = OllamaGuard(breaker, sleep=clock.sleep, clock=clock)
    await guard.before_call(OLLAMA, "qwen2.5:7b")
    await guard.before_call(OLLAMA, "qwen2.5:7b")
    with pytest.raises(AIUnavailable):
        await guard.before_call(OLLAMA, "qwen2.5:7b")
    state = await breaker.state()
    assert state.open and "model thrash" in state.reason


@pytest.mark.asyncio
async def test_cpu_spill_is_recorded_and_counted(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(_ps(("qwen2.5:7b", 100, 4))))
    breaker = AICircuitBreaker(conn)
    fraction = await OllamaGuard(breaker).after_call(OLLAMA, "qwen2.5:7b")
    assert fraction == pytest.approx(0.04)
    assert (await breaker.state()).failures == 1
    placement = await conn.hgetall(ai_runtime.PLACEMENT_KEY)
    assert placement["model"] == "qwen2.5:7b" and placement["gpu_fraction"] == "0.04"


@pytest.mark.asyncio
async def test_model_fully_on_gpu_is_healthy(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(_ps(("qwen2.5:7b", 100, 100))))
    breaker = AICircuitBreaker(conn)
    await guarded_chat(_FakeClient(_completion("{}")), backend="ollama", base_url=OLLAMA, breaker=breaker, model="qwen2.5:7b", messages=[])
    assert (await breaker.state()).failures == 0


# ── One local model ───────────────────────────────────────────────────────────

def test_fingerprint_reuses_investigation_model_on_ollama(monkeypatch):
    config = ScannerConfig(ai_backend="ollama", ai_model="llama3.2:latest", fingerprint_ai_backend="ollama", fingerprint_ai_model="gemma3:4b")
    assert resolve_fingerprint_model(config) == "llama3.2:latest"

    monkeypatch.setattr(settings, "AI_SINGLE_LOCAL_MODEL", False)
    assert resolve_fingerprint_model(config) == "gemma3:4b"


def test_fingerprint_keeps_its_model_on_hosted_backends():
    config = ScannerConfig(ai_backend="ollama", ai_model="llama3.2:latest", fingerprint_ai_backend="anthropic", fingerprint_ai_model="claude-x")
    assert resolve_fingerprint_model(config) == "claude-x"


# ── Single-shot local investigation ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_shot_makes_one_json_call_without_tools(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(None))
    analyst = OpenAICompatibleAnalyst(base_url=OLLAMA, api_key="ollama", model="llama3.2", backend_label="ollama")
    analyst.client = _FakeClient(_completion(json.dumps({
        "device_class": "nas", "confidence": 0.85, "vendor": "Synology", "investigation_notes": "DSM login page",
    })))
    result = _result(ports=(80, 22), probes=[ProbeResult(probe_type="http", target_port=80, success=True, data={"title": "Synology DiskStation"})])

    analysis = await analyst.investigate(result)

    assert len(analyst.client.requests) == 1
    request = analyst.client.requests[0]
    assert "tools" not in request and request["response_format"] == {"type": "json_object"}
    assert "Synology DiskStation" in request["messages"][1]["content"]
    assert analysis.device_class.value == "nas" and analysis.vendor == "Synology"
    assert analysis.agent_steps == 1 and analysis.ai_backend == "ollama"


@pytest.mark.asyncio
async def test_single_shot_falls_back_on_bad_json(conn, monkeypatch):
    monkeypatch.setattr(ai_runtime, "ollama_loaded_models", _async_return(None))
    analyst = OpenAICompatibleAnalyst(base_url=OLLAMA, api_key="ollama", model="llama3.2", backend_label="ollama")
    analyst.client = _FakeClient(_completion("not json"))
    analysis = await analyst.investigate(_result())
    assert "did not complete" in analysis.investigation_notes


@pytest.mark.asyncio
async def test_single_shot_propagates_breaker(conn, monkeypatch):
    await AICircuitBreaker(conn).trip("test", 60)
    analyst = OpenAICompatibleAnalyst(base_url=OLLAMA, api_key="ollama", model="llama3.2", backend_label="ollama")
    analyst.client = _FakeClient()
    with pytest.raises(AIUnavailable):
        await analyst.investigate(_result())


# ── Deferred queue ────────────────────────────────────────────────────────────

class _Analyst:
    def __init__(self, error=None):
        self.calls = 0
        self.error = error

    async def investigate(self, result):
        self.calls += 1
        if self.error:
            raise self.error
        return AIAnalysis(device_class="router", confidence=0.9, vendor="Acme", ai_backend="ollama")


async def _noop(payload):
    return None


@pytest.mark.asyncio
async def test_pipeline_defers_instead_of_investigating():
    analyst = _Analyst()
    gate = AIGate(deferred=True)
    result = _result()
    await pipeline_mod._run_ai_investigation(analyst, result, _noop, "job", result.host.ip_address, ai_gate=gate)
    assert analyst.calls == 0 and result.ai_analysis is None
    priority, signature = gate.candidates[result.host.ip_address]
    assert PRIORITY_NEW <= priority <= PRIORITY_NEW + 50
    assert signature == ai_input_signature(result)


def test_priority_orders_new_changed_stale():
    result = _result()
    signature = ai_input_signature(result)
    now = datetime.now(timezone.utc)
    assert AIGate().priority(result, signature) >= PRIORITY_NEW
    changed = AIGate(prior={"192.168.1.50": ("old", now)}).priority(result, signature)
    stale = AIGate(prior={"192.168.1.50": (signature, now - timedelta(days=30))}).priority(result, signature)
    assert PRIORITY_CHANGED <= changed < PRIORITY_NEW
    assert PRIORITY_STALE <= stale < PRIORITY_CHANGED


@pytest.mark.asyncio
async def test_queue_pops_highest_priority_and_only_raises_scores(conn):
    await ai_queue.enqueue({"a": 100, "b": 300, "c": 200}, conn)
    await ai_queue.enqueue({"a": 50}, conn)               # never lowered
    await ai_queue.enqueue({"c": PRIORITY_ON_DEMAND}, conn)  # on-demand jumps the queue
    assert await ai_queue.queue_position("c", conn) == 1
    assert [m for m, _ in await conn.zrevrange(ai_queue.QUEUE_KEY, 0, -1, withscores=True)] == ["c", "b", "a"]


async def _make_asset(ip="192.168.1.60"):
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        asset = Asset(ip_address=ip, mac_address="AA:BB:CC:DD:EE:01", vendor="Acme", status="online", first_seen=now, last_seen=now)
        db.add(asset)
        await db.flush()
        db.add(Port(asset_id=asset.id, port_number=80, protocol="tcp", service="http", state="open"))
        db.add(ProbeRun(asset_id=asset.id, probe_type="http", target_port=80, success=True, details={"title": "Router admin"}))
        await db.commit()
        return asset.id


@pytest.mark.asyncio
async def test_drain_investigates_from_stored_evidence_and_keeps_scan_signature(conn):
    asset_id = await _make_asset()
    async with AsyncSessionLocal() as db:
        await ai_queue.enqueue_scan_candidates(db, {"192.168.1.60": (PRIORITY_NEW, "scan-signature")})

    seen = []

    class _Seeing(_Analyst):
        async def investigate(self, result):
            seen.append(result)
            return await super().investigate(result)

    async with AsyncSessionLocal() as db:
        outcome = await ai_queue.drain_one(db, analyst_factory=_Seeing, conn=conn)
    assert outcome.status == "investigated" and outcome.next_run_in == settings.AI_QUEUE_MIN_INTERVAL_SECONDS
    assert [p.port for p in seen[0].ports] == [80]
    assert seen[0].probes[0].data == {"title": "Router admin"}

    async with AsyncSessionLocal() as db:
        stored = (await db.execute(AssetAIAnalysis.__table__.select().where(AssetAIAnalysis.asset_id == asset_id))).first()
        asset = await db.get(Asset, asset_id)
    assert stored.input_signature == "scan-signature"
    assert stored.device_class == "router"
    assert asset.device_type == "router"
    assert await conn.zcard(ai_queue.QUEUE_KEY) == 0


@pytest.mark.asyncio
async def test_drain_pauses_while_breaker_is_open(conn):
    await _make_asset()
    await AICircuitBreaker(conn).trip("test", 120)
    async with AsyncSessionLocal() as db:
        await ai_queue.enqueue_scan_candidates(db, {"192.168.1.60": (PRIORITY_NEW, "sig")})
        analyst = _Analyst()
        outcome = await ai_queue.drain_one(db, analyst_factory=lambda: analyst, conn=conn)
    assert outcome.status == "paused" and 0 < outcome.next_run_in <= 120
    assert analyst.calls == 0 and await conn.zcard(ai_queue.QUEUE_KEY) == 1


@pytest.mark.asyncio
async def test_drain_requeues_when_ai_becomes_unavailable(conn):
    await _make_asset()
    async with AsyncSessionLocal() as db:
        await ai_queue.enqueue_scan_candidates(db, {"192.168.1.60": (PRIORITY_NEW, "sig")})
        outcome = await ai_queue.drain_one(db, analyst_factory=lambda: _Analyst(AIUnavailable("model thrash", 300)), conn=conn)
    assert outcome.status == "requeued" and outcome.next_run_in == 300
    assert await conn.zcard(ai_queue.QUEUE_KEY) == 1


@pytest.mark.asyncio
async def test_drain_respects_the_hourly_cap_and_the_lock(conn, monkeypatch):
    await _make_asset()
    async with AsyncSessionLocal() as db:
        await ai_queue.enqueue_scan_candidates(db, {"192.168.1.60": (PRIORITY_NEW, "sig")})
        await conn.set(ai_queue.LOCK_KEY, "someone-else", ex=60)
        assert (await ai_queue.drain_one(db, analyst_factory=_Analyst, conn=conn)).status == "busy"
        await conn.delete(ai_queue.LOCK_KEY)

        monkeypatch.setattr(settings, "AI_QUEUE_MAX_PER_HOUR", 1)
        await conn.set(ai_queue.HOURLY_KEY, 1, ex=600)
        outcome = await ai_queue.drain_one(db, analyst_factory=_Analyst, conn=conn)
    assert outcome.status == "rate_limited" and outcome.next_run_in >= 60
    assert await conn.zcard(ai_queue.QUEUE_KEY) == 1


@pytest.mark.asyncio
async def test_scan_queues_hosts_after_persisting(conn, monkeypatch):
    await _make_asset()
    gate = AIGate(deferred=True, candidates={"192.168.1.60": (PRIORITY_NEW, "sig"), "10.9.9.9": (PRIORITY_NEW, "x")})
    async with AsyncSessionLocal() as db:
        await pipeline_mod._queue_deferred_ai(db, gate)
    assert await conn.zcard(ai_queue.QUEUE_KEY) == 1  # unknown IPs are dropped


# ── API ───────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_investigate_endpoint_puts_asset_first(conn, api_client, admin_user, no_celery):
    asset_id = await _make_asset()
    await ai_queue.enqueue({"other": PRIORITY_NEW}, conn)
    headers = {"Authorization": f"Bearer {admin_user['token']}"}

    response = await api_client.post(f"/api/v1/assets/{asset_id}/ai-analysis/investigate", headers=headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "queued" and body["queue_position"] == 1 and body["queue_depth"] == 2
    assert no_celery == [0]

    status = await api_client.get("/api/v1/system/ai/status", headers=headers)
    assert status.status_code == 200 and status.json()["queue_depth"] == 2


@pytest.mark.asyncio
async def test_investigate_endpoint_requires_admin(conn, api_client, viewer_user):
    asset_id = await _make_asset()
    response = await api_client.post(
        f"/api/v1/assets/{asset_id}/ai-analysis/investigate",
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_breaker_reset_endpoint(conn, api_client, admin_user):
    await AICircuitBreaker(conn).trip("test", 600)
    response = await api_client.post("/api/v1/system/ai/breaker/reset", headers={"Authorization": f"Bearer {admin_user['token']}"})
    assert response.status_code == 200
    assert not (await AICircuitBreaker(conn).state()).open


def test_ai_worker_skips_scanner_startup_hooks(monkeypatch):
    from app.workers import tasks

    started = []
    monkeypatch.setattr(tasks.threading, "Thread", lambda target, daemon: SimpleNamespace(start=lambda: started.append(target), is_alive=lambda: True))
    monkeypatch.setattr(tasks, "_passive_arp_thread", None)
    monkeypatch.setattr(tasks, "_queue_resume_thread", None)
    monkeypatch.setattr(settings, "SCANNER_PASSIVE_ARP", True)

    monkeypatch.setattr(settings, "WORKER_ROLE", "ai")
    tasks._start_passive_arp_listener()
    tasks._resume_scan_queue_on_worker_ready()
    assert started == []

    monkeypatch.setattr(settings, "WORKER_ROLE", "scanner")
    tasks._start_passive_arp_listener()
    tasks._resume_scan_queue_on_worker_ready()
    assert len(started) == 2


def test_final_analysis_tolerates_loose_json_types():
    from app.scanner.agent.base import _parse_final_analysis

    analysis = _parse_final_analysis({
        "device_class": "Router",
        "confidence": "85%",
        "vendor": "null",
        "investigation_notes": ["Login page says EdgeRouter.", "SSH banner matches."],
        "open_services_summary": "ssh, https",
        "security_findings": ["Self-signed certificate", {"severity": "MEDIUM", "title": "Telnet", "detail": 23}],
        "suggested_tags": None,
    })
    assert analysis.device_class.value == "router"
    assert analysis.confidence == pytest.approx(0.85)
    assert analysis.vendor is None
    assert analysis.investigation_notes == "Login page says EdgeRouter. SSH banner matches."
    assert analysis.open_services_summary == ["ssh", "https"]
    assert [f.title for f in analysis.security_findings] == ["Self-signed certificate", "Telnet"]
    assert analysis.security_findings[1].severity == "medium" and analysis.security_findings[1].detail == "23"


@pytest.mark.asyncio
async def test_drain_survives_an_analyst_crash(conn):
    await _make_asset()
    async with AsyncSessionLocal() as db:
        await ai_queue.enqueue_scan_candidates(db, {"192.168.1.60": (PRIORITY_NEW, "sig")})
        outcome = await ai_queue.drain_one(db, analyst_factory=lambda: _Analyst(ValueError("bad model output")), conn=conn)
    assert outcome.status == "failed" and outcome.next_run_in == settings.AI_QUEUE_MIN_INTERVAL_SECONDS
    assert await conn.get(ai_queue.LOCK_KEY) is None


@pytest.mark.asyncio
async def test_only_one_followup_is_scheduled_at_a_time(conn, monkeypatch):
    from app.workers import tasks

    scheduled = []
    monkeypatch.setattr(tasks, "_run_ai_queue_async", _async_return(ai_queue.DrainOutcome("paused", next_run_in=300)))
    monkeypatch.setattr(tasks.run_ai_queue, "apply_async", lambda countdown: scheduled.append(countdown))
    for _ in range(5):   # e.g. beat kicks landing while the breaker is open
        await asyncio.to_thread(tasks.run_ai_queue)
    assert scheduled == [300]
    assert 0 < await conn.ttl(ai_queue.FOLLOWUP_KEY) <= 300
