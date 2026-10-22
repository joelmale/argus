"""Keep AI calls polite to a shared, local model server.

Three guards wrap every model call (see ``guarded_chat``):

- **Client**: no automatic retries and a bounded timeout. The OpenAI SDK retries twice by
  default, so one timed-out call against a saturated Ollama became three.
- **Circuit breaker** (Redis, shared by every worker process): repeated failures or slow
  calls pause all AI work for a cooldown instead of piling more requests onto the server.
- **Ollama placement guard**: before a call, if Ollama has a *different* model loaded we wait
  for it to unload rather than force a swap. Swapping while the old runner still holds VRAM
  makes Ollama load the new model with 0 layers on the GPU, so every swap pushes inference
  onto the CPU. Swaps are counted, and too many in an hour trip the breaker. After a call we
  check how much of the model sits in VRAM and count a CPU spill as a failure.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
import redis.asyncio as redis
from openai import APIConnectionError, APIStatusError, APITimeoutError, AsyncOpenAI

from app.core.config import settings

log = logging.getLogger(__name__)

KEY_PREFIX = "argus:ai"
BREAKER_KEY = f"{KEY_PREFIX}:breaker"
FAILURES_KEY = f"{KEY_PREFIX}:failures"
SWAPS_KEY = f"{KEY_PREFIX}:swaps"
PLACEMENT_KEY = f"{KEY_PREFIX}:placement"
SWAP_POLL_SECONDS = 5


class AIUnavailable(RuntimeError):
    """Raised instead of calling the model while the breaker is open."""

    def __init__(self, reason: str, retry_after: int):
        super().__init__(f"AI paused: {reason} (retry in {retry_after}s)")
        self.reason = reason
        self.retry_after = retry_after


def make_openai_client(base_url: str, api_key: str) -> AsyncOpenAI:
    return AsyncOpenAI(
        base_url=base_url,
        api_key=api_key,
        max_retries=0,
        timeout=float(max(10, settings.AI_REQUEST_TIMEOUT_SECONDS)),
    )


def _redis() -> redis.Redis:
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


# ── Circuit breaker ───────────────────────────────────────────────────────────

@dataclass
class BreakerState:
    open: bool
    reason: str | None = None
    retry_after: int = 0
    failures: int = 0


class AICircuitBreaker:
    def __init__(self, client: redis.Redis | None = None):
        self._client = client
        self._owns_client = False

    async def _conn(self) -> redis.Redis:
        if self._client is None:
            self._client = _redis()
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def state(self) -> BreakerState:
        conn = await self._conn()
        reason = await conn.get(BREAKER_KEY)
        failures = int(await conn.get(FAILURES_KEY) or 0)
        if reason is None:
            return BreakerState(open=False, failures=failures)
        ttl = await conn.ttl(BREAKER_KEY)
        return BreakerState(open=True, reason=reason, retry_after=max(1, ttl), failures=failures)

    async def ensure_closed(self) -> None:
        state = await self.state()
        if state.open:
            raise AIUnavailable(state.reason or "paused", state.retry_after)

    async def trip(self, reason: str, seconds: int | None = None) -> None:
        conn = await self._conn()
        cooldown = max(1, seconds or settings.AI_BREAKER_COOLDOWN_SECONDS)
        await conn.set(BREAKER_KEY, reason, ex=cooldown)
        await conn.delete(FAILURES_KEY)
        log.warning("AI circuit breaker opened for %ss: %s", cooldown, reason)

    async def record_failure(self, reason: str) -> None:
        conn = await self._conn()
        failures = await conn.incr(FAILURES_KEY)
        await conn.expire(FAILURES_KEY, max(60, settings.AI_BREAKER_COOLDOWN_SECONDS))
        log.warning("AI call degraded (%s/%s): %s", failures, settings.AI_BREAKER_FAILURES, reason)
        if failures >= max(1, settings.AI_BREAKER_FAILURES):
            await self.trip(f"{failures} consecutive problems, last: {reason}")

    async def record_success(self) -> None:
        conn = await self._conn()
        await conn.delete(FAILURES_KEY)

    async def reset(self) -> None:
        conn = await self._conn()
        await conn.delete(BREAKER_KEY, FAILURES_KEY)


# ── Ollama placement guard ────────────────────────────────────────────────────

def ollama_root(base_url: str) -> str:
    root = base_url.rstrip("/")
    return root[: -len("/v1")] if root.endswith("/v1") else root


def normalize_model_name(name: str | None) -> str:
    name = (name or "").strip()
    return name if ":" in name else f"{name}:latest"


async def ollama_loaded_models(base_url: str) -> list[dict[str, Any]] | None:
    """Models Ollama currently holds in memory, or None if Ollama can't be asked."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{ollama_root(base_url)}/api/ps")
            response.raise_for_status()
            return list(response.json().get("models") or [])
    except Exception as exc:  # noqa: BLE001 - placement checks are advisory
        log.debug("Ollama /api/ps unavailable: %s", exc)
        return None


def gpu_fraction(entry: dict[str, Any]) -> float:
    size = float(entry.get("size") or 0)
    return float(entry.get("size_vram") or 0) / size if size > 0 else 0.0


class OllamaGuard:
    def __init__(self, breaker: AICircuitBreaker, *, sleep=asyncio.sleep, clock=time.monotonic):
        self.breaker = breaker
        self._sleep = sleep
        self._clock = clock

    async def before_call(self, base_url: str, model: str) -> None:
        wanted = normalize_model_name(model)
        models = await ollama_loaded_models(base_url)
        if not models:
            return
        others = [m["name"] for m in models if normalize_model_name(m.get("name")) != wanted]
        if not others or any(normalize_model_name(m.get("name")) == wanted for m in models):
            return

        # Another model is resident. Give it time to finish and unload instead of forcing a swap.
        log.info("Ollama has %s loaded; waiting up to %ss before switching to %s",
                 ", ".join(others), settings.AI_MODEL_SWAP_WAIT_SECONDS, wanted)
        deadline = self._clock() + max(0, settings.AI_MODEL_SWAP_WAIT_SECONDS)
        while self._clock() < deadline:
            await self._sleep(SWAP_POLL_SECONDS)
            models = await ollama_loaded_models(base_url) or []
            if not any(normalize_model_name(m.get("name")) != wanted for m in models):
                return

        conn = await self.breaker._conn()
        swaps = await conn.incr(SWAPS_KEY)
        if swaps == 1:
            await conn.expire(SWAPS_KEY, 3600)
        log.warning("Forcing Ollama model swap %s -> %s (%s this hour)", ", ".join(others), wanted, swaps)
        if swaps > max(1, settings.AI_MODEL_SWAP_LIMIT_PER_HOUR):
            await self.breaker.trip(
                f"model thrash: {swaps} Ollama swaps this hour ({', '.join(others)} <-> {wanted}); "
                "use one model for every Argus AI role"
            )
            raise AIUnavailable("model thrash", settings.AI_BREAKER_COOLDOWN_SECONDS)

    async def after_call(self, base_url: str, model: str) -> float | None:
        wanted = normalize_model_name(model)
        models = await ollama_loaded_models(base_url)
        entry = next((m for m in models or [] if normalize_model_name(m.get("name")) == wanted), None)
        if entry is None:
            return None
        fraction = gpu_fraction(entry)
        conn = await self.breaker._conn()
        await conn.hset(PLACEMENT_KEY, mapping={
            "model": wanted,
            "gpu_fraction": f"{fraction:.2f}",
            "size": str(entry.get("size") or 0),
            "size_vram": str(entry.get("size_vram") or 0),
            "checked_at": str(int(time.time())),
        })
        if fraction < settings.AI_MIN_GPU_FRACTION:
            await self.breaker.record_failure(
                f"{wanted} is only {fraction:.0%} on GPU (CPU spill); free VRAM or pick a smaller model"
            )
        return fraction


# ── The guarded call ──────────────────────────────────────────────────────────

async def guarded_chat(
    client: AsyncOpenAI,
    *,
    backend: str,
    base_url: str | None,
    breaker: AICircuitBreaker | None = None,
    guard: OllamaGuard | None = None,
    **request: Any,
):
    owns_breaker = breaker is None
    breaker = breaker or AICircuitBreaker()
    try:
        return await _guarded_chat(client, backend, base_url, breaker, guard, request)
    finally:
        if owns_breaker:
            await breaker.aclose()


async def _guarded_chat(client, backend, base_url, breaker: AICircuitBreaker, guard, request: dict):
    await breaker.ensure_closed()
    is_ollama = backend == "ollama" and base_url
    if is_ollama:
        guard = guard or OllamaGuard(breaker)
        await guard.before_call(base_url, request["model"])

    started = time.monotonic()
    try:
        response = await client.chat.completions.create(**request)
    except (APITimeoutError, APIConnectionError) as exc:
        await breaker.record_failure(f"{type(exc).__name__} after {time.monotonic() - started:.0f}s")
        raise
    except APIStatusError as exc:
        if exc.status_code >= 500 or exc.status_code == 429:
            await breaker.record_failure(f"HTTP {exc.status_code}")
        raise

    elapsed = time.monotonic() - started
    degraded = False
    if elapsed > settings.AI_SLOW_CALL_SECONDS:
        await breaker.record_failure(f"slow call: {elapsed:.0f}s for {request['model']}")
        degraded = True
    if is_ollama:
        fraction = await guard.after_call(base_url, request["model"])
        degraded = degraded or (fraction is not None and fraction < settings.AI_MIN_GPU_FRACTION)
    if not degraded:
        await breaker.record_success()
    return response


async def ai_runtime_status() -> dict[str, Any]:
    breaker = AICircuitBreaker()
    try:
        state = await breaker.state()
        conn = await breaker._conn()
        placement = await conn.hgetall(PLACEMENT_KEY)
        swaps = int(await conn.get(SWAPS_KEY) or 0)
    finally:
        await breaker.aclose()
    return {
        "breaker_open": state.open,
        "breaker_reason": state.reason,
        "retry_after_seconds": state.retry_after if state.open else 0,
        "recent_failures": state.failures,
        "model_swaps_last_hour": swaps,
        "placement": placement or None,
    }
