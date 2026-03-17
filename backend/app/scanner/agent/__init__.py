"""
Agent factory — returns the appropriate analyst based on available config.

Priority: Anthropic API (if key set) → Ollama (if reachable) → rule-based fallback.
Override with AI_BACKEND env var: "ollama" | "anthropic" | "none"
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.config import settings
from app.scanner.agent.base import BaseAnalyst

if TYPE_CHECKING:
    from app.scanner.models import AIAnalysis

log = logging.getLogger(__name__)


class RuleBasedFallback(BaseAnalyst):
    """
    Pure heuristic analyst — no LLM required.
    Used when neither Ollama nor Anthropic is configured.
    Produces reasonable classifications from port/OS fingerprint alone.
    """

    async def investigate(self, result) -> "AIAnalysis":
        from app.scanner.models import AIAnalysis
        from app.scanner.stages.fingerprint import classify

        hint = classify(result.host, result.ports, result.os_fingerprint)
        return AIAnalysis(
            device_class=hint.device_class,
            confidence=hint.confidence,
            investigation_notes=f"Rule-based classification. Reason: {hint.reason}",
            ai_backend="rule_based",
        )


def get_analyst() -> BaseAnalyst:
    """Return the best available analyst backend."""
    backend = settings.AI_BACKEND.lower()

    if backend == "anthropic" and settings.ANTHROPIC_API_KEY:
        log.info("AI analyst: Anthropic API (%s)", settings.ANTHROPIC_MODEL)
        from app.scanner.agent.anthropic_analyst import AnthropicAnalyst
        return AnthropicAnalyst()

    if backend in ("ollama", "auto"):
        log.info("AI analyst: Ollama (%s @ %s)", settings.OLLAMA_MODEL, settings.OLLAMA_BASE_URL)
        from app.scanner.agent.ollama_analyst import OllamaAnalyst
        return OllamaAnalyst()

    log.info("AI analyst: rule-based fallback (set AI_BACKEND=ollama or AI_BACKEND=anthropic)")
    return RuleBasedFallback()
