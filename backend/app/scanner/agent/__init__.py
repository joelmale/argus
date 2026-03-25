"""
Agent factory — returns the configured analyst backend.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.config import settings
from app.scanner.config import EffectiveScannerConfig
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

        hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
        return AIAnalysis(
            device_class=hint.device_class,
            confidence=hint.confidence,
            investigation_notes=f"Rule-based classification. Reason: {hint.reason}",
            ai_backend="rule_based",
        )


def get_analyst(config: EffectiveScannerConfig | None = None) -> BaseAnalyst:
    """Return the configured analyst backend."""
    backend = (config.ai_backend if config else settings.AI_BACKEND).lower()
    model = config.ai_model if config else None

    if backend == "anthropic":
        api_key = config.anthropic_api_key if config else settings.ANTHROPIC_API_KEY
        if api_key:
            log.info("AI analyst: Anthropic (%s)", model or settings.ANTHROPIC_MODEL)
            from app.scanner.agent.anthropic_analyst import AnthropicAnalyst
            return AnthropicAnalyst(api_key=api_key, model=model)

    if backend == "openai":
        api_key = config.openai_api_key if config else settings.OPENAI_API_KEY
        if api_key:
            log.info("AI analyst: OpenAI (%s @ %s)", model or settings.OPENAI_MODEL, config.openai_base_url if config else settings.OPENAI_BASE_URL)
            from app.scanner.agent.openai_analyst import OpenAIAnalyst
            return OpenAIAnalyst(
                base_url=config.openai_base_url if config else settings.OPENAI_BASE_URL,
                api_key=api_key,
                model=model or settings.OPENAI_MODEL,
            )

    if backend == "ollama":
        log.info("AI analyst: Ollama (%s @ %s)", model or settings.OLLAMA_MODEL, config.ollama_base_url if config else settings.OLLAMA_BASE_URL)
        from app.scanner.agent.openai_compatible_analyst import OpenAICompatibleAnalyst
        return OpenAICompatibleAnalyst(
            base_url=config.ollama_base_url if config else settings.OLLAMA_BASE_URL,
            api_key="ollama",
            model=model or settings.OLLAMA_MODEL,
            backend_label="ollama",
        )

    log.info("AI analyst: rule-based fallback")
    return RuleBasedFallback()
