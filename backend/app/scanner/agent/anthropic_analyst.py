"""
Anthropic API Analyst Backend (optional fallback)

Uses the Anthropic SDK's native tool use. Slightly different from the OpenAI
format but the same ReAct loop logic. Claude is particularly good at synthesizing
ambiguous multi-signal evidence into coherent narratives.

Set ANTHROPIC_API_KEY in .env to enable. If not set, the pipeline falls back
to OllamaAnalyst automatically.

Model recommendation: claude-haiku-4-5 for cost efficiency on bulk scans;
claude-sonnet-4-6 for high-confidence critical asset investigation.
"""
from __future__ import annotations
import logging

import anthropic

from app.core.config import settings
from app.scanner.agent.base import BaseAnalyst, SYSTEM_PROMPT
from app.scanner.agent.tools import TOOL_SCHEMAS, execute
from app.scanner.models import AIAnalysis, HostScanResult
from app.scanner.stages.fingerprint import classify, probe_priority

log = logging.getLogger(__name__)

# Convert OpenAI-format tool schemas to Anthropic format
def _to_anthropic_tools(schemas: list[dict]) -> list[dict]:
    tools = []
    for schema in schemas:
        fn = schema.get("function", {})
        tools.append({
            "name": fn["name"],
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return tools


ANTHROPIC_TOOLS = _to_anthropic_tools(TOOL_SCHEMAS)


class AnthropicAnalyst(BaseAnalyst):
    """Investigation agent using Anthropic Claude API."""

    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.model = settings.ANTHROPIC_MODEL

    async def investigate(self, result: HostScanResult) -> AIAnalysis:
        hint, initial_context = self._build_investigation_seed(result)

        messages = [{"role": "user", "content": initial_context}]
        steps = 0
        final_args: dict | None = None

        log.info("Anthropic investigation started for %s [model: %s]", result.host.ip_address, self.model)

        while steps < self.MAX_STEPS:
            steps += 1

            try:
                response = self.client.messages.stream(
                    model=self.model,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    messages=messages,
                    tools=ANTHROPIC_TOOLS,
                )
                async with response as stream:
                    msg = await stream.get_final_message()
            except Exception as exc:
                log.error("Anthropic API error on step %d: %s", steps, exc)
                break

            # Append assistant response
            messages.append({"role": "assistant", "content": msg.content})

            tool_calls = [b for b in msg.content if b.type == "tool_use"]
            if not tool_calls:
                self._request_final_analysis(messages, steps)
                if msg.stop_reason == "end_turn":
                    break
                continue

            final_args, tool_results = await self._handle_tool_calls(tool_calls, result.host.ip_address)

            if final_args:
                break

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        analysis = self._parse_analysis(final_args) if final_args else self._fallback_analysis(hint)

        analysis.ai_backend = "anthropic"
        analysis.model_used = self.model
        analysis.agent_steps = steps
        return analysis

    def _build_investigation_seed(self, result: HostScanResult):
        hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
        priorities = probe_priority(result.ports, hint)
        initial_context = self._build_context(result, hint.device_class.value, hint.confidence, priorities)
        return hint, initial_context

    def _request_final_analysis(self, messages: list[dict], steps: int) -> None:
        if steps >= 3:
            messages.append({"role": "user", "content": "Please call final_analysis now."})

    async def _handle_tool_calls(self, tool_calls, ip_address: str) -> tuple[dict | None, list[dict]]:
        tool_results = []
        for tool_call in tool_calls:
            tool_name = tool_call.name
            tool_args = tool_call.input if isinstance(tool_call.input, dict) else {}

            if tool_name == "final_analysis":
                return tool_args, tool_results

            tool_result = await execute(tool_name, tool_args, ip_address)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": tool_result[:4000],
            })
        return None, tool_results

    def _fallback_analysis(self, hint) -> AIAnalysis:
        return AIAnalysis(
            device_class=hint.device_class,
            confidence=hint.confidence * 0.7,
            investigation_notes=f"Anthropic agent did not complete. Heuristic: {hint.reason}",
        )
