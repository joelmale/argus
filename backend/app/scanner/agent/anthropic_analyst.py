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
        hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
        priorities = probe_priority(result.host, result.ports, hint)
        initial_context = self._build_context(result, hint.device_class.value, hint.confidence, priorities)

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
                if steps >= 3:
                    messages.append({"role": "user", "content": "Please call final_analysis now."})
                if msg.stop_reason == "end_turn":
                    break
                continue

            tool_results = []
            for tc in tool_calls:
                tool_name = tc.name
                tool_args = tc.input if isinstance(tc.input, dict) else {}

                if tool_name == "final_analysis":
                    final_args = tool_args
                    break

                tool_result = await execute(tool_name, tool_args, result.host.ip_address, result.ports)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": tool_result[:4000],
                })

            if final_args:
                break

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        if final_args:
            analysis = self._parse_analysis(final_args)
        else:
            analysis = AIAnalysis(
                device_class=hint.device_class,
                confidence=hint.confidence * 0.7,
                investigation_notes=f"Anthropic agent did not complete. Heuristic: {hint.reason}",
            )

        analysis.ai_backend = "anthropic"
        analysis.model_used = self.model
        analysis.agent_steps = steps
        return analysis
