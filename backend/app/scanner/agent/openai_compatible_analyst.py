from __future__ import annotations

import json
import logging

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam

from app.scanner.agent.base import BaseAnalyst, SYSTEM_PROMPT
from app.scanner.agent.tools import TOOL_SCHEMAS, execute
from app.scanner.models import AIAnalysis, HostScanResult
from app.scanner.stages.fingerprint import classify, probe_priority

log = logging.getLogger(__name__)


class OpenAICompatibleAnalyst(BaseAnalyst):
    def __init__(self, *, base_url: str, api_key: str, model: str, backend_label: str):
        self.client = AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self.model = model
        self.backend_label = backend_label

    async def investigate(self, result: HostScanResult) -> AIAnalysis:
        hint, initial_context = self._build_investigation_seed(result)

        messages: list[ChatCompletionMessageParam] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": initial_context},
        ]

        steps = 0
        final_args: dict | None = None

        log.info("%s investigation started for %s [model: %s]", self.backend_label, result.host.ip_address, self.model)

        while steps < self.MAX_STEPS:
            steps += 1

            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.1,
                    max_tokens=1024,
                )
            except Exception as exc:
                log.error("%s API error on step %d: %s", self.backend_label, steps, exc)
                break

            msg = response.choices[0].message
            messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": msg.tool_calls or []})

            if not msg.tool_calls:
                if msg.content and "final_analysis" in msg.content.lower():
                    break
                self._request_final_analysis(messages, steps)
                continue

            final_args = await self._handle_tool_calls(messages, msg.tool_calls, result.host.ip_address)
            if final_args is not None:
                break

        analysis = self._parse_analysis(final_args) if final_args else self._fallback_analysis(hint)
        analysis.ai_backend = self.backend_label
        analysis.model_used = self.model
        analysis.agent_steps = steps
        return analysis

    def _build_investigation_seed(self, result: HostScanResult):
        hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
        priorities = probe_priority(result.ports, hint)
        initial_context = self._build_context(
            result,
            hint.device_class.value,
            hint.confidence,
            priorities,
        )
        return hint, initial_context

    def _request_final_analysis(self, messages: list[ChatCompletionMessageParam], steps: int) -> None:
        if steps >= 3:
            messages.append({
                "role": "user",
                "content": "Please call final_analysis now to submit your findings.",
            })

    async def _handle_tool_calls(self, messages: list[ChatCompletionMessageParam], tool_calls, ip_address: str) -> dict | None:
        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            tool_args = self._parse_tool_args(tool_call.function.arguments)

            if tool_name == "final_analysis":
                return tool_args

            tool_result = await execute(tool_name, tool_args, ip_address)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": tool_result[:4000],
            })
        return None

    def _parse_tool_args(self, raw_arguments: str) -> dict:
        try:
            return json.loads(raw_arguments)
        except json.JSONDecodeError:
            return {}

    def _fallback_analysis(self, hint) -> AIAnalysis:
        return AIAnalysis(
            device_class=hint.device_class,
            confidence=hint.confidence * 0.7,
            investigation_notes=f"{self.backend_label} agent did not complete investigation. Heuristic guess: {hint.reason}",
        )
