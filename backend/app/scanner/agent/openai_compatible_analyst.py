from __future__ import annotations

import json
import logging

from openai.types.chat import ChatCompletionMessageParam

from app.core.config import settings
from app.scanner.agent.base import SINGLE_SHOT_PROMPT, SYSTEM_PROMPT, BaseAnalyst, summarize_probes
from app.scanner.ai_runtime import AIUnavailable, guarded_chat, make_openai_client
from app.scanner.agent.tools import TOOL_SCHEMAS, execute
from app.scanner.models import AIAnalysis, HostScanResult
from app.scanner.stages.fingerprint import classify, probe_priority

log = logging.getLogger(__name__)


class OpenAICompatibleAnalyst(BaseAnalyst):
    def __init__(self, *, base_url: str, api_key: str, model: str, backend_label: str):
        self.client = make_openai_client(base_url, api_key)
        self.base_url = base_url
        self.model = model
        self.backend_label = backend_label

    @property
    def single_shot(self) -> bool:
        return self.backend_label == "ollama" and settings.AI_LOCAL_MODE.strip().lower() != "agent"

    async def _chat(self, **request):
        return await guarded_chat(self.client, backend=self.backend_label, base_url=self.base_url, model=self.model, **request)

    async def investigate(self, result: HostScanResult) -> AIAnalysis:
        if self.single_shot:
            return await self._investigate_single_shot(result)
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
                response = await self._chat(
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.1,
                    max_tokens=1024,
                )
            except AIUnavailable:
                raise
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

    async def _investigate_single_shot(self, result: HostScanResult) -> AIAnalysis:
        """One JSON call over the evidence the scan already gathered: no tool loop, no extra probes."""
        hint, initial_context = self._build_investigation_seed(result)
        prompt = "\n".join([initial_context, "", "### Deep probe results", summarize_probes(result.probes)])
        log.info("%s single-shot investigation for %s [model: %s]", self.backend_label, result.host.ip_address, self.model)
        args: dict | None = None
        try:
            response = await self._chat(
                messages=[
                    {"role": "system", "content": SINGLE_SHOT_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=700,
            )
            args = self._parse_tool_args(response.choices[0].message.content or "")
        except AIUnavailable:
            raise
        except Exception as exc:
            log.error("%s single-shot call failed for %s: %s", self.backend_label, result.host.ip_address, exc)

        analysis = self._parse_analysis(args) if args else self._fallback_analysis(hint)
        analysis.ai_backend = self.backend_label
        analysis.model_used = self.model
        analysis.agent_steps = 1
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
