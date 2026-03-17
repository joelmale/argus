"""
Ollama AI Analyst Backend

Uses your local Ollama instance (running in a separate container) via its
OpenAI-compatible API. With an RTX A2000, recommended models in order of
capability vs speed:

  qwen2.5:7b      — excellent tool use, fast, ~6GB VRAM
  llama3.1:8b     — solid tool use, good reasoning, ~6GB VRAM
  qwen2.5:14b     — better reasoning, ~10GB VRAM (fits A2000 12GB)
  mistral:7b      — decent, but weaker tool calling than qwen/llama

The ReAct loop (Reason → Act → Observe → Reason) works as follows:
  1. Send system prompt + initial device context to the model
  2. Model responds with either a tool_call or text
  3. If tool_call → execute the probe, append result as tool_response message
  4. If text with no tool_call → model is thinking (append as assistant message)
  5. Repeat until model calls final_analysis or MAX_STEPS reached
  6. Parse final_analysis args into AIAnalysis

This is the same pattern as LangGraph's ReAct agent, but implemented directly
without a framework dependency — easier to debug and customize.
"""
from __future__ import annotations

import json
import logging

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam

from app.core.config import settings
from app.scanner.agent.base import BaseAnalyst, SYSTEM_PROMPT
from app.scanner.agent.tools import TOOL_SCHEMAS, execute
from app.scanner.models import AIAnalysis, HostScanResult
from app.scanner.stages.fingerprint import classify, probe_priority

log = logging.getLogger(__name__)


class OllamaAnalyst(BaseAnalyst):
    """
    Drives a local Ollama model through a ReAct investigation loop.

    The model sees: [system] → [user: initial context] → [assistant: tool_call]
    → [tool: result] → [assistant: tool_call] → ... → [assistant: final_analysis]
    """

    def __init__(self):
        self.client = AsyncOpenAI(
            base_url=settings.OLLAMA_BASE_URL,
            api_key="ollama",   # Ollama doesn't require an API key, but client needs something
        )
        self.model = settings.OLLAMA_MODEL

    async def investigate(self, result: HostScanResult) -> AIAnalysis:
        # Get heuristic hint to prime the agent's context
        hint = classify(result.host, result.ports, result.os_fingerprint)
        priorities = probe_priority(result.host, result.ports, hint)

        initial_context = self._build_context(
            result,
            hint.device_class.value,
            hint.confidence,
            priorities,
        )

        messages: list[ChatCompletionMessageParam] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": initial_context},
        ]

        steps = 0
        final_args: dict | None = None

        log.info("AI investigation started for %s [model: %s]", result.host.ip_address, self.model)

        while steps < self.MAX_STEPS:
            steps += 1
            log.debug("Agent step %d for %s", steps, result.host.ip_address)

            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.1,    # Low temp → consistent, factual responses
                    max_tokens=1024,
                )
            except Exception as exc:
                log.error("Ollama API error on step %d: %s", steps, exc)
                break

            msg = response.choices[0].message

            # Append assistant message to conversation history
            messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": msg.tool_calls or []})

            # No tool calls → model is done or confused; stop
            if not msg.tool_calls:
                log.debug("Agent produced text response (no tool call) on step %d", steps)
                # Try to extract final_analysis from text if present (model quirk)
                if msg.content and "final_analysis" in msg.content.lower():
                    break
                # Ask the model to wrap up
                if steps >= 3:
                    messages.append({
                        "role": "user",
                        "content": "Please call final_analysis now to submit your findings.",
                    })
                continue

            # Process each tool call
            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                log.debug("Agent calling tool: %s(%s)", tool_name, tool_args)

                # Check for termination
                if tool_name == "final_analysis":
                    final_args = tool_args
                    break

                # Execute the probe
                tool_result = await execute(tool_name, tool_args, result.host.ip_address, result.ports)

                # Append tool result to conversation
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result[:4000],  # Truncate to stay within context
                })

            if final_args is not None:
                break

        # Build AIAnalysis from final tool args, or fall back to heuristic result
        if final_args:
            analysis = self._parse_analysis(final_args)
        else:
            log.warning("Agent did not produce final_analysis for %s, using heuristics", result.host.ip_address)
            analysis = AIAnalysis(
                device_class=hint.device_class,
                confidence=hint.confidence * 0.7,  # Reduce confidence for fallback
                investigation_notes=f"AI agent did not complete investigation. Heuristic guess: {hint.reason}",
            )

        analysis.ai_backend = "ollama"
        analysis.model_used = self.model
        analysis.agent_steps = steps

        log.info(
            "AI investigation complete for %s: %s (%.0f%%) in %d steps",
            result.host.ip_address,
            analysis.device_class.value,
            analysis.confidence * 100,
            steps,
        )
        return analysis
