from __future__ import annotations

import json
from typing import Any

from openai import AsyncOpenAI

from app.core.config import settings

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """You synthesize network fingerprint evidence into cautious hypotheses.
Return JSON only with keys:
- device_type
- vendor
- model
- os_guess
- confidence
- summary
- supporting_evidence

Rules:
- Treat this as hypothesis generation, not fact extraction.
- Prefer "unknown" over overclaiming.
- Use only the supplied evidence.
- confidence must be between 0 and 1.
- supporting_evidence must be a short list of the strongest evidence strings."""


def build_fingerprint_prompt(asset: dict[str, Any], evidence: list[dict[str, Any]], prompt_suffix: str | None = None) -> str:
    lines = [
        f"Asset IP: {asset.get('ip_address')}",
        f"Hostname: {asset.get('hostname') or 'unknown'}",
        f"MAC vendor: {asset.get('vendor') or 'unknown'}",
        f"Detected type: {asset.get('device_type') or 'unknown'}",
        "",
        "Evidence:",
    ]
    for item in evidence[:20]:
        lines.append(
            f"- [{item.get('source')}/{item.get('category')}] {item.get('key')}={item.get('value')} (confidence={item.get('confidence')})"
        )
    if prompt_suffix:
        lines.extend(["", "Operator guidance:", prompt_suffix.strip()])
    return "\n".join(lines)


def parse_fingerprint_response(content: str) -> dict[str, Any]:
    text = content.strip()
    if "```" in text:
        parts = [part.strip() for part in text.split("```") if part.strip()]
        for part in parts:
            if part.startswith("{") or part.startswith("json\n{"):
                text = part.removeprefix("json").strip()
                break
    data = json.loads(text)
    return {
        "device_type": data.get("device_type"),
        "vendor": data.get("vendor"),
        "model": data.get("model"),
        "os_guess": data.get("os_guess"),
        "confidence": float(data.get("confidence", 0.0)),
        "summary": str(data.get("summary", "")).strip(),
        "supporting_evidence": data.get("supporting_evidence") or [],
        "raw_response": content,
    }


async def synthesize_fingerprint(
    *,
    asset: dict[str, Any],
    evidence: list[dict[str, Any]],
    model: str,
    prompt_suffix: str | None,
) -> dict[str, Any]:
    client = AsyncOpenAI(base_url=settings.OLLAMA_BASE_URL, api_key="ollama")
    prompt = build_fingerprint_prompt(asset, evidence, prompt_suffix)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=500,
    )
    content = response.choices[0].message.content or "{}"
    parsed = parse_fingerprint_response(content)
    parsed["model_used"] = model
    parsed["prompt_version"] = PROMPT_VERSION
    return parsed
