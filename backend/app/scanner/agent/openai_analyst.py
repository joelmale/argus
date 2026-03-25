from __future__ import annotations

from app.core.config import settings
from app.scanner.agent.openai_compatible_analyst import OpenAICompatibleAnalyst


class OpenAIAnalyst(OpenAICompatibleAnalyst):
    def __init__(self, *, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        super().__init__(
            base_url=base_url or settings.OPENAI_BASE_URL,
            api_key=api_key or settings.OPENAI_API_KEY,
            model=model or settings.OPENAI_MODEL,
            backend_label="openai",
        )
