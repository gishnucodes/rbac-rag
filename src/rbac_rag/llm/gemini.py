from __future__ import annotations

from rbac_rag.config import Settings
from rbac_rag.google_client import genai_client


class GeminiLLM:
    def __init__(self, settings: Settings, client=None, model: str | None = None):
        self.model = model or settings.gemini_llm_model
        self._client = client or genai_client(settings)

    def generate(self, system: str, prompt: str) -> str:
        from google.genai import types

        response = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(system_instruction=system, temperature=0.0),
        )
        return (response.text or "").strip()
