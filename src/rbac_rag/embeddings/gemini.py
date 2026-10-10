from __future__ import annotations

import logging

from rbac_rag.config import Settings
from rbac_rag.google_client import genai_client

log = logging.getLogger(__name__)


class GeminiEmbedder:
    """Gemini embeddings (Vertex AI or Gemini API) via ``google-genai``."""

    def __init__(self, settings: Settings, client=None):
        self.dim = settings.embedding_dim
        self.model = settings.gemini_embedding_model
        self.batch_size = max(1, settings.embed_batch_size)
        self._client = client or genai_client(settings)

    def _call(self, texts: list[str], task_type: str) -> list[list[float]]:
        from google.genai import types

        response = self._client.models.embed_content(
            model=self.model,
            contents=texts,
            config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=self.dim),
        )
        return [list(e.values) for e in response.embeddings]

    def _embed(self, texts: list[str], task_type: str) -> list[list[float]]:
        out: list[list[float]] = []
        for start in range(0, len(texts), self.batch_size):
            batch = texts[start : start + self.batch_size]
            try:
                out.extend(self._call(batch, task_type))
            except Exception as exc:
                if len(batch) == 1:
                    raise
                # Some Vertex embedding models accept one input per request.
                log.warning("batch embed failed (%s); retrying one input per request", exc)
                self.batch_size = 1
                for text in batch:
                    out.extend(self._call([text], task_type))
        return out

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts, "RETRIEVAL_DOCUMENT")

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], "RETRIEVAL_QUERY")[0]
