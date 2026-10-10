from __future__ import annotations

from functools import lru_cache

from rbac_rag.config import Settings


@lru_cache(maxsize=4)
def _client(api_key: str | None, vertexai: bool, project: str | None, location: str):
    from google import genai

    if vertexai and project and not api_key:
        return genai.Client(vertexai=True, project=project, location=location)
    if vertexai and api_key:
        # Vertex AI express mode: API key, no project needed.
        return genai.Client(vertexai=True, api_key=api_key)
    if api_key:
        return genai.Client(api_key=api_key)
    # Fall back to google-genai's own environment / ADC discovery.
    return genai.Client()


def genai_client(settings: Settings):
    """A shared ``google.genai.Client`` configured for Vertex AI from settings."""
    return _client(
        settings.google_api_key,
        settings.google_use_vertexai,
        settings.google_cloud_project,
        settings.google_cloud_location,
    )
