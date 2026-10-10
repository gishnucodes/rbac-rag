"""Runtime settings, read from environment variables (prefix ``RBAC_RAG_``) or ``.env``."""

from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RBAC_RAG_", env_file=".env", extra="ignore")

    database_url: str = "postgresql://rag:rag@localhost:5432/rbac_rag"

    # Component selection, by registry name or "package.module:ClassName".
    chunker: str = "markdown"
    embedder: str = "gemini"
    llm: str = "gemini"
    acl_filter: str = "directory"

    chunk_size: int = 800
    chunk_overlap: int = 120
    top_k: int = 5
    # HNSW candidate list size used for filtered searches.
    hnsw_ef_search: int = 200

    embedding_dim: int = 768
    gemini_embedding_model: str = "gemini-embedding-001"
    gemini_llm_model: str = "gemini-2.5-flash"
    gemini_judge_model: str = "gemini-2.5-flash"
    embed_batch_size: int = 16

    # Google / Vertex AI. These use the standard google-genai variable names.
    google_api_key: str | None = Field(
        default=None, validation_alias=AliasChoices("GOOGLE_API_KEY", "RBAC_RAG_GOOGLE_API_KEY")
    )
    google_use_vertexai: bool = Field(
        default=True,
        validation_alias=AliasChoices("GOOGLE_GENAI_USE_VERTEXAI", "RBAC_RAG_GOOGLE_USE_VERTEXAI"),
    )
    google_cloud_project: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GOOGLE_CLOUD_PROJECT", "RBAC_RAG_GOOGLE_CLOUD_PROJECT"),
    )
    google_cloud_location: str = Field(
        default="us-central1",
        validation_alias=AliasChoices("GOOGLE_CLOUD_LOCATION", "RBAC_RAG_GOOGLE_CLOUD_LOCATION"),
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
