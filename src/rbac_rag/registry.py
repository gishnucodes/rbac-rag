"""Registry of pluggable components and pipeline builder."""

from __future__ import annotations

import importlib
from typing import Any, Callable

import psycopg

from rbac_rag.acl.filters import ClaimsAclFilter, DirectoryAclFilter
from rbac_rag.acl.guard import AccessGuard
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.chunking.markdown import MarkdownChunker
from rbac_rag.chunking.recursive import RecursiveChunker
from rbac_rag.config import Settings
from rbac_rag.embeddings.fake import HashingEmbedder
from rbac_rag.embeddings.gemini import GeminiEmbedder
from rbac_rag.interfaces import AclFilter, Chunker, Embedder, LLM
from rbac_rag.llm.fake import ExtractiveLLM
from rbac_rag.llm.gemini import GeminiLLM
from rbac_rag.pipeline.ingest import IngestionPipeline
from rbac_rag.pipeline.rag import RAGPipeline
from rbac_rag.pipeline.retriever import SecureRetriever
from rbac_rag.store.pgvector_store import PgVectorStore


def _resolve_class(spec: str) -> type:
    mod_name, cls_name = spec.split(":", 1)
    mod = importlib.import_module(mod_name)
    return getattr(mod, cls_name)


def _instantiate(cls: type, settings: Settings) -> Any:
    # Try initializing with settings, or no-args fallback.
    try:
        return cls(settings)
    except TypeError:
        return cls()


_CHUNKER_FACTORIES: dict[str, Callable[[Settings], Chunker]] = {
    "markdown": lambda s: MarkdownChunker(chunk_size=s.chunk_size, chunk_overlap=s.chunk_overlap),
    "recursive": lambda s: RecursiveChunker(chunk_size=s.chunk_size, chunk_overlap=s.chunk_overlap),
}

_EMBEDDER_FACTORIES: dict[str, Callable[[Settings], Embedder]] = {
    "gemini": lambda s: GeminiEmbedder(s),
    "fake": lambda s: HashingEmbedder(dim=s.embedding_dim),
}

_LLM_FACTORIES: dict[str, Callable[[Settings], LLM]] = {
    "gemini": lambda s: GeminiLLM(s),
    "fake": lambda s: ExtractiveLLM(),
}

_ACL_FILTER_FACTORIES: dict[str, Callable[[Settings], AclFilter]] = {
    "directory": lambda s: DirectoryAclFilter(),
    "claims": lambda s: ClaimsAclFilter(),
}


def get_chunker(name_or_spec: str, settings: Settings) -> Chunker:
    if ":" in name_or_spec:
        cls = _resolve_class(name_or_spec)
        return _instantiate(cls, settings)
    if name_or_spec in _CHUNKER_FACTORIES:
        return _CHUNKER_FACTORIES[name_or_spec](settings)
    raise ValueError(f"Unknown chunker {name_or_spec!r}")


def get_embedder(name_or_spec: str, settings: Settings) -> Embedder:
    if ":" in name_or_spec:
        cls = _resolve_class(name_or_spec)
        return _instantiate(cls, settings)
    if name_or_spec in _EMBEDDER_FACTORIES:
        return _EMBEDDER_FACTORIES[name_or_spec](settings)
    raise ValueError(f"Unknown embedder {name_or_spec!r}")


def get_llm(name_or_spec: str, settings: Settings) -> LLM:
    if ":" in name_or_spec:
        cls = _resolve_class(name_or_spec)
        return _instantiate(cls, settings)
    if name_or_spec in _LLM_FACTORIES:
        return _LLM_FACTORIES[name_or_spec](settings)
    raise ValueError(f"Unknown llm {name_or_spec!r}")


def get_acl_filter(name_or_spec: str, settings: Settings) -> AclFilter:
    if ":" in name_or_spec:
        cls = _resolve_class(name_or_spec)
        return _instantiate(cls, settings)
    if name_or_spec in _ACL_FILTER_FACTORIES:
        return _ACL_FILTER_FACTORIES[name_or_spec](settings)
    raise ValueError(f"Unknown acl_filter {name_or_spec!r}")


def build_pipeline(
    settings: Settings, conn: psycopg.Connection
) -> tuple[IngestionPipeline, SecureRetriever, RAGPipeline]:
    chunker = get_chunker(settings.chunker, settings)
    embedder = get_embedder(settings.embedder, settings)
    llm = get_llm(settings.llm, settings)
    acl_filter = get_acl_filter(settings.acl_filter, settings)

    store = PgVectorStore(conn, embedder, hnsw_ef_search=settings.hnsw_ef_search)
    policy_store = PolicyStore(conn)
    guard = AccessGuard()

    ingest_pipeline = IngestionPipeline(chunker=chunker, embedder=embedder, store=store)
    retriever = SecureRetriever(
        conn=conn,
        store=store,
        embedder=embedder,
        acl_filter=acl_filter,
        policy_store=policy_store,
        guard=guard,
        k=settings.top_k,
    )
    rag_pipeline = RAGPipeline(retriever=retriever, llm=llm)

    return ingest_pipeline, retriever, rag_pipeline
