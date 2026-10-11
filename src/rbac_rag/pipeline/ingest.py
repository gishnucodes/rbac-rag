"""Ingestion pipeline and manifest loader."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from rbac_rag.interfaces import Chunker, Embedder
from rbac_rag.store.pgvector_store import PgVectorStore
from rbac_rag.types import Acl, Chunk, SourceDocument


def load_manifest(path: str | Path) -> list[SourceDocument]:
    manifest_path = Path(path).resolve()
    raw = yaml.safe_load(manifest_path.read_text()) or []
    if isinstance(raw, dict) and "documents" in raw:
        specs = raw["documents"]
    elif isinstance(raw, list):
        specs = raw
    else:
        raise ValueError(f"invalid manifest format in {manifest_path}")

    docs: list[SourceDocument] = []
    base_dir = manifest_path.parent

    for spec in specs:
        doc_id = spec["id"]
        rel_path = spec["path"]
        file_path = base_dir / rel_path
        text = file_path.read_text(encoding="utf-8")
        title = spec.get("title", file_path.stem)
        classification = spec["classification"]
        acl = Acl.from_specs(allow=spec.get("allow"), deny=spec.get("deny"))
        source_uri = spec.get("source_uri", rel_path)
        metadata = spec.get("metadata", {})

        docs.append(
            SourceDocument(
                id=doc_id,
                title=title,
                text=text,
                classification=classification,
                acl=acl,
                source_uri=source_uri,
                metadata=metadata,
            )
        )

    return docs


class IngestionPipeline:
    def __init__(self, chunker: Chunker, embedder: Embedder, store: PgVectorStore):
        self.chunker = chunker
        self.embedder = embedder
        self.store = store

    def ingest(self, docs: list[SourceDocument]) -> list[str]:
        ingested_ids: list[str] = []

        chunker_cls = self.chunker.__class__.__name__
        chunk_size = str(getattr(self.chunker, "chunk_size", ""))
        chunk_overlap = str(getattr(self.chunker, "chunk_overlap", ""))

        for doc in docs:
            drafts = self.chunker.split(doc)
            chunks: list[Chunk] = []

            for ordinal, draft in enumerate(drafts):
                chunk_id = f"{doc.id}:{ordinal:04d}"
                if draft.override:
                    chunk_acl = draft.override.apply(doc.acl)
                    chunk_classification = draft.override.classification or doc.classification
                else:
                    chunk_acl = doc.acl
                    chunk_classification = doc.classification

                chunks.append(
                    Chunk(
                        id=chunk_id,
                        document_id=doc.id,
                        ordinal=ordinal,
                        content=draft.content,
                        classification=chunk_classification,
                        acl=chunk_acl,
                        metadata=draft.metadata,
                    )
                )

            # Change detection hashes
            raw_content_str = f"{doc.text}{chunker_cls}{chunk_size}{chunk_overlap}"
            content_hash = hashlib.sha256(raw_content_str.encode("utf-8")).hexdigest()

            acl_summary = [(c.ordinal, c.classification, c.acl.entries()) for c in chunks]
            raw_acl_str = f"{doc.classification}{doc.acl.entries()}{acl_summary}"
            acl_hash = hashlib.sha256(raw_acl_str.encode("utf-8")).hexdigest()

            existing = self.store.get_document_hashes(doc.id)

            if existing is not None and existing[0] == content_hash and existing[1] == acl_hash:
                # Unchanged, skip
                continue

            if existing is not None and existing[0] == content_hash and existing[1] != acl_hash:
                # ACL / classification only changed
                self.store.upsert_document(
                    doc=doc,
                    chunks=chunks,
                    embeddings=None,
                    content_hash=content_hash,
                    acl_hash=acl_hash,
                )
            else:
                # Content changed or new document
                texts = [c.content for c in chunks]
                embeddings = self.embedder.embed_documents(texts) if texts else []
                self.store.upsert_document(
                    doc=doc,
                    chunks=chunks,
                    embeddings=embeddings,
                    content_hash=content_hash,
                    acl_hash=acl_hash,
                )

            ingested_ids.append(doc.id)

        return ingested_ids
