"""Postgres + pgvector document, chunk, and chunk_acl store with secure search."""

from __future__ import annotations

import json
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from rbac_rag.interfaces import Embedder, SqlFragment
from rbac_rag.types import (
    Acl,
    Chunk,
    Principal,
    PrincipalType,
    RetrievedChunk,
    SourceDocument,
)


def _parse_version(vstr: str) -> tuple[int, ...]:
    clean = vstr.split("-")[0].split("+")[0]
    parts = []
    for part in clean.split("."):
        digits = ""
        for char in part:
            if char.isdigit():
                digits += char
            else:
                break
        if digits:
            parts.append(int(digits))
    return tuple(parts)


class PgVectorStore:
    def __init__(self, conn: psycopg.Connection, embedder: Embedder, hnsw_ef_search: int = 200):
        self.conn = conn
        self.embedder = embedder
        self.hnsw_ef_search = hnsw_ef_search

        row = self.conn.execute("SELECT value FROM rag_meta WHERE key = 'embedding_dim'").fetchone()
        if not row:
            raise ValueError("rag_meta key 'embedding_dim' not found in database")
        db_dim = int(row[0])
        if db_dim != embedder.dim:
            raise ValueError(
                f"Database embedding dimension ({db_dim}) does not match embedder dimension ({embedder.dim})"
            )

    def get_document_hashes(self, doc_id: str) -> tuple[str, str] | None:
        row = self.conn.execute(
            "SELECT content_hash, acl_hash FROM documents WHERE id = %s", (doc_id,)
        ).fetchone()
        if row is None:
            return None
        return (row[0], row[1])

    def upsert_document(
        self,
        doc: SourceDocument,
        chunks: list[Chunk],
        embeddings: list[list[float]] | None,
        content_hash: str,
        acl_hash: str,
    ) -> None:
        """Write documents, chunks, and chunk_acl in one transaction.

        If only acl_hash changed, rewrites chunk_acl and chunks.classification
        without re-embedding.
        """
        existing = self.get_document_hashes(doc.id)

        with self.conn.transaction():
            if existing is not None and existing[0] == content_hash and existing[1] != acl_hash:
                # Content is unchanged, but ACL/classification changed.
                self.conn.execute(
                    """
                    UPDATE documents
                    SET classification = %s, acl_hash = %s, updated_at = now()
                    WHERE id = %s
                    """,
                    (doc.classification, acl_hash, doc.id),
                )
                for chunk in chunks:
                    self.conn.execute(
                        "UPDATE chunks SET classification = %s WHERE id = %s",
                        (chunk.classification, chunk.id),
                    )
                    self.conn.execute("DELETE FROM chunk_acl WHERE chunk_id = %s", (chunk.id,))
                    with self.conn.cursor() as cur:
                        cur.executemany(
                            """
                            INSERT INTO chunk_acl (chunk_id, principal_type, principal_name, effect)
                            VALUES (%s, %s, %s, %s)
                            """,
                            [
                                (chunk.id, str(p.type), p.name, effect)
                                for p, effect in chunk.acl.entries()
                            ],
                        )
            else:
                # Content changed or document is new.
                self.conn.execute(
                    """
                    INSERT INTO documents (id, title, source_uri, classification, content_hash, acl_hash, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        source_uri = EXCLUDED.source_uri,
                        classification = EXCLUDED.classification,
                        content_hash = EXCLUDED.content_hash,
                        acl_hash = EXCLUDED.acl_hash,
                        metadata = EXCLUDED.metadata,
                        updated_at = now()
                    """,
                    (
                        doc.id,
                        doc.title,
                        doc.source_uri,
                        doc.classification,
                        content_hash,
                        acl_hash,
                        Jsonb(doc.metadata),
                    ),
                )

                # Delete existing chunks for this document (cascades to chunk_acl).
                self.conn.execute("DELETE FROM chunks WHERE document_id = %s", (doc.id,))

                if embeddings is None:
                    raise ValueError("Embeddings are required for new or re-embedded documents")
                if len(chunks) != len(embeddings):
                    raise ValueError(
                        f"Mismatched chunks and embeddings count: {len(chunks)} vs {len(embeddings)}"
                    )

                for chunk, emb in zip(chunks, embeddings):
                    # Format embedding vector as JSON string array if needed or list
                    emb_param = f"[{','.join(map(str, emb))}]"
                    self.conn.execute(
                        """
                        INSERT INTO chunks (id, document_id, ordinal, content, classification, embedding, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            chunk.id,
                            chunk.document_id,
                            chunk.ordinal,
                            chunk.content,
                            chunk.classification,
                            emb_param,
                            Jsonb(chunk.metadata),
                        ),
                    )
                    with self.conn.cursor() as cur:
                        cur.executemany(
                            """
                            INSERT INTO chunk_acl (chunk_id, principal_type, principal_name, effect)
                            VALUES (%s, %s, %s, %s)
                            """,
                            [
                                (chunk.id, str(p.type), p.name, effect)
                                for p, effect in chunk.acl.entries()
                            ],
                        )

    def delete_document(self, doc_id: str) -> None:
        with self.conn.transaction():
            self.conn.execute("DELETE FROM documents WHERE id = %s", (doc_id,))

    def secure_search(
        self,
        query_vec: list[float],
        fragment: SqlFragment,
        policy_version: int,
        k: int,
    ) -> list[RetrievedChunk]:
        with self.conn.transaction():
            self.conn.execute(f"SET LOCAL hnsw.ef_search = {int(self.hnsw_ef_search)}")

            row = self.conn.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
            ).fetchone()
            if row and row[0]:
                ext_ver = _parse_version(row[0])
                if ext_ver >= (0, 8):
                    self.conn.execute("SET LOCAL hnsw.iterative_scan = relaxed_order")

            extra_where = f"AND ({fragment.extra_where})" if fragment.extra_where.strip() else ""

            query_sql = f"""
            WITH p AS ({fragment.principals_sql}),
                 clr AS (SELECT rbac_clearance(ARRAY(SELECT principal_name FROM p WHERE principal_type='role'), %(pv)s) AS lvl)
            SELECT c.id, c.document_id, d.title, c.content, c.classification, c.metadata,
                   1 - (c.embedding <=> %(q)s::vector) AS score,
                   (SELECT json_agg(json_build_array(a.principal_type, a.principal_name, a.effect))
                    FROM chunk_acl a WHERE a.chunk_id = c.id) AS acl
            FROM chunks c JOIN documents d ON d.id = c.document_id
            JOIN classification_levels cl ON cl.policy_version = %(pv)s AND cl.label = c.classification
            WHERE cl.required_clearance <= (SELECT lvl FROM clr)
              AND EXISTS (
                  SELECT 1 FROM chunk_acl a JOIN p USING (principal_type, principal_name)
                  WHERE a.chunk_id = c.id AND a.effect = 'allow'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM chunk_acl a JOIN p USING (principal_type, principal_name)
                  WHERE a.chunk_id = c.id AND a.effect = 'deny'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM policy_deny_rules r JOIN p USING (principal_type, principal_name)
                  WHERE r.policy_version = %(pv)s AND r.classification = c.classification
              )
              {extra_where}
            ORDER BY c.embedding <=> %(q)s::vector LIMIT %(k)s
            """

            params = dict(fragment.params)
            params["q"] = f"[{','.join(map(str, query_vec))}]"
            params["pv"] = policy_version
            params["k"] = k

            rows = self.conn.execute(query_sql, params).fetchall()

        results: list[RetrievedChunk] = []
        for row_id, doc_id, title, content, classification, metadata, score, acl_raw in rows:
            allows: set[Principal] = set()
            denies: set[Principal] = set()
            if acl_raw:
                if isinstance(acl_raw, str):
                    acl_list = json.loads(acl_raw)
                else:
                    acl_list = acl_raw
                for item in acl_list:
                    p_type, p_name, effect = item[0], item[1], item[2]
                    principal = Principal(PrincipalType(p_type), p_name)
                    if effect == "allow":
                        allows.add(principal)
                    elif effect == "deny":
                        denies.add(principal)

            acl = Acl(frozenset(allows), frozenset(denies))
            results.append(
                RetrievedChunk(
                    chunk_id=row_id,
                    document_id=doc_id,
                    title=title,
                    content=content,
                    classification=classification,
                    score=float(score),
                    acl=acl,
                    metadata=metadata or {},
                )
            )

        results.sort(key=lambda x: x.score, reverse=True)
        return results
