"""Secure retriever with CTE vector search and post-retrieval access guard."""

from __future__ import annotations

from typing import Any

import psycopg

from rbac_rag.acl.guard import AccessGuard, resolve_subject
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.interfaces import AclFilter, Embedder
from rbac_rag.store.pgvector_store import PgVectorStore
from rbac_rag.types import RetrievalResult, UserContext


class SecureRetriever:
    def __init__(
        self,
        conn: psycopg.Connection,
        store: PgVectorStore,
        embedder: Embedder,
        acl_filter: AclFilter,
        policy_store: PolicyStore,
        guard: AccessGuard,
        k: int = 5,
    ):
        self.conn = conn
        self.store = store
        self.embedder = embedder
        self.acl_filter = acl_filter
        self.policy_store = policy_store
        self.guard = guard
        self.k = k

    def retrieve(self, user: UserContext, query: str) -> RetrievalResult:
        policy_version = self.policy_store.resolve_version(user.policy_version)
        query_vec = self.embedder.embed_query(query)
        fragment = self.acl_filter.build(user, policy_version)
        chunks = self.store.secure_search(
            query_vec=query_vec,
            fragment=fragment,
            policy_version=policy_version,
            k=self.k,
        )

        policy = self.policy_store.get(policy_version)
        subject = resolve_subject(self.conn, self.acl_filter, policy, user)
        self.guard.check(subject, policy, chunks)

        chunk_ids = [c.chunk_id for c in chunks]
        with self.conn.transaction():
            self.conn.execute(
                """
                INSERT INTO retrieval_audit (user_id, policy_version, acl_filter, query, chunk_ids)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user.user_id, policy_version, self.acl_filter.name, query, chunk_ids),
            )

        return RetrievalResult(
            user=user,
            policy_version=policy_version,
            query=query,
            chunks=chunks,
        )
