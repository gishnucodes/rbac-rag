"""Extension points. Implement any of these protocols and register the
implementation in :mod:`rbac_rag.registry` (or reference it as
``"package.module:ClassName"`` in settings)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from rbac_rag.types import ChunkDraft, SourceDocument, UserContext


@runtime_checkable
class Chunker(Protocol):
    def split(self, document: SourceDocument) -> list[ChunkDraft]: ...


@runtime_checkable
class Embedder(Protocol):
    dim: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


@runtime_checkable
class LLM(Protocol):
    def generate(self, system: str, prompt: str) -> str: ...


@dataclass(frozen=True)
class SqlFragment:
    """SQL contributed by an :class:`AclFilter` to the secure search query.

    ``principals_sql`` must be a query returning ``(principal_type,
    principal_name)`` rows: the caller's effective principals. The store
    wraps it in a CTE named ``p`` and applies the chunk ACL, policy deny
    rules and classification clearance against it. ``extra_where`` lets a
    filter add further predicates over ``c`` (chunks) and ``d`` (documents).
    """

    principals_sql: str
    params: dict[str, Any] = field(default_factory=dict)
    extra_where: str = ""


@runtime_checkable
class AclFilter(Protocol):
    name: str

    def build(self, user: UserContext, policy_version: int) -> SqlFragment: ...

    def memberships(self, conn: Any, user: UserContext) -> tuple[set[str], set[str]] | None:
        """Return ``(groups, roles)`` directly held by the user, or ``None`` for
        an unknown user. Used by the post-retrieval guard to re-check results
        independently of the SQL."""
        ...
