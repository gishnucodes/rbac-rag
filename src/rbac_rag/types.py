"""Core value types shared across the framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PrincipalType(StrEnum):
    USER = "user"
    GROUP = "group"
    ROLE = "role"


@dataclass(frozen=True, order=True)
class Principal:
    type: PrincipalType
    name: str

    @classmethod
    def parse(cls, spec: str) -> Principal:
        """Parse ``"role:engineer"`` / ``"group:hr"`` / ``"user:alice"``."""
        kind, sep, name = spec.partition(":")
        if not sep or not name:
            raise ValueError(f"principal must look like 'type:name', got {spec!r}")
        return cls(PrincipalType(kind.strip()), name.strip())

    def __str__(self) -> str:
        return f"{self.type}:{self.name}"


@dataclass(frozen=True)
class Acl:
    """Allow/deny principal sets attached to a document or chunk."""

    allow: frozenset[Principal] = frozenset()
    deny: frozenset[Principal] = frozenset()

    @classmethod
    def from_specs(cls, allow: list[str] | None = None, deny: list[str] | None = None) -> Acl:
        return cls(
            frozenset(Principal.parse(s) for s in allow or []),
            frozenset(Principal.parse(s) for s in deny or []),
        )

    def entries(self) -> list[tuple[Principal, str]]:
        return [(p, "allow") for p in sorted(self.allow)] + [(p, "deny") for p in sorted(self.deny)]


@dataclass(frozen=True)
class AclOverride:
    """A section-level ACL change produced by a chunker.

    ``mode="extend"`` adds to the document ACL; ``mode="replace"`` replaces it.
    Denies are always unioned: an override can never remove a document-level deny.
    """

    acl: Acl
    mode: str = "extend"
    classification: str | None = None

    def apply(self, base: Acl) -> Acl:
        if self.mode == "replace":
            return Acl(self.acl.allow, base.deny | self.acl.deny)
        if self.mode == "extend":
            return Acl(base.allow | self.acl.allow, base.deny | self.acl.deny)
        raise ValueError(f"unknown ACL override mode {self.mode!r}")


@dataclass(frozen=True)
class SourceDocument:
    id: str
    title: str
    text: str
    classification: str
    acl: Acl
    source_uri: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChunkDraft:
    """Chunker output, before ACL resolution and embedding."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    override: AclOverride | None = None


@dataclass(frozen=True)
class Chunk:
    id: str
    document_id: str
    ordinal: int
    content: str
    classification: str
    acl: Acl
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UserContext:
    """Who is asking.

    With the directory ACL filter only ``user_id`` is used and memberships are
    read from Postgres. With the claims filter, ``groups``/``roles`` come from
    the caller (e.g. a verified IdP token). ``policy_version=None`` means the
    active policy.
    """

    user_id: str
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    policy_version: int | None = None


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    document_id: str
    title: str
    content: str
    classification: str
    score: float
    acl: Acl
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievalResult:
    user: UserContext
    policy_version: int
    query: str
    chunks: list[RetrievedChunk]


@dataclass(frozen=True)
class Answer:
    question: str
    text: str
    refused: bool
    retrieval: RetrievalResult

    @property
    def contexts(self) -> list[str]:
        return [c.content for c in self.retrieval.chunks]
