"""Defense in depth: re-check every retrieved chunk in Python."""

from __future__ import annotations

from typing import Any

from rbac_rag.acl.policy import Policy, Subject
from rbac_rag.interfaces import AclFilter
from rbac_rag.types import RetrievedChunk, UserContext


class AccessViolation(RuntimeError):
    """The SQL filter returned a chunk the reference evaluator rejects.

    This indicates a bug in an ACL filter or in the schema functions, never a
    user error, so it is raised rather than silently dropping the chunk."""


def resolve_subject(conn: Any, acl_filter: AclFilter, policy: Policy, user: UserContext) -> Subject | None:
    memberships = acl_filter.memberships(conn, user)
    if memberships is None:
        return None
    groups, roles = memberships
    return policy.subject(user.user_id, groups, roles)


class AccessGuard:
    def check(self, subject: Subject | None, policy: Policy, chunks: list[RetrievedChunk]) -> None:
        for chunk in chunks:
            decision = policy.decide(subject, chunk.classification, chunk.acl)
            if not decision.allowed:
                who = subject.user_id if subject else "<unknown>"
                raise AccessViolation(
                    f"chunk {chunk.chunk_id} returned for {who} under policy v{policy.version} "
                    f"but the reference evaluator denies it: {decision.reason}"
                )
