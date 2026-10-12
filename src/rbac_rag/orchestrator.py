"""Multi-persona / multi-policy orchestration over :class:`RAGPipeline`.

Runs one question for several callers or policy versions, isolates failures per
run (an ``AccessViolation`` for one persona never hides the others), and
reports which chunks each run saw so policy changes can be compared."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from rbac_rag.acl.guard import AccessViolation
from rbac_rag.pipeline.rag import RAGPipeline
from rbac_rag.types import Answer, UserContext


@dataclass(frozen=True)
class RunResult:
    user: UserContext
    question: str
    answer: Answer | None
    error: str | None
    elapsed_ms: float

    @property
    def ok(self) -> bool:
        return self.answer is not None

    @property
    def policy_version(self) -> int | None:
        return self.answer.retrieval.policy_version if self.answer else None

    @property
    def chunk_ids(self) -> frozenset[str]:
        if not self.answer:
            return frozenset()
        return frozenset(c.chunk_id for c in self.answer.retrieval.chunks)


@dataclass(frozen=True)
class PolicyDiff:
    before: RunResult
    after: RunResult

    @property
    def gained(self) -> frozenset[str]:
        return self.after.chunk_ids - self.before.chunk_ids

    @property
    def lost(self) -> frozenset[str]:
        return self.before.chunk_ids - self.after.chunk_ids


class Orchestrator:
    def __init__(self, pipeline: RAGPipeline):
        self.pipeline = pipeline

    def run(self, user: UserContext, question: str) -> RunResult:
        start = time.perf_counter()
        answer: Answer | None = None
        error: str | None = None
        try:
            answer = self.pipeline.answer(user, question)
        except AccessViolation as exc:
            error = f"AccessViolation: {exc}"
        elapsed = (time.perf_counter() - start) * 1000
        return RunResult(user, question, answer, error, elapsed)

    def ask_many(self, users: list[UserContext], question: str) -> list[RunResult]:
        return [self.run(user, question) for user in users]

    def compare_policies(
        self, user: UserContext, question: str, before: int, after: int
    ) -> PolicyDiff:
        return PolicyDiff(
            before=self.run(replace(user, policy_version=before), question),
            after=self.run(replace(user, policy_version=after), question),
        )
