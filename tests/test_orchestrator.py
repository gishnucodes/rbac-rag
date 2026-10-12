from rbac_rag.acl.guard import AccessViolation
from rbac_rag.orchestrator import Orchestrator
from rbac_rag.pipeline.rag import REFUSAL
from rbac_rag.types import Acl, Answer, RetrievalResult, RetrievedChunk, UserContext


def _chunk(cid: str) -> RetrievedChunk:
    return RetrievedChunk(cid, "d", "t", f"text {cid}", "internal", 1.0, Acl())


class StubPipeline:
    """Visible chunks per (user_id, policy_version)."""

    def __init__(self, visible):
        self.visible = visible

    def answer(self, user, question):
        if user.user_id == "bad":
            raise AccessViolation("leak")
        pv = user.policy_version or 1
        chunks = [_chunk(c) for c in self.visible.get((user.user_id, pv), [])]
        retrieval = RetrievalResult(user, pv, question, chunks)
        return Answer(question, "ok" if chunks else REFUSAL, not chunks, retrieval)


def _orch():
    return Orchestrator(
        StubPipeline({("alice", 1): ["a", "b"], ("alice", 2): ["b", "c"], ("bob", 1): ["a"]})
    )


def test_ask_many_isolates_violations():
    results = _orch().ask_many(
        [UserContext("alice"), UserContext("bad"), UserContext("carol")], "q"
    )
    assert [r.ok for r in results] == [True, False, True]
    assert "AccessViolation" in results[1].error
    assert results[2].answer.refused


def test_compare_policies_reports_gained_and_lost():
    diff = _orch().compare_policies(UserContext("alice"), "q", 1, 2)
    assert diff.gained == {"c"}
    assert diff.lost == {"a"}
    assert diff.before.policy_version == 1 and diff.after.policy_version == 2
