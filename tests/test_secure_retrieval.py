"""DB integration tests for secure retrieval, ingestion, ACL enforcement, and audit."""

import os
import tempfile
from pathlib import Path

import pytest
import psycopg

from rbac_rag.acl.directory import DirectoryStore, DirectoryUser, load_directory
from rbac_rag.acl.filters import DirectoryAclFilter, ClaimsAclFilter
from rbac_rag.acl.guard import AccessGuard, AccessViolation, resolve_subject
from rbac_rag.acl.policy import Policy, load_policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.chunking.markdown import MarkdownChunker
from rbac_rag.config import Settings
from rbac_rag.db.migrate import migrate
from rbac_rag.embeddings.fake import HashingEmbedder
from rbac_rag.interfaces import SqlFragment
from rbac_rag.pipeline.ingest import IngestionPipeline, load_manifest
from rbac_rag.pipeline.rag import REFUSAL, RAGPipeline
from rbac_rag.pipeline.retriever import SecureRetriever
from rbac_rag.registry import build_pipeline
from rbac_rag.store.pgvector_store import PgVectorStore
from rbac_rag.types import Acl, Chunk, Principal, PrincipalType, SourceDocument, UserContext

pytestmark = pytest.mark.db


class BypassingAclFilter:
    """ACL filter stub that simulates a SQL filter defect returning chunks forbidden by the reference evaluator."""

    name = "bypassing"

    def build(self, user: UserContext, policy_version: int) -> SqlFragment:
        return SqlFragment(
            principals_sql="SELECT 'role'::text AS principal_type, 'hr_manager'::text AS principal_name"
        )

    def memberships(self, conn, user: UserContext):
        return DirectoryAclFilter().memberships(conn, user)


@pytest.fixture
def acme_env(db_conn):
    """Seed the Acme corpus from examples/acme with HashingEmbedder and setup policies and directory."""
    manifest_path = Path("examples/acme/acl.yaml")
    docs = load_manifest(manifest_path)

    policy_v1 = load_policy("examples/acme/policy_v1.yaml")
    policy_v2 = load_policy("examples/acme/policy_v2.yaml")

    policy_store = PolicyStore(db_conn)
    policy_store.publish(policy_v1, activate=True)
    policy_store.publish(policy_v2, activate=False)

    directory_path = Path("examples/acme/directory.yaml")
    directory = load_directory(directory_path)
    DirectoryStore(db_conn).sync(directory)

    embedder = HashingEmbedder(768)
    store = PgVectorStore(db_conn, embedder)
    chunker = MarkdownChunker(chunk_size=800, chunk_overlap=120)

    ingest_pipeline = IngestionPipeline(chunker=chunker, embedder=embedder, store=store)
    ingest_pipeline.ingest(docs)

    retriever = SecureRetriever(
        conn=db_conn,
        store=store,
        embedder=embedder,
        acl_filter=DirectoryAclFilter(),
        policy_store=policy_store,
        guard=AccessGuard(),
        k=10,
    )

    return {
        "docs": docs,
        "policy_v1": policy_v1,
        "policy_v2": policy_v2,
        "policy_store": policy_store,
        "directory": directory,
        "embedder": embedder,
        "store": store,
        "chunker": chunker,
        "retriever": retriever,
        "ingest_pipeline": ingest_pipeline,
    }


def test_soundness_sweep(db_conn, acme_env):
    """1. Soundness sweep.

    For every persona x every question x policy {1, 2}, every retrieved chunk
    passes the Python oracle Policy.decide. Build the oracle independently from
    the YAML sources, and use chunk ACLs from chunk_acl.
    """
    retriever = acme_env["retriever"]
    policy_v1_oracle = load_policy("examples/acme/policy_v1.yaml")
    policy_v2_oracle = load_policy("examples/acme/policy_v2.yaml")
    directory_oracle = load_directory("examples/acme/directory.yaml")

    personas = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "henry", "mallory"]
    questions = [
        "employee handbook engineering guidelines",
        "engineering operations infrastructure runbook",
        "break glass emergency access token",
        "compensation structure and salary bands",
        "Q3 financial performance and forecast report",
        "Project Nightjar acquisition strategy",
        "internal audit findings and remediation roadmap",
    ]

    for pv in (1, 2):
        oracle_policy = policy_v1_oracle if pv == 1 else policy_v2_oracle

        for persona in personas:
            if persona in directory_oracle:
                user_dir = directory_oracle[persona]
                subject = oracle_policy.subject(
                    user_id=persona,
                    groups=set(user_dir.groups),
                    roles=set(user_dir.roles),
                )
            else:
                subject = None

            for q in questions:
                user = UserContext(user_id=persona, policy_version=pv)
                result = retriever.retrieve(user, q)

                for chunk in result.chunks:
                    # Verify chunk ACLs match chunk_acl DB table
                    db_acl_rows = db_conn.execute(
                        "SELECT principal_type, principal_name, effect FROM chunk_acl WHERE chunk_id = %s",
                        (chunk.chunk_id,),
                    ).fetchall()
                    allows = {
                        Principal(PrincipalType(ptype), pname)
                        for ptype, pname, effect in db_acl_rows
                        if effect == "allow"
                    }
                    denies = {
                        Principal(PrincipalType(ptype), pname)
                        for ptype, pname, effect in db_acl_rows
                        if effect == "deny"
                    }
                    expected_db_acl = Acl(frozenset(allows), frozenset(denies))
                    assert chunk.acl == expected_db_acl

                    # Pass through independent oracle Policy.decide
                    decision = oracle_policy.decide(subject, chunk.classification, chunk.acl)
                    assert decision.allowed, (
                        f"Oracle denied chunk {chunk.chunk_id} for user '{persona}' "
                        f"under policy v{pv}: {decision.reason}"
                    )


def test_deny_beats_allow(db_conn, acme_env):
    """2. Deny beats allow.

    carol (executive) never gets legal_project_nightjar chunks; henry and grace do.
    """
    retriever = acme_env["retriever"]
    query = "Project Nightjar acquisition strategy legal memorandum"

    for pv in (1, 2):
        # Carol (executive) has allow via executive role, but explicit deny for user:carol
        res_carol = retriever.retrieve(UserContext(user_id="carol", policy_version=pv), query)
        assert not any(c.document_id == "legal_project_nightjar" for c in res_carol.chunks)

        # Henry (CEO / executive) gets Nightjar chunks
        res_henry = retriever.retrieve(UserContext(user_id="henry", policy_version=pv), query)
        assert any(c.document_id == "legal_project_nightjar" for c in res_henry.chunks)

        # Grace (general counsel) gets Nightjar chunks (explicit allow user:grace)
        res_grace = retriever.retrieve(UserContext(user_id="grace", policy_version=pv), query)
        assert any(c.document_id == "legal_project_nightjar" for c in res_grace.chunks)


def test_per_chunk_override(db_conn, acme_env):
    """3. Per-chunk override.

    contractors and interns never get the break-glass section, even though
    they're allowed on the rest of the runbook.
    """
    retriever = acme_env["retriever"]
    query = "break glass emergency access token runbook"

    # Erin (contractor) under policy v1 (when contractor is allowed on internal runbook)
    res_erin = retriever.retrieve(UserContext(user_id="erin", policy_version=1), query)
    assert any(c.document_id == "eng_runbook" for c in res_erin.chunks)
    assert not any("Break-glass" in c.content or c.classification == "confidential" for c in res_erin.chunks)

    # Dave (intern) under policy v2 (when intern clearance is elevated to 1)
    res_dave = retriever.retrieve(UserContext(user_id="dave", policy_version=2), query)
    assert any(c.document_id == "eng_runbook" for c in res_dave.chunks)
    assert not any("Break-glass" in c.content or c.classification == "confidential" for c in res_dave.chunks)


def test_clearance(db_conn, acme_env):
    """4. Clearance.

    dave (intern) gets no runbook chunks under v1 and does under v2.
    """
    retriever = acme_env["retriever"]
    query = "engineering operations runbook"

    # Dave under v1 (clearance 0 < 1) -> 0 runbook chunks
    res_dave_v1 = retriever.retrieve(UserContext(user_id="dave", policy_version=1), query)
    assert not any(c.document_id == "eng_runbook" for c in res_dave_v1.chunks)

    # Dave under v2 (clearance elevated to 1) -> receives runbook chunks
    res_dave_v2 = retriever.retrieve(UserContext(user_id="dave", policy_version=2), query)
    assert any(c.document_id == "eng_runbook" for c in res_dave_v2.chunks)


def test_policy_switch(db_conn, acme_env):
    """5. Policy switch.

    erin loses runbook access in v2, and frank gains audit_findings in v2.
    """
    retriever = acme_env["retriever"]

    # Erin (contractor)
    runbook_q = "engineering operations runbook"
    res_erin_v1 = retriever.retrieve(UserContext(user_id="erin", policy_version=1), runbook_q)
    assert any(c.document_id == "eng_runbook" for c in res_erin_v1.chunks)

    res_erin_v2 = retriever.retrieve(UserContext(user_id="erin", policy_version=2), runbook_q)
    assert not any(c.document_id == "eng_runbook" for c in res_erin_v2.chunks)

    # Frank (finance)
    audit_q = "internal audit findings remediation roadmap"
    res_frank_v1 = retriever.retrieve(UserContext(user_id="frank", policy_version=1), audit_q)
    assert not any(c.document_id == "audit_findings" for c in res_frank_v1.chunks)

    res_frank_v2 = retriever.retrieve(UserContext(user_id="frank", policy_version=2), audit_q)
    assert any(c.document_id == "audit_findings" for c in res_frank_v2.chunks)


def test_unknown_user(db_conn, acme_env):
    """6. Unknown user.

    mallory gets zero chunks.
    """
    retriever = acme_env["retriever"]
    queries = [
        "employee handbook engineering",
        "engineering operations runbook",
        "compensation structure salary bands",
        "Project Nightjar acquisition strategy",
    ]

    for pv in (1, 2):
        for q in queries:
            res = retriever.retrieve(UserContext(user_id="mallory", policy_version=pv), q)
            assert len(res.chunks) == 0


def test_nearest_vector_excluded(db_conn, acme_env):
    """7. Nearest vector excluded.

    Query with the exact text of a restricted chunk as an unauthorized user;
    that chunk must not come back.
    """
    retriever = acme_env["retriever"]

    # Restricted chunk from legal_project_nightjar
    nightjar_chunk = db_conn.execute(
        "SELECT content FROM chunks WHERE document_id = 'legal_project_nightjar' LIMIT 1"
    ).fetchone()[0]

    # Carol is unauthorized due to explicit deny on legal_project_nightjar
    res_carol = retriever.retrieve(UserContext(user_id="carol", policy_version=1), nightjar_chunk)
    assert not any(c.document_id == "legal_project_nightjar" for c in res_carol.chunks)

    # Alice is unauthorized due to insufficient clearance (clearance 1 < 3)
    res_alice = retriever.retrieve(UserContext(user_id="alice", policy_version=1), nightjar_chunk)
    assert not any(c.document_id == "legal_project_nightjar" for c in res_alice.chunks)

    # Confidential chunk from hr_comp_bands
    hr_chunk = db_conn.execute(
        "SELECT content FROM chunks WHERE document_id = 'hr_comp_bands' LIMIT 1"
    ).fetchone()[0]

    # Alice (engineer) is unauthorized for HR comp bands
    res_alice_hr = retriever.retrieve(UserContext(user_id="alice", policy_version=1), hr_chunk)
    assert not any(c.document_id == "hr_comp_bands" for c in res_alice_hr.chunks)


def test_guard_access_violation(db_conn, acme_env):
    """8. Guard.

    A deliberately broken custom AclFilter that returns all principals makes AccessGuard raise AccessViolation.
    """
    store = acme_env["store"]
    embedder = acme_env["embedder"]
    policy_store = acme_env["policy_store"]

    broken_retriever = SecureRetriever(
        conn=db_conn,
        store=store,
        embedder=embedder,
        acl_filter=BypassingAclFilter(),
        policy_store=policy_store,
        guard=AccessGuard(),
        k=10,
    )

    alice_user = UserContext(user_id="alice", policy_version=1)

    with pytest.raises(AccessViolation) as exc_info:
        broken_retriever.retrieve(alice_user, "Executive salaries and compensation")

    assert "returned for alice under policy v1 but the reference evaluator denies it" in str(exc_info.value)


def test_claims_filter_matches_directory_filter(db_conn, acme_env):
    """9. Claims filter.

    It matches the directory filter for equivalent memberships.
    """
    store = acme_env["store"]
    embedder = acme_env["embedder"]
    policy_store = acme_env["policy_store"]
    directory = acme_env["directory"]

    dir_retriever = SecureRetriever(
        conn=db_conn,
        store=store,
        embedder=embedder,
        acl_filter=DirectoryAclFilter(),
        policy_store=policy_store,
        guard=AccessGuard(),
        k=10,
    )

    claims_retriever = SecureRetriever(
        conn=db_conn,
        store=store,
        embedder=embedder,
        acl_filter=ClaimsAclFilter(),
        policy_store=policy_store,
        guard=AccessGuard(),
        k=10,
    )

    queries = [
        "employee handbook engineering",
        "engineering operations infrastructure runbook",
        "compensation structure salary bands",
        "Project Nightjar acquisition strategy",
        "internal audit findings remediation",
    ]

    for uid, duser in directory.items():
        for pv in (1, 2):
            for q in queries:
                dir_user = UserContext(user_id=uid, policy_version=pv)
                claims_user = UserContext(
                    user_id=uid,
                    groups=duser.groups,
                    roles=duser.roles,
                    policy_version=pv,
                )

                res_dir = dir_retriever.retrieve(dir_user, q)
                res_claims = claims_retriever.retrieve(claims_user, q)

                dir_ids = [c.chunk_id for c in res_dir.chunks]
                claims_ids = [c.chunk_id for c in res_claims.chunks]
                assert dir_ids == claims_ids, f"Mismatch for user {uid} under policy v{pv} on query '{q}'"

                dir_scores = [c.score for c in res_dir.chunks]
                claims_scores = [c.score for c in res_claims.chunks]
                assert dir_scores == claims_scores


def test_audit_logging(db_conn, acme_env):
    """10. Audit.

    One retrieval_audit row per retrieve, with the right chunk ids and policy version.
    """
    retriever = acme_env["retriever"]

    db_conn.execute("TRUNCATE TABLE retrieval_audit")

    alice_user = UserContext(user_id="alice", policy_version=1)
    res1 = retriever.retrieve(alice_user, "employee handbook")

    rows = db_conn.execute(
        "SELECT user_id, policy_version, acl_filter, query, chunk_ids FROM retrieval_audit ORDER BY id DESC"
    ).fetchall()

    assert len(rows) == 1
    row1 = rows[0]
    assert row1[0] == "alice"
    assert row1[1] == 1
    assert row1[2] == "directory"
    assert row1[3] == "employee handbook"
    assert row1[4] == [c.chunk_id for c in res1.chunks]

    bob_user = UserContext(user_id="bob", policy_version=2)
    res2 = retriever.retrieve(bob_user, "compensation structure")

    rows2 = db_conn.execute(
        "SELECT user_id, policy_version, acl_filter, query, chunk_ids FROM retrieval_audit ORDER BY id DESC"
    ).fetchall()

    assert len(rows2) == 2
    row2 = rows2[0]
    assert row2[0] == "bob"
    assert row2[1] == 2
    assert row2[2] == "directory"
    assert row2[3] == "compensation structure"
    assert row2[4] == [c.chunk_id for c in res2.chunks]


def test_incremental_ingest(db_conn, acme_env):
    """11. Incremental ingest.

    Re-ingesting with only an ACL change rewrites chunk_acl without calling the
    embedder (use a counting embedder), and the new ACL takes effect immediately.
    """
    store = acme_env["store"]
    chunker = acme_env["chunker"]
    policy_store = acme_env["policy_store"]

    base_embedder = HashingEmbedder(768)
    embed_calls = 0

    class CountingEmbedder:
        def __init__(self, inner):
            self.inner = inner
            self.dim = inner.dim

        def embed_documents(self, texts):
            nonlocal embed_calls
            embed_calls += 1
            return self.inner.embed_documents(texts)

        def embed_query(self, query):
            return self.inner.embed_query(query)

    counting_embedder = CountingEmbedder(base_embedder)
    counting_store = PgVectorStore(db_conn, counting_embedder)
    ingest_pipe = IngestionPipeline(chunker=chunker, embedder=counting_embedder, store=counting_store)

    retriever = SecureRetriever(
        conn=db_conn,
        store=counting_store,
        embedder=counting_embedder,
        acl_filter=DirectoryAclFilter(),
        policy_store=policy_store,
        guard=AccessGuard(),
        k=10,
    )

    doc_id = "inc_test_doc"
    doc_v1 = SourceDocument(
        id=doc_id,
        title="Incremental Test Doc",
        text="## Incremental Section\nUnique text content for incremental ACL test.",
        classification="internal",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )

    # First ingest -> calls embedder
    ingest_pipe.ingest([doc_v1])
    assert embed_calls == 1

    # Alice (engineer) can retrieve it; Bob (hr_manager) cannot
    alice_user = UserContext(user_id="alice", policy_version=1)
    bob_user = UserContext(user_id="bob", policy_version=1)

    res_alice1 = retriever.retrieve(alice_user, "Unique text content")
    assert any(c.document_id == doc_id for c in res_alice1.chunks)

    res_bob1 = retriever.retrieve(bob_user, "Unique text content")
    assert not any(c.document_id == doc_id for c in res_bob1.chunks)

    # Update ACL only -> allow role:hr_manager
    doc_v2 = SourceDocument(
        id=doc_id,
        title="Incremental Test Doc",
        text="## Incremental Section\nUnique text content for incremental ACL test.",
        classification="internal",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )

    res_inc = ingest_pipe.ingest([doc_v2])
    assert res_inc == [doc_id]
    # Embedder was NOT called during ACL-only update
    assert embed_calls == 1

    # Verify chunk_acl table was rewritten in DB
    chunk_acl_rows = db_conn.execute(
        "SELECT principal_name FROM chunk_acl WHERE chunk_id = %s",
        (f"{doc_id}:0000",),
    ).fetchall()
    assert [r[0] for r in chunk_acl_rows] == ["hr_manager"]

    # New ACL takes effect immediately: Alice loses access, Bob gains access
    res_alice2 = retriever.retrieve(alice_user, "Unique text content")
    assert not any(c.document_id == doc_id for c in res_alice2.chunks)

    res_bob2 = retriever.retrieve(bob_user, "Unique text content")
    assert any(c.document_id == doc_id for c in res_bob2.chunks)


def test_manifest_and_ingestion_and_retrieval(db_conn):
    """Manifest loading, pipeline construction, RAG answer and refusal."""
    policy = Policy.from_dict({
        "version": 1,
        "name": "v1",
        "description": "Test Policy",
        "classifications": {"public": 0, "internal": 1, "confidential": 2},
        "roles": {
            "engineer": {"clearance": 1, "inherits": []},
            "hr_manager": {"clearance": 2, "inherits": []},
        },
        "groups": {
            "eng": ["engineer"],
            "hr": ["hr_manager"],
        },
        "deny_rules": [],
    })
    policy_store = PolicyStore(db_conn)
    policy_store.publish(policy, activate=True)

    dstore = DirectoryStore(db_conn)
    alice = DirectoryUser(id="alice", display_name="Alice", groups=frozenset(["eng"]), roles=frozenset(["engineer"]))
    bob = DirectoryUser(id="bob", display_name="Bob", groups=frozenset(["hr"]), roles=frozenset(["hr_manager"]))
    dstore.sync({"alice": alice, "bob": bob}, prune=True)

    settings = Settings(embedder="fake", llm="fake", top_k=5)
    ingest_pipeline, retriever, rag_pipeline = build_pipeline(settings, db_conn)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        doc1_file = tmp_path / "eng_doc.md"
        doc1_file.write_text("## Engineering Handbook\nSystem deployment uses Kubernetes and Terraform.")

        doc2_file = tmp_path / "hr_doc.md"
        doc2_file.write_text("## HR Comp Bands\nExecutive salaries and compensation structures.")

        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(f"""
documents:
  - id: doc_eng
    path: eng_doc.md
    title: Engineering
    classification: internal
    allow: ["role:engineer"]
  - id: doc_hr
    path: hr_doc.md
    title: HR
    classification: confidential
    allow: ["role:hr_manager"]
""")

        docs = load_manifest(manifest_file)
        assert len(docs) == 2

        ingested = ingest_pipeline.ingest(docs)
        assert len(ingested) == 2

        # Alice (Engineer) asks about deployment -> gets eng_doc
        alice_user = UserContext(user_id="alice")
        res_alice = retriever.retrieve(alice_user, "Kubernetes deployment")
        assert len(res_alice.chunks) == 1
        assert res_alice.chunks[0].document_id == "doc_eng"

        # Bob (HR) asks about salaries -> gets hr_doc
        bob_user = UserContext(user_id="bob")
        res_bob = retriever.retrieve(bob_user, "salaries compensation")
        assert len(res_bob.chunks) == 1
        assert res_bob.chunks[0].document_id == "doc_hr"

        # Bob asks about salaries with RAG pipeline -> gets answer from hr_doc
        ans_bob = rag_pipeline.answer(bob_user, "salaries compensation")
        assert not ans_bob.refused
        assert "salaries" in ans_bob.text or "compensation" in ans_bob.text

        # Alice asks about HR compensation -> retrieved chunks never include doc_hr
        res_alice_hr = retriever.retrieve(alice_user, "salaries compensation")
        assert not any(c.document_id == "doc_hr" for c in res_alice_hr.chunks)

        # Alice asking HR question in RAG pipeline is refused
        ans_alice_hr = rag_pipeline.answer(alice_user, "salaries compensation")
        assert ans_alice_hr.refused
        assert ans_alice_hr.text == REFUSAL


def test_delete_document(db_conn, acme_env):
    """12. Delete document.

    Ingest a document, verify it exists and its chunks are returned in retrieval,
    then delete it via PgVectorStore.delete_document.
    Assert store.get_document_hashes(doc_id) returns None, no chunk rows remain for doc_id,
    retrieval returns no chunks for doc_id, and other documents remain intact.
    """
    store = acme_env["store"]
    ingest_pipeline = acme_env["ingest_pipeline"]
    retriever = acme_env["retriever"]

    doc_id = "doc_to_delete"
    doc = SourceDocument(
        id=doc_id,
        title="Document To Delete",
        text="## Temporary Document\nThis document will be deleted and tested.",
        classification="internal",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )

    ingest_pipeline.ingest([doc])

    # Document and chunks exist prior to deletion
    assert store.get_document_hashes(doc_id) is not None
    alice_user = UserContext(user_id="alice", policy_version=1)
    res_before = retriever.retrieve(alice_user, "Temporary Document")
    assert any(c.document_id == doc_id for c in res_before.chunks)

    chunks_before = db_conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE document_id = %s", (doc_id,)
    ).fetchone()[0]
    assert chunks_before > 0

    # Ensure other documents exist
    other_doc_id = "handbook"
    assert store.get_document_hashes(other_doc_id) is not None
    other_chunks_before = db_conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE document_id = %s", (other_doc_id,)
    ).fetchone()[0]
    assert other_chunks_before > 0

    # Perform deletion
    store.delete_document(doc_id)

    # 1. Document hashes return None
    assert store.get_document_hashes(doc_id) is None

    # 2. Secure search / retrieval returns no chunks for deleted doc
    res_after = retriever.retrieve(alice_user, "Temporary Document")
    assert not any(c.document_id == doc_id for c in res_after.chunks)

    # 3. No chunk rows remain for deleted doc (cascade)
    chunks_after = db_conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE document_id = %s", (doc_id,)
    ).fetchone()[0]
    assert chunks_after == 0

    # 4. Other documents are untouched
    assert store.get_document_hashes(other_doc_id) is not None
    other_chunks_after = db_conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE document_id = %s", (other_doc_id,)
    ).fetchone()[0]
    assert other_chunks_after == other_chunks_before

    other_retrieved = retriever.retrieve(alice_user, "employee handbook")
    assert any(c.document_id == other_doc_id for c in other_retrieved.chunks)
