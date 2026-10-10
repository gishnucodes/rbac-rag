"""Integration tests for secure retrieval, ingestion, RAG pipeline, and registry."""

import os
import tempfile
from pathlib import Path

import pytest
import psycopg

from rbac_rag.acl.directory import DirectoryStore, DirectoryUser
from rbac_rag.acl.filters import DirectoryAclFilter
from rbac_rag.acl.guard import AccessGuard, AccessViolation
from rbac_rag.acl.policy import Policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.config import Settings
from rbac_rag.db.connection import connect
from rbac_rag.db.migrate import migrate
from rbac_rag.interfaces import SqlFragment
from rbac_rag.pipeline.ingest import load_manifest
from rbac_rag.pipeline.rag import REFUSAL
from rbac_rag.registry import build_pipeline
from rbac_rag.types import Acl, Chunk, Principal, SourceDocument, UserContext

pytestmark = pytest.mark.db


@pytest.fixture
def db_conn():
    db_url = (
        os.environ.get("RBAC_RAG_TEST_DATABASE_URL")
        or os.environ.get("RBAC_RAG_DATABASE_URL")
        or Settings().database_url
    )
    conn = connect(db_url)
    migrate(conn, 768)
    yield conn
    conn.close()


@pytest.fixture
def sample_policy(db_conn):
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
    store = PolicyStore(db_conn)
    store.publish(policy, activate=True)
    return policy


@pytest.fixture
def sample_directory(db_conn):
    dstore = DirectoryStore(db_conn)
    alice = DirectoryUser(id="alice", display_name="Alice", groups=frozenset(["eng"]), roles=frozenset(["engineer"]))
    bob = DirectoryUser(id="bob", display_name="Bob", groups=frozenset(["hr"]), roles=frozenset(["hr_manager"]))
    dstore.sync({"alice": alice, "bob": bob}, prune=True)


class BypassingAclFilter:
    """ACL filter stub that simulates a SQL filter defect returning chunks forbidden by the reference evaluator."""

    name = "bypassing"

    def build(self, user: UserContext, policy_version: int) -> SqlFragment:
        return SqlFragment(
            principals_sql="SELECT 'role'::text AS principal_type, 'hr_manager'::text AS principal_name"
        )

    def memberships(self, conn, user: UserContext):
        return DirectoryAclFilter().memberships(conn, user)


def test_manifest_and_ingestion_and_retrieval(db_conn, sample_policy, sample_directory):
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

        # Unknown user gets no retrieved chunks and RAG refusal
        unknown_user = UserContext(user_id="charlie_unknown")
        res_unknown = retriever.retrieve(unknown_user, "Kubernetes deployment")
        assert len(res_unknown.chunks) == 0

        ans_unknown = rag_pipeline.answer(unknown_user, "Kubernetes deployment")
        assert ans_unknown.refused
        assert ans_unknown.text == REFUSAL

        # Verify audit log entries
        rows = db_conn.execute(
            "SELECT user_id, policy_version, acl_filter, query, chunk_ids FROM retrieval_audit ORDER BY id DESC"
        ).fetchall()
        assert len(rows) >= 4
        # Check unknown user audit log entry
        latest_unknown = [r for r in rows if r[0] == "charlie_unknown"][0]
        assert latest_unknown[0] == "charlie_unknown"
        assert latest_unknown[1] == 1
        assert latest_unknown[2] == "directory"
        assert latest_unknown[4] == []


def test_access_violation_propagation(db_conn, sample_policy, sample_directory):
    settings = Settings(embedder="fake", llm="fake")
    ingest_pipeline, retriever, rag_pipeline = build_pipeline(settings, db_conn)

    doc = SourceDocument(
        id="doc_restricted",
        title="Restricted HR",
        text="Executive salaries and bonuses.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    ingest_pipeline.ingest([doc])

    # Replace retriever's ACL filter with BypassingAclFilter to simulate a buggy SQL filter
    retriever.acl_filter = BypassingAclFilter()

    alice_user = UserContext(user_id="alice")

    # SecureRetriever.retrieve must catch Mismatch via AccessGuard and propagate AccessViolation
    with pytest.raises(AccessViolation) as exc_info:
        retriever.retrieve(alice_user, "Executive salaries")
    assert "returned for alice under policy v1 but the reference evaluator denies it" in str(exc_info.value)


def test_hash_change_detection_and_deletion(db_conn, sample_policy, sample_directory):
    settings = Settings(embedder="fake", llm="fake")
    ingest_pipeline, retriever, _ = build_pipeline(settings, db_conn)
    store = ingest_pipeline.store

    # Wrap embedder to count calls
    embed_calls = 0
    orig_embed = ingest_pipeline.embedder.embed_documents

    def counting_embed(texts):
        nonlocal embed_calls
        embed_calls += 1
        return orig_embed(texts)

    ingest_pipeline.embedder.embed_documents = counting_embed

    doc = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Initial text content for change detection.",
        classification="internal",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )

    # 1. First ingest -> triggers embedding
    ingest_pipeline.ingest([doc])
    assert embed_calls == 1
    h1 = store.get_document_hashes("doc_hash_test")
    assert h1 is not None

    # Alice can retrieve it
    alice_user = UserContext(user_id="alice")
    res_alice1 = retriever.retrieve(alice_user, "Initial text content")
    assert any(c.document_id == "doc_hash_test" for c in res_alice1.chunks)

    # 2. Ingest identical doc -> skipped, no embedding calls
    res = ingest_pipeline.ingest([doc])
    assert res == []
    assert embed_calls == 1
    h2 = store.get_document_hashes("doc_hash_test")
    assert h1 == h2

    # 3. ACL / classification change only -> same content_hash, new acl_hash, NO re-embedding
    doc_acl_changed = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Initial text content for change detection.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    res_acl = ingest_pipeline.ingest([doc_acl_changed])
    assert res_acl == ["doc_hash_test"]
    assert embed_calls == 1  # Re-embedding was BYPASSED!
    h3 = store.get_document_hashes("doc_hash_test")
    assert h3[0] == h1[0]  # content_hash unchanged
    assert h3[1] != h1[1]  # acl_hash changed

    # Alice (engineer) can no longer retrieve it; Bob (hr_manager) can
    bob_user = UserContext(user_id="bob")
    res_alice2 = retriever.retrieve(alice_user, "Initial text content")
    assert not any(c.document_id == "doc_hash_test" for c in res_alice2.chunks)

    res_bob1 = retriever.retrieve(bob_user, "Initial text content")
    assert any(c.document_id == "doc_hash_test" for c in res_bob1.chunks)

    # 4. Content change -> triggers re-embedding
    doc_content_changed = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Updated text content for change detection.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    res_content = ingest_pipeline.ingest([doc_content_changed])
    assert res_content == ["doc_hash_test"]
    assert embed_calls == 2  # Re-embedding occurred
    h4 = store.get_document_hashes("doc_hash_test")
    assert h4[0] != h1[0]

    # 5. Delete document
    store.delete_document("doc_hash_test")
    assert store.get_document_hashes("doc_hash_test") is None
