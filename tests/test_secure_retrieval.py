"""Integration tests for secure retrieval, ingestion, RAG pipeline, and registry."""

import os
import tempfile
from pathlib import Path

import pytest
import psycopg

from rbac_rag.acl.directory import DirectoryStore, DirectoryUser
from rbac_rag.acl.guard import AccessGuard, AccessViolation
from rbac_rag.acl.policy import Policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.config import Settings
from rbac_rag.db.connection import connect
from rbac_rag.db.migrate import migrate
from rbac_rag.pipeline.ingest import load_manifest
from rbac_rag.pipeline.rag import REFUSAL
from rbac_rag.registry import build_pipeline
from rbac_rag.types import Acl, Chunk, Principal, SourceDocument, UserContext


@pytest.fixture
def db_conn():
    db_url = os.environ.get("RBAC_RAG_DATABASE_URL", "postgresql://rag:rag@localhost:5432/rbac_rag")
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


def test_access_violation_propagation(db_conn, sample_policy, sample_directory):
    settings = Settings(embedder="fake", llm="fake")
    ingest_pipeline, retriever, rag_pipeline = build_pipeline(settings, db_conn)

    # Ingest doc for HR manager only
    doc = SourceDocument(
        id="doc_restricted",
        title="Restricted",
        text="Sensitive HR records.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    ingest_pipeline.ingest([doc])

    alice_user = UserContext(user_id="alice")

    # Manually pass a forbidden chunk to AccessGuard to verify it raises AccessViolation
    guard = AccessGuard()
    policy = sample_policy
    subject = policy.subject("alice", groups={"eng"}, roles={"engineer"})

    from rbac_rag.types import RetrievedChunk
    forbidden_chunk = RetrievedChunk(
        chunk_id="doc_restricted:0000",
        document_id="doc_restricted",
        title="Restricted",
        content="Sensitive HR records.",
        classification="confidential",
        score=0.9,
        acl=doc.acl,
    )

    with pytest.raises(AccessViolation):
        guard.check(subject, policy, [forbidden_chunk])


def test_hash_change_detection_and_deletion(db_conn, sample_policy, sample_directory):
    settings = Settings(embedder="fake", llm="fake")
    ingest_pipeline, retriever, _ = build_pipeline(settings, db_conn)
    store = ingest_pipeline.store

    doc = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Initial text content for change detection.",
        classification="internal",
        acl=Acl.from_specs(allow=["role:engineer"]),
    )

    # 1. First ingest
    ingest_pipeline.ingest([doc])
    h1 = store.get_document_hashes("doc_hash_test")
    assert h1 is not None

    # 2. Ingest identical doc -> skipped, hashes unchanged
    res = ingest_pipeline.ingest([doc])
    assert res == []
    h2 = store.get_document_hashes("doc_hash_test")
    assert h1 == h2

    # 3. ACL / classification change only -> same content_hash, new acl_hash
    doc_acl_changed = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Initial text content for change detection.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    res_acl = ingest_pipeline.ingest([doc_acl_changed])
    assert res_acl == ["doc_hash_test"]
    h3 = store.get_document_hashes("doc_hash_test")
    assert h3[0] == h1[0]  # content_hash unchanged
    assert h3[1] != h1[1]  # acl_hash changed

    # 4. Content change -> new content_hash
    doc_content_changed = SourceDocument(
        id="doc_hash_test",
        title="Hash Test",
        text="Updated text content for change detection.",
        classification="confidential",
        acl=Acl.from_specs(allow=["role:hr_manager"]),
    )
    res_content = ingest_pipeline.ingest([doc_content_changed])
    assert res_content == ["doc_hash_test"]
    h4 = store.get_document_hashes("doc_hash_test")
    assert h4[0] != h1[0]

    # 5. Delete document
    store.delete_document("doc_hash_test")
    assert store.get_document_hashes("doc_hash_test") is None
