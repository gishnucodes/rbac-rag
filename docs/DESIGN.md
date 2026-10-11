# RBAC-aware RAG on Postgres + pgvector

## Overview
`rbac-rag` is a pluggable, RBAC-aware Retrieval-Augmented Generation (RAG) framework built on Postgres and `pgvector`.
- **Chunk-Level ACL:** Each document chunk's Access Control List (ACL) is stored directly in Postgres (`chunk_acl`).
- **Single-Query Filtered Search:** Vector similarity search and ACL evaluation happen in a single SQL query inside Postgres, ensuring unauthorized chunks are never returned from vector search.
- **Defense in Depth:** Retrieved chunks are re-evaluated in Python by a policy oracle before being passed to the LLM. Access violations trigger immediate rejection.
- **Versioned Policies & Schema:** Policy definitions (roles, inheritance, group-to-role mappings, clearance levels, explicit deny rules) are published as immutable versions. Database schema changes are managed via numbered migrations.
- **Pluggable Architecture:** Interfaces for `Chunker`, `Embedder`, `LLM`, and `AclFilter` allow swapping built-in components (e.g. Gemini, fake/hashing implementations) or loading custom classes dynamically via Python module entrypoints (`pkg.module:Class`).

## Stack
- **Language & Package Manager:** Python 3.12+, `uv`
- **Database & Search:** Postgres 16 + `pgvector`, `psycopg` 3 raw SQL queries
- **Data Models & Settings:** `pydantic` v2, `pydantic-settings`, PyYAML
- **AI / Embeddings / LLM:** `google-genai` (Gemini 2.5 Flash, Gemini Embedding 001 with 768 dimensions), fake hashing/extractive components for offline execution
- **Evaluation:** RAGAS 0.4 API with Gemini on Vertex AI, deterministic security evaluator

## Repository Structure
```
pyproject.toml, docker-compose.yml, .env.example, README.md
src/rbac_rag/
  config.py            # Settings loaded from environment / .env
  types.py             # UserContext, Document, Chunk, Acl, RetrievedChunk, Answer
  interfaces.py        # Chunker, Embedder, LLM, AclFilter, ChunkStore Protocols
  registry.py          # Component factories and build_pipeline helper
  google_client.py     # Vertex AI / Google GenAI SDK client setup
  cli.py               # Typer CLI (`rbac-rag migrate`, `policy`, `directory`, `ask`, etc.)
  db/
    connection.py      # Database connection factory
    migrate.py         # Schema migration engine
    migrations/        # 0001_core.sql, 0002_policy.sql, 0003_acl_functions.sql
  chunking/            # MarkdownChunker (with section ACLs), RecursiveChunker
  embeddings/          # GeminiEmbedder, HashingEmbedder (fake)
  llm/                 # GeminiLLM, ExtractiveLLM (fake)
  acl/                 # Policy model, DirectoryStore, PolicyStore, DirectoryAclFilter, ClaimsAclFilter, AccessGuard
  store/               # PgVectorStore (upsert, secure vector search)
  pipeline/            # IngestionPipeline, SecureRetriever, RAGPipeline
examples/acme/
  docs/*.md            # Sample corpus documents
  acl.yaml             # Manifest mapping files to ACLs and classifications
  directory.yaml       # User-group-role directory mappings
  policy_v1.yaml       # Initial policy version
  policy_v2.yaml       # Updated policy version (stricter contractor rules, new roles)
  seed.py, demo.py     # Database seeding and persona query demo scripts
evals/
  dataset.yaml         # Test dataset (persona, question, expected_doc_ids, canaries)
  security_eval.py     # Deterministic security & canary evaluation
  ragas_eval.py        # RAGAS metrics & leakage critic evaluation
  report.py            # Report formatting (JSON + Markdown in evals/results/)
tests/                 # Pytest test suite
```

## Data Model & Migrations
- `schema_migrations(version, name, applied_at)` tracks applied database migrations.
- **Policy Tables:**
  - `policy_versions(id, version, name, description, checksum, created_at, is_active)`
  - `roles(policy_version_id, name, clearance, description)`
  - `role_inheritance(policy_version_id, role_name, parent_role_name)`
  - `group_roles(policy_version_id, group_name, role_name)`
  - `classification_levels(policy_version_id, label, required_clearance)`
  - `policy_deny_rules(policy_version_id, principal_type, principal_name, classification)`
- **Directory Tables:**
  - `users(id, username, attributes)`
  - `user_groups(user_id, group_name)`
  - `user_roles(user_id, role_name)`
- **Document & Chunk Tables:**
  - `documents(id, source_uri, title, classification, content_hash, metadata)`
  - `chunks(id, document_id, ordinal, content, classification, embedding vector(768), metadata)` with an HNSW cosine index (`vector_cosine_ops`).
  - `chunk_acl(chunk_id, principal_type, principal_name, effect)` with indices on `chunk_id` and `(principal_type, principal_name)`.

## Single-Query Vector Retrieval SQL
During retrieval, `PgVectorStore.secure_search()` combines vector distance with ACL CTE filtering:
```sql
WITH p AS (
    -- Effective principals resolved for the user under active or requested policy version
    SELECT * FROM rbac_effective_principals(%(uid)s, %(pv)s)
),
clr AS (
    -- Maximum clearance level across effective roles
    SELECT rbac_user_clearance(%(uid)s, %(pv)s) AS lvl
)
SELECT c.id, c.document_id, c.ordinal, c.content, c.classification,
       d.title, d.source_uri,
       1 - (c.embedding <=> %(q_emb)s) AS score
FROM chunks c
JOIN documents d ON d.id = c.document_id
JOIN classification_levels cl ON cl.policy_version_id = %(pv)s AND cl.label = c.classification
WHERE EXISTS (
    SELECT 1 FROM chunk_acl a
    JOIN p ON p.principal_type = a.principal_type AND p.principal_name = a.principal_name
    WHERE a.chunk_id = c.id AND a.effect = 'allow'
)
AND NOT EXISTS (
    SELECT 1 FROM chunk_acl a
    JOIN p ON p.principal_type = a.principal_type AND p.principal_name = a.principal_name
    WHERE a.chunk_id = c.id AND a.effect = 'deny'
)
AND NOT EXISTS (
    SELECT 1 FROM policy_deny_rules r
    JOIN p ON p.principal_type = r.principal_type AND p.principal_name = r.principal_name
    WHERE r.policy_version_id = %(pv)s AND r.classification = c.classification
)
AND cl.required_clearance <= (SELECT lvl FROM clr)
ORDER BY c.embedding <=> %(q_emb)s
LIMIT %(k)s;
```

## Security & Quality Evals
1. **Deterministic Security Evaluation (`evals/security_eval.py`):**
   - Runs offline using the fake embedder/LLM.
   - Verifies zero leakage (`retrieved_chunks ⊆ authorized_chunks`) across all persona queries.
   - Scans retrieved context for forbidden canary strings (e.g. `NIGHTJAR-7731`).
   - Computes Access Recall against target persona expectation sets.
   - Calculates access delta between policy versions (v1 vs v2).
2. **RAGAS Quality Evaluation (`evals/ragas_eval.py`):**
   - Evaluates answer quality using Gemini 2.5 Flash as judge via Vertex AI / Google GenAI.
   - Metrics: Faithfulness, Answer Relevancy, Context Precision, Context Recall.
   - Refusal Accuracy for non-authorized queries (`should_refuse: true`).
   - Leakage Critic judge detecting sensitive fact exposures in generated answers.
