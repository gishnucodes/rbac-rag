# RBAC-aware RAG on Postgres + pgvector, with versioned policies and RAGAS evals

## Context
The repo (`gishnucodes/rbac-rag`, branch `claude/epic-lovelace-cucmn2`) is empty. You want a RAG framework where:
- documents are chunked, and **each chunk's ACL is stored in Postgres**;
- retrieval **adds ACL SQL to the vector search**, so a user only gets chunks their permission set allows;
- the parts are **pluggable** (chunker, embedder, LLM, where user memberships come from, the ACL SQL itself);
- **policy and schema are versioned**: role hierarchy, group→role mappings, clearances and deny rules are published as numbered policy versions; the DB schema is managed by numbered migrations;
- there's a runnable **example corpus** and **RAGAS evals** that check answer quality and that nothing leaks.

Decisions from your answers: pgvector in the same Postgres (one query does vector search and ACL filtering), roles + groups + explicit deny + classification clearance, versioned policies/schema (not document versions), and Gemini on Vertex AI for the LLM, embeddings and the RAGAS judge.

## Stack
Python 3.12+, `uv` project, `psycopg` 3 + `pgvector` (raw SQL so the ACL SQL is easy to see), `pydantic` / `pydantic-settings`, `PyYAML`, `google-genai` (Vertex: `GOOGLE_API_KEY` or `GOOGLE_CLOUD_PROJECT` + ADC, `GOOGLE_GENAI_USE_VERTEXAI=true`), `ragas` + `langchain-google-genai` wrappers for the judge (I'll check the exact ragas/Gemini wrapper API when I implement). Postgres comes from `docker-compose.yml` using the `pgvector/pgvector:pg16` image. Default models, overridable by env: `gemini-2.5-flash` for generation and judging, `gemini-embedding-001` with `output_dimensionality=768` (HNSW indexes cap at 2000 dims).

## Layout
```
pyproject.toml, docker-compose.yml, .env.example, README.md
src/rbac_rag/
  config.py            # Settings (DB url, model names, dims, k, active policy override)
  types.py             # UserContext, Document, Chunk, AclEntry, RetrievedChunk, Answer
  interfaces.py        # Protocols: Chunker, Embedder, LLM, PrincipalResolver, AclFilter, ChunkStore
  registry.py          # name -> implementation factories; build_pipeline(settings)
  db/migrate.py        # applies db/migrations/NNNN_*.sql in order, records them in schema_migrations
  db/migrations/0001_core.sql, 0002_policy.sql, 0003_acl_functions.sql
  chunking/recursive.py   # size/overlap recursive splitter
  chunking/markdown.py    # heading-aware; reads `<!-- acl: ... -->` section overrides
  embeddings/gemini.py, embeddings/fake.py   # fake = deterministic hashing embedder for offline tests
  llm/gemini.py, llm/fake.py
  acl/policy.py           # Policy model + YAML loader + Python reference evaluator (the "oracle")
  acl/policy_store.py     # publish / activate / list / diff policy versions in Postgres
  acl/resolvers.py        # PostgresDirectoryResolver (default), StaticResolver (YAML/dict)
  acl/sql_filter.py       # DefaultAclFilter -> SQL fragment + params (the pluggable ACL SQL)
  store/pgvector_store.py # upsert documents/chunks/chunk_acl; secure_search()
  pipeline/ingest.py      # IngestionPipeline: load -> chunk -> attach ACL -> embed -> store
  pipeline/retriever.py   # SecureRetriever: resolve principals -> filtered vector SQL -> post-check guard
  pipeline/rag.py         # RAGPipeline: retrieve -> prompt (cite only given context, refuse otherwise) -> answer
  cli.py                  # `rbac-rag migrate | policy publish/activate/list | ingest | ask --user`
examples/acme/
  docs/*.md               # handbook (public), eng runbook, HR comp bands, finance Q3, legal M&A memo, mixed-ACL doc
  acl.yaml                # per-doc grants/denies + classification
  directory.yaml          # users -> groups/roles (alice eng, bob HR mgr, carol CFO, dave intern, erin contractor)
  policy_v1.yaml, policy_v2.yaml   # v2 example: contractors lose `internal`, finance_analyst inherits auditor
  seed.py, demo.py        # seed DB; ask the same question as each persona, then under v1 vs v2
evals/
  dataset.yaml            # persona, question, reference answer, expected_doc_ids, should_refuse, forbidden_canaries
  security_eval.py        # deterministic, no LLM
  ragas_eval.py           # RAGAS metrics + leakage critic
  report.py               # JSON + markdown summary to evals/results/
tests/ test_chunking.py, test_policy.py, test_migrations.py, test_secure_retrieval.py, test_policy_versions.py
```

## Data model (migrations)
- `schema_migrations(version, name, applied_at)`
- **Policy, versioned:** `policy_versions(id, version, name, description, created_at, is_active)` with a partial unique index so only one version is active. Under each version: `roles(policy_version_id, name, clearance)`, `role_inheritance(pv, role, parent_role)`, `group_roles(pv, group_name, role)`, `classification_levels(pv, label, required_clearance)`, `policy_deny_rules(pv, principal_type, principal_name, classification)` (deny a principal everything at a classification). Publishing a new version is an insert; old versions stay readable for audit and A/B evals.
- **Directory, not versioned** (an identity source; can be swapped for an IdP through `PrincipalResolver`): `users(id, username, attributes jsonb)`, `user_groups`, `user_roles`.
- **Content:** `documents(id, source_uri, title, classification, content_hash, metadata)`, `chunks(id, document_id, ordinal, content, embedding vector(768), metadata)` with an HNSW cosine index.
- **Per-chunk ACL:** `chunk_acl(chunk_id, principal_type in {role,group,user}, principal_name, effect in {allow,deny})`, indexed on `(principal_type, principal_name)`. Chunks inherit the document ACL at ingest; markdown section overrides narrow or extend it per chunk.
- **SQL functions** (0003): `rbac_effective_principals(user_id, pv)` is a recursive CTE that expands user roles, group→roles and role inheritance into the `(type, name)` set; `rbac_user_clearance(user_id, pv)` returns the max clearance over effective roles.

## Retrieval: ACL SQL added to the vector search
`DefaultAclFilter.build(user, policy_version)` returns a fragment that `pgvector_store.secure_search` puts into one query:
```sql
WITH p AS (SELECT * FROM rbac_effective_principals(%(uid)s, %(pv)s)),
     clr AS (SELECT rbac_user_clearance(%(uid)s, %(pv)s) AS lvl)
SELECT c.id, c.content, d.title, 1 - (c.embedding <=> %(q)s) AS score
FROM chunks c JOIN documents d ON d.id = c.document_id
JOIN classification_levels cl ON cl.policy_version_id = %(pv)s AND cl.label = d.classification
WHERE EXISTS (SELECT 1 FROM chunk_acl a JOIN p USING (principal_type, principal_name)
              WHERE a.chunk_id = c.id AND a.effect = 'allow')
  AND NOT EXISTS (SELECT 1 FROM chunk_acl a JOIN p USING (principal_type, principal_name)
              WHERE a.chunk_id = c.id AND a.effect = 'deny')
  AND NOT EXISTS (SELECT 1 FROM policy_deny_rules r JOIN p USING (principal_type, principal_name)
              WHERE r.policy_version_id = %(pv)s AND r.classification = d.classification)
  AND cl.required_clearance <= (SELECT lvl FROM clr)
ORDER BY c.embedding <=> %(q)s LIMIT %(k)s;
```
- Deny always wins and the default is deny: no matching allow means no access.
- Filtered HNSW can return too few rows, so the query runs with `SET LOCAL hnsw.iterative_scan = relaxed_order` (pgvector ≥0.8).
- **Defense in depth:** after the query, `SecureRetriever` re-checks each returned chunk against the Python policy oracle and raises `AccessViolation` on any mismatch. The prompt only ever contains authorized chunks, and the model is told to say it lacks the information rather than guess.
- Every retrieval logs `user, policy_version, chunk_ids` for audit.
- Pluggability: any `AclFilter` (for example an ABAC filter later) can replace the SQL fragment; resolvers, chunkers, embedders and LLMs are picked by name in config through `registry.py`.

## Evals
1. **Security eval** (`security_eval.py`, deterministic, runs offline with the fake embedder): for every persona × question, compute the authorized chunk set with the Python oracle, independently of the SQL. Assert retrieved ⊆ authorized (**leakage rate must be 0**), report access recall (expected authorized docs that were retrieved), and check that no `forbidden_canaries` (unique strings planted in restricted docs, e.g. `NIGHTJAR-7731`) show up in contexts. Runs under both policy v1 and v2, and reports the access change between them.
2. **RAGAS eval** (`ragas_eval.py`, Gemini judge): build an `EvaluationDataset` of `SingleTurnSample(user_input, retrieved_contexts, response, reference)` per persona. Metrics: Faithfulness, ResponseRelevancy, LLMContextPrecisionWithReference, LLMContextRecall, plus an `AspectCritic` "confidential-leakage" judge and a refusal-correctness check for `should_refuse` rows (for example the intern asking about comp bands should get "I don't have access to that information"). Results go to `evals/results/<timestamp>_<policy>.json` with a markdown summary that breaks scores down per persona.

## Implementation order
1. Scaffold the uv project, docker-compose, settings, migrations runner, and migrations 0001–0003.
2. Write the types and interfaces, then the chunkers and the fake and Gemini embedders and LLMs.
3. Build the policy model, YAML loader and oracle; the policy store (publish/activate/diff); the resolvers; the SQL filter; the pgvector store; the ingest, retriever and RAG pipelines; the CLI.
4. Write the example corpus with canaries, ACL, directory, policies v1 and v2, `seed.py` and `demo.py`.
5. Write the security eval, the RAGAS eval and the report, then the tests and the README (architecture, how to plug in components, how to run).
6. Commit and push to `claude/epic-lovelace-cucmn2` (no PR unless you ask).

## Verification
- `docker compose up -d` (or install `postgresql-16-pgvector` locally if docker isn't usable here), then `uv run rbac-rag migrate` and run it again to confirm re-running changes nothing.
- `uv run pytest`: unit tests plus DB integration tests with the fake embedder. The tests check: deny overrides allow, inheritance, group→role, clearance, per-chunk override, a v1→v2 switch changing results, and retrieval never returning an unauthorized chunk even when it is the closest vector.
- `uv run python examples/acme/seed.py && uv run python examples/acme/demo.py --fake`: the same question gives different contexts per persona.
- `uv run python evals/security_eval.py --fake`: leakage = 0 under v1 and v2.
- With Vertex credentials set (`GOOGLE_API_KEY` or project + ADC): `uv run python evals/ragas_eval.py` produces a RAGAS report. No Google credentials are set in this container, so the live Gemini/RAGAS run needs the key added as an environment secret. Until then, I can only check that run up to the point of the API call.
