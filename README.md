# rbac-rag

Pluggable, RBAC-aware RAG on Postgres + pgvector. Each chunk's ACL is stored in
Postgres, and retrieval runs the ACL SQL inside the vector search query, so a user
only ever receives chunks their permission set allows. Policies (roles,
inheritance, group→role mappings, clearances, explicit deny rules) are versioned, and
the schema is managed by numbered migrations. Security evals verify zero leakage offline,
and RAGAS evaluates answer quality with Gemini on Vertex AI.

---

## Quickstart

### 1. Spin up Postgres + pgvector

Start Postgres 16 with pgvector (listening on port `5432`):

```bash
docker compose up -d
```

Set the database connection environment variable:

```bash
export RBAC_RAG_DATABASE_URL="postgresql://rag:rag@localhost:5432/rbac_rag"
```

### 2. Install dependencies

Install `rbac-rag` with evaluation extras using `uv`:

```bash
uv sync --extra evals
```

### 3. Seed database

Seed migrations, directory, policies (v1 and v2), and sample documents into Postgres:

```bash
# Offline mode using fake embedder
uv run python examples/acme/seed.py --fake

# Or live mode using Gemini Embeddings (requires Vertex / Google credentials set)
uv run python examples/acme/seed.py
```

### 4. Run demo queries

Query across multiple personas under Policy v1, compare changes under Policy v2, and test ClaimsAclFilter vs DirectoryAclFilter:

```bash
# Offline mode using fake embedder and fake LLM
uv run python examples/acme/demo.py --fake

# Or live mode using Gemini
uv run python examples/acme/demo.py
```

### 5. Run evaluations

```bash
# Deterministic security evaluation (offline, zero LLM calls)
uv run python evals/security_eval.py --fake

# Quality evaluation using RAGAS + Gemini on Vertex AI
uv run python evals/ragas_eval.py --policy 1
```

---

## Architecture

```mermaid
flowchart TD
    subgraph Ingestion
        A[Documents / Manifest] --> B[Chunker: Markdown / Recursive]
        B -->|Extract section ACLs| C[Chunk Drafts + ACL]
        C --> D[Embedder: Gemini / Fake]
        D --> E[(Postgres: chunks + chunk_acl)]
    end

    subgraph Retrieval & Generation
        F[User Query + UserContext] --> G[SecureRetriever]
        G --> H[AclFilter: Directory / Claims]
        H -->|Generate SQL CTE| I[Single Filtered Vector Query in Postgres]
        E --> I
        I -->|Candidate Chunks| J[Python AccessGuard Policy Oracle]
        J -->|Access Re-verification| K{Authorized?}
        K -- No --> L[AccessViolation Error]
        K -- Yes --> M[LLM: Gemini / Fake]
        M --> N[Answer + Citation & Audit Log]
    end
```

### Retrieval Mechanics

When a user asks a question, `PgVectorStore.secure_search` combines vector similarity search and policy enforcement in a single Postgres SQL query:

```sql
WITH p AS (
    -- Effective principals (user, groups, effective roles via inheritance & group-mapping)
    SELECT * FROM rbac_effective_principals(%(uid)s, %(pv)s)
),
clr AS (
    -- User's maximum clearance level across effective roles
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

---

## ACL Semantics

Access evaluation follows strict deny-by-default logic across 6 rule types:

| Rule / Condition | Behavior / Semantics |
| :--- | :--- |
| **Deny Overrides Allow** | If any matching principal (`user`, `group`, or `role`) has an explicit `deny` in `chunk_acl`, access is denied, even if another principal has an `allow`. |
| **Default Deny** | Access requires at least one matching `allow` rule in `chunk_acl`. Chunks with no matching allow rules are denied. |
| **Clearance Requirement** | The user's maximum clearance level across effective roles must be $\ge$ the required clearance level defined for the chunk's classification in the active policy. |
| **Policy Deny Rules** | Global policy rules can deny specific principals (`user`, `group`, or `role`) access to an entire classification level (e.g. `contractor` restricted from `internal`). |
| **Unknown Classification** | If a chunk's classification label is not defined in the active policy version, access is denied. |
| **Unknown User** | If a user cannot be resolved in the directory (or has no claims), access is denied for all non-public content. |

---

## Extending Components

`rbac-rag` provides Protocol interfaces in `rbac_rag.interfaces`. Custom components can be registered by built-in shorthand name or loaded via `pkg.module:Class` specs.

### Custom `AclFilter` (e.g. Tenant Scoping)

```python
from typing import Any
from rbac_rag.types import UserContext
from rbac_rag.interfaces import SqlFragment, AclFilter

class TenantAclFilter(AclFilter):
    name = "tenant"

    def build(self, user: UserContext, policy_version: int) -> SqlFragment:
        # Use Directory CTE for principal resolution + add tenant extra_where filter
        principals_sql = "SELECT principal_type, principal_name FROM rbac_effective_principals(%(uid)s, %(pv)s)"
        tenant_id = user.attributes.get("tenant_id", "default")
        extra_where = "d.metadata->>'tenant_id' = %(tenant_id)s"
        return SqlFragment(
            principals_sql=principals_sql,
            params={"tenant_id": tenant_id},
            extra_where=extra_where,
        )

    def memberships(self, conn: Any, user: UserContext) -> tuple[set[str], set[str]] | None:
        # Return (groups, roles) directly held by the user
        ...
```

To configure custom classes in settings or environment variables:

```bash
export RBAC_RAG_ACL_FILTER="my_package.module:TenantAclFilter"
export RBAC_RAG_CHUNKER="my_package.module:CustomChunker"
export RBAC_RAG_EMBEDDER="my_package.module:CustomEmbedder"
export RBAC_RAG_LLM="my_package.module:CustomLLM"
```

---

## Policy Versioning Workflow

Policies define roles, inheritance, group-to-role mappings, clearance levels, and policy-wide explicit deny rules. Policies are versioned immutably in Postgres.

1. **Publish a Policy Version:**

```bash
uv run rbac-rag policy publish examples/acme/policy_v2.yaml
# Published policy v2 ('Acme Policy v2')
```

2. **Diff Policy Versions:**

Compare changes between two policy versions before activating:

```bash
uv run rbac-rag policy diff 1 2
```

3. **Evaluate Inactive Policy:**

Run security and quality evals against policy v2 without affecting production users:

```bash
uv run python evals/security_eval.py --policies 1,2
uv run python evals/ragas_eval.py --policy 2
```

4. **Activate Policy Version:**

Promote policy v2 to active status:

```bash
uv run rbac-rag policy activate 2
# Activated policy v2
```

---

## Evals & Reports

`rbac-rag` includes two evaluation suites that write JSON and Markdown reports to `evals/results/`.

### 1. Deterministic Security Eval (`evals/security_eval.py`)

Runs offline without external LLM dependencies.
- **Leakage Rate:** Must be `0.0`. Asserts retrieved chunks $\subseteq$ oracle-authorized chunks for every persona query.
- **Canary Exposures:** Verifies restricted canary strings (e.g. `NIGHTJAR-7731`, `COMPBAND-9921`) never appear in contexts retrieved for unauthorized personas.
- **Access Recall:** Fraction of expected authorized documents retrieved for target persona questions.
- **Policy Delta:** Reports documents gained and lost per persona across policy versions.

### 2. RAGAS Quality Eval (`evals/ragas_eval.py`)

Evaluates pipeline responses using Gemini on Vertex AI.
- **Faithfulness:** Verifies generation is grounded strictly in retrieved context.
- **Answer Relevancy:** Measures question-answer alignment.
- **Context Precision & Recall:** Evaluates context retrieval quality against ground truth references.
- **Refusal Accuracy:** Verifies the model correctly refuses unauthorized queries (`should_refuse: true`).
- **Leakage Critic:** Aspect critic evaluating whether sensitive facts were exposed in generated answers.

---

## Known Limits

- **Filtered HNSW Recall on pgvector:**
  For `pgvector < 0.8`, pre-filtered HNSW searches may exhibit degraded recall (< 0.8) when ACL filters significantly restrict candidate vector sets. On `pgvector >= 0.8`, `rbac-rag` automatically executes retrieval with `SET LOCAL hnsw.iterative_scan = relaxed_order` to maintain high recall during filtered search.
- **Claims Filter Trust:**
  The `ClaimsAclFilter` trusts group and role claims provided directly in the `UserContext` without querying the central user directory table. Downstream authentication infrastructure must validate and sign claims prior to invocation.
- **Author-Controlled Classification Overrides:**
  When chunking markdown documents with section-level ACL annotations (e.g. `<!-- acl: classification=restricted -->`), section classifications are controlled by document content authors. Ingestion pipelines should validate document section classifications against repository compliance constraints.
