# rbac-rag

Pluggable, RBAC-aware RAG on Postgres + pgvector. Each chunk's ACL is stored in
Postgres, and retrieval runs the ACL SQL inside the vector search, so a user
only ever receives chunks their permission set allows. Policies (roles,
inheritance, group→role mappings, clearances, deny rules) are versioned, and
the schema is managed by numbered migrations. Evals use RAGAS with Gemini on
Vertex AI.

**Status:** work in progress. See [docs/DESIGN.md](docs/DESIGN.md) for the
architecture and the GitHub issues for the remaining work.

## Dev quickstart

```bash
uv sync --extra evals
# Postgres 16 with pgvector >= 0.6, e.g. docker run -p 5432:5432 -e POSTGRES_USER=rag \
#   -e POSTGRES_PASSWORD=rag -e POSTGRES_DB=rbac_rag pgvector/pgvector:pg16
export RBAC_RAG_DATABASE_URL=postgresql://rag:rag@localhost:5432/rbac_rag
```
