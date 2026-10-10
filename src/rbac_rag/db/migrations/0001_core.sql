-- Core content + directory schema.
-- {{EMBEDDING_DIM}} is rendered by rbac_rag.db.migrate from settings.

CREATE EXTENSION IF NOT EXISTS vector;

-- Records deployment-wide invariants (e.g. the embedding dimension the
-- chunks table was created with) so a mismatched embedder fails fast.
CREATE TABLE rag_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO rag_meta (key, value) VALUES ('embedding_dim', '{{EMBEDDING_DIM}}');

-- Directory: the identity source. Not policy-versioned; swap it for an IdP
-- by using the claims ACL filter instead of the directory one.
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    display_name TEXT,
    attributes   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE user_groups (
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    PRIMARY KEY (user_id, group_name)
);

CREATE TABLE user_roles (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    PRIMARY KEY (user_id, role_name)
);

CREATE TABLE documents (
    id             TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    source_uri     TEXT,
    classification TEXT NOT NULL,
    -- content_hash covers text + chunker config (drives re-embedding);
    -- acl_hash covers ACL + classification (drives ACL-only rewrites).
    content_hash   TEXT NOT NULL,
    acl_hash       TEXT NOT NULL,
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Classification lives on the chunk (defaulting to the document's) so a
-- single section can be more sensitive than the rest of its document.
CREATE TABLE chunks (
    id             TEXT PRIMARY KEY,
    document_id    TEXT NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    ordinal        INT  NOT NULL,
    content        TEXT NOT NULL,
    classification TEXT NOT NULL,
    embedding      vector({{EMBEDDING_DIM}}) NOT NULL,
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (document_id, ordinal)
);

CREATE INDEX chunks_embedding_hnsw ON chunks USING hnsw (embedding vector_cosine_ops);

-- Per-chunk ACL. Deny-by-default: a chunk is readable only with a matching
-- 'allow' and no matching 'deny'.
CREATE TABLE chunk_acl (
    chunk_id       TEXT NOT NULL REFERENCES chunks (id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'group', 'role')),
    principal_name TEXT NOT NULL,
    effect         TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    PRIMARY KEY (chunk_id, principal_type, principal_name, effect)
);

CREATE INDEX chunk_acl_principal_idx
    ON chunk_acl (principal_type, principal_name, effect, chunk_id);
