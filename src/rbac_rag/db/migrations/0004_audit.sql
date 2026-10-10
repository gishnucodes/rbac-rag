-- Append-only audit trail of what each user was served, under which policy.
CREATE TABLE retrieval_audit (
    id             BIGSERIAL PRIMARY KEY,
    at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id        TEXT NOT NULL,
    policy_version INT  NOT NULL,
    acl_filter     TEXT NOT NULL,
    query          TEXT NOT NULL,
    chunk_ids      TEXT[] NOT NULL
);

CREATE INDEX retrieval_audit_user_idx ON retrieval_audit (user_id, at DESC);
