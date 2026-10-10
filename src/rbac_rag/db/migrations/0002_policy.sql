-- Versioned access policy. A policy version is an immutable snapshot of the
-- role catalogue, role inheritance, group->role mapping, classification
-- clearances and deny rules. Publishing inserts a new version; exactly one
-- version is active, and any version can be queried explicitly.

CREATE TABLE policy_versions (
    version      INT PRIMARY KEY CHECK (version > 0),
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    checksum     TEXT NOT NULL,
    is_active    BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX policy_versions_one_active
    ON policy_versions ((true)) WHERE is_active;

CREATE TABLE roles (
    policy_version INT  NOT NULL REFERENCES policy_versions (version) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    clearance      INT  NOT NULL DEFAULT 0,
    description    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (policy_version, name)
);

-- role inherits every permission granted to parent_role.
CREATE TABLE role_inheritance (
    policy_version INT  NOT NULL,
    role           TEXT NOT NULL,
    parent_role    TEXT NOT NULL,
    PRIMARY KEY (policy_version, role, parent_role),
    FOREIGN KEY (policy_version, role) REFERENCES roles (policy_version, name) ON DELETE CASCADE,
    FOREIGN KEY (policy_version, parent_role) REFERENCES roles (policy_version, name) ON DELETE CASCADE
);

CREATE TABLE group_roles (
    policy_version INT  NOT NULL,
    group_name     TEXT NOT NULL,
    role           TEXT NOT NULL,
    PRIMARY KEY (policy_version, group_name, role),
    FOREIGN KEY (policy_version, role) REFERENCES roles (policy_version, name) ON DELETE CASCADE
);

-- A chunk whose classification is not listed in the policy version is
-- unreadable under that version (deny-by-default).
CREATE TABLE classification_levels (
    policy_version     INT  NOT NULL REFERENCES policy_versions (version) ON DELETE CASCADE,
    label              TEXT NOT NULL,
    required_clearance INT  NOT NULL,
    PRIMARY KEY (policy_version, label)
);

-- Blanket denial of a classification to a principal, e.g. contractors may
-- never read 'confidential' content regardless of chunk-level grants.
CREATE TABLE policy_deny_rules (
    policy_version INT  NOT NULL REFERENCES policy_versions (version) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'group', 'role')),
    principal_name TEXT NOT NULL,
    classification TEXT NOT NULL,
    PRIMARY KEY (policy_version, principal_type, principal_name, classification)
);
