-- Principal expansion lives in SQL so retrieval can resolve permissions and
-- run the vector search in a single round trip.

-- Expand a set of directly-held roles and groups into the full set of
-- effective roles under a policy version (group->role mapping, then the
-- transitive closure of role inheritance). Roles not defined in the version
-- are dropped. UNION (not UNION ALL) makes inheritance cycles terminate.
CREATE OR REPLACE FUNCTION rbac_expand_roles(p_roles TEXT[], p_groups TEXT[], p_version INT)
RETURNS TABLE (role TEXT)
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE seed AS (
        SELECT unnest(COALESCE(p_roles, '{}'::TEXT[])) AS role
        UNION
        SELECT gr.role
        FROM group_roles gr
        WHERE gr.policy_version = p_version
          AND gr.group_name = ANY (COALESCE(p_groups, '{}'::TEXT[]))
    ),
    closure AS (
        SELECT r.name AS role
        FROM seed s
        JOIN roles r ON r.policy_version = p_version AND r.name = s.role
        UNION
        SELECT ri.parent_role
        FROM closure c
        JOIN role_inheritance ri ON ri.policy_version = p_version AND ri.role = c.role
    )
    SELECT role FROM closure
$$;

-- Effective principals for an explicit identity (user id + claimed groups
-- and roles), e.g. from an IdP token.
CREATE OR REPLACE FUNCTION rbac_principals_for(p_user TEXT, p_roles TEXT[], p_groups TEXT[], p_version INT)
RETURNS TABLE (principal_type TEXT, principal_name TEXT)
LANGUAGE sql STABLE AS $$
    SELECT 'user'::TEXT, p_user
    UNION
    SELECT 'group'::TEXT, g FROM unnest(COALESCE(p_groups, '{}'::TEXT[])) AS g
    UNION
    SELECT 'role'::TEXT, e.role FROM rbac_expand_roles(p_roles, p_groups, p_version) e
$$;

-- Effective principals for a user known to the directory. Unknown users get
-- no principals and therefore see nothing.
CREATE OR REPLACE FUNCTION rbac_effective_principals(p_user TEXT, p_version INT)
RETURNS TABLE (principal_type TEXT, principal_name TEXT)
LANGUAGE sql STABLE AS $$
    SELECT p.principal_type, p.principal_name
    FROM users u,
         rbac_principals_for(
             u.id,
             ARRAY(SELECT role_name FROM user_roles WHERE user_id = u.id),
             ARRAY(SELECT group_name FROM user_groups WHERE user_id = u.id),
             p_version
         ) p
    WHERE u.id = p_user
$$;

-- Highest clearance across a principal set's roles (0 when none).
CREATE OR REPLACE FUNCTION rbac_clearance(p_roles TEXT[], p_version INT)
RETURNS INT
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(MAX(r.clearance), 0)
    FROM roles r
    WHERE r.policy_version = p_version
      AND r.name = ANY (COALESCE(p_roles, '{}'::TEXT[]))
$$;

CREATE OR REPLACE FUNCTION rbac_active_policy_version()
RETURNS INT
LANGUAGE sql STABLE AS $$
    SELECT version FROM policy_versions WHERE is_active
$$;
