import random
import pytest
from rbac_rag.acl.directory import DirectoryStore, DirectoryUser
from rbac_rag.acl.policy import Policy, RoleDef
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.types import Principal, PrincipalType

pytestmark = pytest.mark.db


def generate_random_policy_and_directory(seed: int):
    rng = random.Random(seed)

    # Generate roles
    num_roles = rng.randint(3, 10)
    role_names = [f"role_{i}" for i in range(num_roles)]

    roles = {}
    for rname in role_names:
        clearance = rng.randint(0, 100)
        # Random parent roles (can include cycles)
        possible_parents = [p for p in role_names if p != rname]
        num_parents = rng.randint(0, min(2, len(possible_parents)))
        inherits = tuple(rng.sample(possible_parents, num_parents)) if possible_parents else ()
        roles[rname] = RoleDef(name=rname, clearance=clearance, inherits=inherits)

    # Generate groups
    num_groups = rng.randint(2, 6)
    group_names = [f"group_{g}" for g in range(num_groups)]
    groups = {}
    for gname in group_names:
        num_groles = rng.randint(0, 3)
        groups[gname] = tuple(rng.sample(role_names, num_groles))

    # Generate policy
    classifications = {"public": 0, "internal": 50, "secret": 100}
    policy = Policy(
        version=seed,
        name=f"random_policy_{seed}",
        classifications=classifications,
        roles=roles,
        groups=groups,
    )

    # Generate users in directory
    num_users = rng.randint(5, 12)
    users = []
    for u_idx in range(num_users):
        uid = f"user_{seed}_{u_idx}"
        user_groups = set(rng.sample(group_names, rng.randint(0, len(group_names))))
        user_roles = set(rng.sample(role_names, rng.randint(0, len(role_names))))
        users.append(DirectoryUser(id=uid, groups=frozenset(user_groups), roles=frozenset(user_roles)))

    # Include an unknown user not in directory
    unknown_user_id = f"unknown_user_{seed}"

    return policy, users, unknown_user_id


def test_sql_principals_and_clearance_property(db_conn):
    policy_store = PolicyStore(db_conn)
    dir_store = DirectoryStore(db_conn)

    # Run property tests with fixed seeds
    for seed in range(101, 106):
        policy, users, unknown_user_id = generate_random_policy_and_directory(seed)

        # Publish policy and sync users to directory
        policy_store.publish(policy, activate=True)
        dir_store.sync({u.id: u for u in users})

        # Test each known user in directory
        for user in users:
            # 1. Evaluate via Python Policy.subject(...)
            py_subj = policy.subject(
                user_id=user.id,
                groups=set(user.groups),
                roles=set(user.roles),
            )

            # 2. Evaluate SQL rbac_effective_principals(user_id, version)
            sql_principals_rows = db_conn.execute(
                "SELECT principal_type, principal_name FROM rbac_effective_principals(%s, %s)",
                (user.id, policy.version),
            ).fetchall()

            sql_principals = {
                Principal(PrincipalType(ptype), pname)
                for ptype, pname in sql_principals_rows
            }

            assert sql_principals == py_subj.principals, (
                f"Mismatch in effective principals for user {user.id} under policy seed {seed}:\n"
                f"SQL: {sql_principals}\nPy: {py_subj.principals}"
            )

            # 3. Evaluate SQL rbac_clearance(effective_roles, version)
            eff_roles_list = list(py_subj.effective_roles)
            sql_clearance = db_conn.execute(
                "SELECT rbac_clearance(%s, %s)",
                (eff_roles_list, policy.version),
            ).fetchone()[0]

            assert sql_clearance == py_subj.clearance, (
                f"Mismatch in clearance for user {user.id} under policy seed {seed}:\n"
                f"SQL: {sql_clearance}\nPy: {py_subj.clearance}"
            )

        # Test unknown user
        sql_unknown_principals = db_conn.execute(
            "SELECT principal_type, principal_name FROM rbac_effective_principals(%s, %s)",
            (unknown_user_id, policy.version),
        ).fetchall()

        assert sql_unknown_principals == [], "Unknown user must return no principals from SQL"
