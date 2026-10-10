"""Pluggable ACL SQL.

An ACL filter decides *where the caller's principals come from*; the store
then applies chunk ACLs, policy deny rules and classification clearance to
them inside the vector search query. Write your own by implementing
:class:`rbac_rag.interfaces.AclFilter`.
"""

from __future__ import annotations

from typing import Any

from rbac_rag.acl.directory import DirectoryStore
from rbac_rag.interfaces import SqlFragment
from rbac_rag.types import UserContext


class DirectoryAclFilter:
    """Principals are resolved in-database from the ``users`` /
    ``user_groups`` / ``user_roles`` tables. Unknown users see nothing."""

    name = "directory"

    def build(self, user: UserContext, policy_version: int) -> SqlFragment:
        return SqlFragment(
            principals_sql=(
                "SELECT principal_type, principal_name "
                "FROM rbac_effective_principals(%(acl_user)s, %(acl_pv)s)"
            ),
            params={"acl_user": user.user_id, "acl_pv": policy_version},
        )

    def memberships(self, conn: Any, user: UserContext) -> tuple[set[str], set[str]] | None:
        found = DirectoryStore(conn).get(user.user_id)
        if found is None:
            return None
        return set(found.groups), set(found.roles)


class ClaimsAclFilter:
    """Principals come from caller-supplied claims (e.g. groups/roles in a
    verified IdP token) instead of the directory tables. Role inheritance
    and group->role mapping are still taken from the policy version.

    Only use this with claims you have verified: the claims *are* the
    permission set."""

    name = "claims"

    def build(self, user: UserContext, policy_version: int) -> SqlFragment:
        return SqlFragment(
            principals_sql=(
                "SELECT principal_type, principal_name "
                "FROM rbac_principals_for(%(acl_user)s, %(acl_roles)s, %(acl_groups)s, %(acl_pv)s)"
            ),
            params={
                "acl_user": user.user_id,
                "acl_roles": list(user.roles),
                "acl_groups": list(user.groups),
                "acl_pv": policy_version,
            },
        )

    def memberships(self, conn: Any, user: UserContext) -> tuple[set[str], set[str]] | None:
        return set(user.groups), set(user.roles)
