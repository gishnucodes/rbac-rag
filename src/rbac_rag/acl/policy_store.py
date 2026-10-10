"""Persist, activate and load versioned policies in Postgres."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import psycopg

from rbac_rag.acl.policy import DenyRule, Policy, RoleDef
from rbac_rag.types import Principal, PrincipalType


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyVersionInfo:
    version: int
    name: str
    description: str
    checksum: str
    is_active: bool
    created_at: datetime
    activated_at: datetime | None


class PolicyStore:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn
        self._cache: dict[int, Policy] = {}

    def publish(self, policy: Policy, *, activate: bool = False) -> bool:
        """Insert ``policy`` as a new immutable version.

        Re-publishing an identical version is a no-op (returns ``False``);
        publishing different content under an existing version number raises.
        """
        checksum = policy.checksum()
        with self.conn.transaction():
            row = self.conn.execute(
                "SELECT checksum FROM policy_versions WHERE version = %s FOR UPDATE",
                (policy.version,),
            ).fetchone()
            if row is not None:
                if row[0] != checksum:
                    raise PolicyError(
                        f"policy v{policy.version} already exists with different content; "
                        "publish changes as a new version"
                    )
                created = False
            else:
                self._insert(policy, checksum)
                created = True
            if activate:
                self._activate(policy.version)
        return created

    def _insert(self, policy: Policy, checksum: str) -> None:
        v = policy.version
        self.conn.execute(
            "INSERT INTO policy_versions (version, name, description, checksum) VALUES (%s, %s, %s, %s)",
            (v, policy.name, policy.description, checksum),
        )
        with self.conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO classification_levels (policy_version, label, required_clearance) VALUES (%s, %s, %s)",
                [(v, label, level) for label, level in policy.classifications.items()],
            )
            cur.executemany(
                "INSERT INTO roles (policy_version, name, clearance, description) VALUES (%s, %s, %s, %s)",
                [(v, r.name, r.clearance, r.description) for r in policy.roles.values()],
            )
            cur.executemany(
                "INSERT INTO role_inheritance (policy_version, role, parent_role) VALUES (%s, %s, %s)",
                [(v, r.name, p) for r in policy.roles.values() for p in r.inherits],
            )
            cur.executemany(
                "INSERT INTO group_roles (policy_version, group_name, role) VALUES (%s, %s, %s)",
                [(v, g, r) for g, roles in policy.groups.items() for r in roles],
            )
            cur.executemany(
                "INSERT INTO policy_deny_rules (policy_version, principal_type, principal_name, classification) "
                "VALUES (%s, %s, %s, %s)",
                [
                    (v, str(d.principal.type), d.principal.name, d.classification)
                    for d in policy.deny_rules
                ],
            )

    def _activate(self, version: int) -> None:
        exists = self.conn.execute(
            "SELECT 1 FROM policy_versions WHERE version = %s", (version,)
        ).fetchone()
        if not exists:
            raise PolicyError(f"policy v{version} does not exist")
        self.conn.execute(
            "UPDATE policy_versions SET is_active = false WHERE is_active AND version <> %s",
            (version,),
        )
        self.conn.execute(
            "UPDATE policy_versions SET is_active = true, activated_at = now() "
            "WHERE version = %s AND NOT is_active",
            (version,),
        )

    def activate(self, version: int) -> None:
        with self.conn.transaction():
            self._activate(version)

    def active_version(self) -> int:
        row = self.conn.execute("SELECT version FROM policy_versions WHERE is_active").fetchone()
        if row is None:
            raise PolicyError("no active policy version; publish one with activate=True")
        return row[0]

    def resolve_version(self, requested: int | None) -> int:
        if requested is None:
            return self.active_version()
        if not self.conn.execute(
            "SELECT 1 FROM policy_versions WHERE version = %s", (requested,)
        ).fetchone():
            raise PolicyError(f"policy v{requested} does not exist")
        return requested

    def list(self) -> list[PolicyVersionInfo]:
        rows = self.conn.execute(
            "SELECT version, name, description, checksum, is_active, created_at, activated_at "
            "FROM policy_versions ORDER BY version"
        ).fetchall()
        return [PolicyVersionInfo(*row) for row in rows]

    def get(self, version: int) -> Policy:
        """Load a policy version. Versions are immutable, so results are cached."""
        if version in self._cache:
            return self._cache[version]
        head = self.conn.execute(
            "SELECT name, description FROM policy_versions WHERE version = %s", (version,)
        ).fetchone()
        if head is None:
            raise PolicyError(f"policy v{version} does not exist")
        q = self.conn.execute
        classifications = dict(
            q("SELECT label, required_clearance FROM classification_levels WHERE policy_version = %s", (version,)).fetchall()
        )
        inherits: dict[str, list[str]] = {}
        for role, parent in q(
            "SELECT role, parent_role FROM role_inheritance WHERE policy_version = %s", (version,)
        ).fetchall():
            inherits.setdefault(role, []).append(parent)
        roles = {
            name: RoleDef(name, clearance, tuple(sorted(inherits.get(name, []))), description)
            for name, clearance, description in q(
                "SELECT name, clearance, description FROM roles WHERE policy_version = %s", (version,)
            ).fetchall()
        }
        groups: dict[str, list[str]] = {}
        for group, role in q(
            "SELECT group_name, role FROM group_roles WHERE policy_version = %s", (version,)
        ).fetchall():
            groups.setdefault(group, []).append(role)
        deny_rules = tuple(
            sorted(
                DenyRule(Principal(PrincipalType(t), n), c)
                for t, n, c in q(
                    "SELECT principal_type, principal_name, classification FROM policy_deny_rules "
                    "WHERE policy_version = %s",
                    (version,),
                ).fetchall()
            )
        )
        policy = Policy(
            version=version,
            name=head[0],
            description=head[1],
            classifications=classifications,
            roles=roles,
            groups={g: tuple(sorted(rs)) for g, rs in groups.items()},
            deny_rules=deny_rules,
        )
        self._cache[version] = policy
        return policy
