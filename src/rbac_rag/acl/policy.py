"""Access policy model, YAML loader and a pure-Python reference evaluator.

The evaluator implements exactly the semantics the SQL enforces; it is used
by the post-retrieval guard, by ``rbac-rag explain`` and by the security eval
as an independent oracle.

Semantics, for a user with direct groups G and roles R under policy P:

* effective roles  = closure over P.inherits of (R ∪ P.groups[g] for g in G),
  restricted to roles defined in P
* principals       = {user:<id>} ∪ {group:g | g ∈ G} ∪ {role:r | r ∈ effective roles}
* clearance        = max clearance of effective roles (0 if none)
* a chunk with classification C and ACL (allow, deny) is readable iff
  C is defined in P, clearance >= P.classifications[C],
  no policy deny rule matches (principal, C), no ACL deny matches a principal,
  and at least one ACL allow matches a principal.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rbac_rag.types import Acl, Principal, PrincipalType


@dataclass(frozen=True)
class RoleDef:
    name: str
    clearance: int = 0
    inherits: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, order=True)
class DenyRule:
    principal: Principal
    classification: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class Policy:
    version: int
    name: str
    classifications: dict[str, int]
    roles: dict[str, RoleDef]
    groups: dict[str, tuple[str, ...]] = field(default_factory=dict)
    deny_rules: tuple[DenyRule, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        self.validate()

    # -- construction -----------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        roles = {
            name: RoleDef(
                name=name,
                clearance=int((spec or {}).get("clearance", 0)),
                inherits=tuple((spec or {}).get("inherits", [])),
                description=(spec or {}).get("description", ""),
            )
            for name, spec in (data.get("roles") or {}).items()
        }
        return cls(
            version=int(data["version"]),
            name=data.get("name", f"v{data['version']}"),
            description=data.get("description", ""),
            classifications={k: int(v) for k, v in (data.get("classifications") or {}).items()},
            roles=roles,
            groups={g: tuple(rs or []) for g, rs in (data.get("groups") or {}).items()},
            deny_rules=tuple(
                sorted(
                    DenyRule(Principal.parse(rule["principal"]), rule["classification"])
                    for rule in data.get("deny_rules") or []
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "classifications": dict(sorted(self.classifications.items())),
            "roles": {
                name: {
                    "clearance": r.clearance,
                    "inherits": sorted(r.inherits),
                    "description": r.description,
                }
                for name, r in sorted(self.roles.items())
            },
            "groups": {g: sorted(rs) for g, rs in sorted(self.groups.items())},
            "deny_rules": [
                {"principal": str(r.principal), "classification": r.classification}
                for r in self.deny_rules
            ],
        }

    def checksum(self) -> str:
        """Content hash of the policy, excluding its version number and name."""
        body = self.to_dict()
        body.pop("version")
        body.pop("name")
        body.pop("description")
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def validate(self) -> None:
        if self.version <= 0:
            raise ValueError("policy version must be positive")
        for role in self.roles.values():
            for parent in role.inherits:
                if parent not in self.roles:
                    raise ValueError(f"role {role.name!r} inherits undefined role {parent!r}")
        for group, roles in self.groups.items():
            for role in roles:
                if role not in self.roles:
                    raise ValueError(f"group {group!r} maps to undefined role {role!r}")
        for rule in self.deny_rules:
            if rule.classification not in self.classifications:
                raise ValueError(
                    f"deny rule for {rule.principal} uses undefined classification "
                    f"{rule.classification!r}"
                )

    # -- evaluation -------------------------------------------------------
    def effective_roles(self, roles: set[str] | frozenset[str], groups: set[str] | frozenset[str]) -> set[str]:
        seed = set(roles)
        for group in groups:
            seed.update(self.groups.get(group, ()))
        frontier = [r for r in seed if r in self.roles]
        closure: set[str] = set()
        while frontier:
            role = frontier.pop()
            if role in closure:
                continue
            closure.add(role)
            frontier.extend(self.roles[role].inherits)
        return closure

    def clearance(self, effective_roles: set[str]) -> int:
        return max((self.roles[r].clearance for r in effective_roles), default=0)

    def principals(self, user_id: str, groups: set[str], effective_roles: set[str]) -> set[Principal]:
        return (
            {Principal(PrincipalType.USER, user_id)}
            | {Principal(PrincipalType.GROUP, g) for g in groups}
            | {Principal(PrincipalType.ROLE, r) for r in effective_roles}
        )

    def subject(self, user_id: str, groups: set[str], roles: set[str]) -> Subject:
        eff = self.effective_roles(roles, groups)
        return Subject(
            user_id=user_id,
            principals=frozenset(self.principals(user_id, groups, eff)),
            effective_roles=frozenset(eff),
            clearance=self.clearance(eff),
        )

    def decide(self, subject: Subject | None, classification: str, acl: Acl) -> Decision:
        if subject is None:
            return Decision(False, "unknown user")
        if classification not in self.classifications:
            return Decision(False, f"classification {classification!r} not defined in policy v{self.version}")
        required = self.classifications[classification]
        if subject.clearance < required:
            return Decision(
                False, f"clearance {subject.clearance} < {required} required for {classification!r}"
            )
        for rule in self.deny_rules:
            if rule.classification == classification and rule.principal in subject.principals:
                return Decision(False, f"policy deny rule: {rule.principal} may not read {classification!r}")
        denied = sorted(acl.deny & subject.principals)
        if denied:
            return Decision(False, f"explicit deny for {', '.join(map(str, denied))}")
        allowed = sorted(acl.allow & subject.principals)
        if not allowed:
            return Decision(False, "no matching allow (deny by default)")
        return Decision(True, f"allowed via {', '.join(map(str, allowed))}")


@dataclass(frozen=True)
class Subject:
    """A user's resolved permission set under one policy version."""

    user_id: str
    principals: frozenset[Principal]
    effective_roles: frozenset[str]
    clearance: int


def load_policy(path: str | Path) -> Policy:
    return Policy.from_dict(yaml.safe_load(Path(path).read_text()))


def diff_policies(old: Policy, new: Policy) -> dict[str, Any]:
    """Structural diff between two policy versions, for review before activation."""

    def keyed(d: dict, a: dict) -> dict[str, Any]:
        return {
            "added": sorted(set(a) - set(d)),
            "removed": sorted(set(d) - set(a)),
            "changed": sorted(k for k in set(d) & set(a) if d[k] != a[k]),
        }

    o, n = old.to_dict(), new.to_dict()
    deny_old = {(r["principal"], r["classification"]) for r in o["deny_rules"]}
    deny_new = {(r["principal"], r["classification"]) for r in n["deny_rules"]}
    return {
        "from": old.version,
        "to": new.version,
        "classifications": keyed(o["classifications"], n["classifications"]),
        "roles": keyed(o["roles"], n["roles"]),
        "groups": keyed(o["groups"], n["groups"]),
        "deny_rules": {
            "added": sorted(f"{p} !{c}" for p, c in deny_new - deny_old),
            "removed": sorted(f"{p} !{c}" for p, c in deny_old - deny_new),
        },
    }
