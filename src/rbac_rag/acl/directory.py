"""The user directory: who is in which group and holds which direct roles."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb
import yaml


@dataclass(frozen=True)
class DirectoryUser:
    id: str
    display_name: str = ""
    groups: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    attributes: dict[str, Any] = field(default_factory=dict)


def load_directory(path: str | Path) -> dict[str, DirectoryUser]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return {
        uid: DirectoryUser(
            id=uid,
            display_name=(spec or {}).get("display_name", uid),
            groups=frozenset((spec or {}).get("groups", [])),
            roles=frozenset((spec or {}).get("roles", [])),
            attributes=(spec or {}).get("attributes", {}),
        )
        for uid, spec in (data.get("users") or {}).items()
    }


class DirectoryStore:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def upsert(self, user: DirectoryUser) -> None:
        with self.conn.transaction():
            self.conn.execute(
                """
                INSERT INTO users (id, display_name, attributes) VALUES (%s, %s, %s)
                ON CONFLICT (id) DO UPDATE
                SET display_name = EXCLUDED.display_name, attributes = EXCLUDED.attributes
                """,
                (user.id, user.display_name, Jsonb(user.attributes)),
            )
            self.conn.execute("DELETE FROM user_groups WHERE user_id = %s", (user.id,))
            self.conn.execute("DELETE FROM user_roles WHERE user_id = %s", (user.id,))
            with self.conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO user_groups (user_id, group_name) VALUES (%s, %s)",
                    [(user.id, g) for g in sorted(user.groups)],
                )
                cur.executemany(
                    "INSERT INTO user_roles (user_id, role_name) VALUES (%s, %s)",
                    [(user.id, r) for r in sorted(user.roles)],
                )

    def sync(self, users: dict[str, DirectoryUser], *, prune: bool = False) -> None:
        for user in users.values():
            self.upsert(user)
        if prune:
            with self.conn.transaction():
                self.conn.execute("DELETE FROM users WHERE NOT (id = ANY(%s))", (list(users),))

    def get(self, user_id: str) -> DirectoryUser | None:
        row = self.conn.execute(
            """
            SELECT u.id, u.display_name, u.attributes,
                   ARRAY(SELECT group_name FROM user_groups WHERE user_id = u.id),
                   ARRAY(SELECT role_name FROM user_roles WHERE user_id = u.id)
            FROM users u WHERE u.id = %s
            """,
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return DirectoryUser(row[0], row[1] or "", frozenset(row[3]), frozenset(row[4]), row[2])
