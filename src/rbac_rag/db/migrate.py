"""Minimal, ordered SQL migration runner.

Migrations are ``db/migrations/NNNN_name.sql``; each is applied once, in its
own transaction, and recorded in ``schema_migrations`` with its checksum. An
already-applied migration whose file has changed is an error, so the schema
history stays reproducible.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib import resources

import psycopg

_MIGRATION_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
# Arbitrary constant; serialises concurrent migrators.
_LOCK_KEY = 0x5242_4143


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode()).hexdigest()


def load_migrations(embedding_dim: int) -> list[Migration]:
    migrations = []
    for entry in resources.files("rbac_rag.db").joinpath("migrations").iterdir():
        match = _MIGRATION_RE.match(entry.name)
        if not match:
            continue
        sql = entry.read_text().replace("{{EMBEDDING_DIM}}", str(embedding_dim))
        migrations.append(Migration(int(match.group(1)), match.group(2), sql))
    return sorted(migrations, key=lambda m: m.version)


def migrate(conn: psycopg.Connection, embedding_dim: int) -> list[Migration]:
    """Apply pending migrations; return the ones applied by this call."""
    with conn.transaction():
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version    INT PRIMARY KEY,
                name       TEXT NOT NULL,
                checksum   TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    applied_now: list[Migration] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
        applied = {
            row[0]: row[1]
            for row in conn.execute("SELECT version, checksum FROM schema_migrations").fetchall()
        }
        for migration in load_migrations(embedding_dim):
            if migration.version in applied:
                if applied[migration.version] != migration.checksum:
                    raise RuntimeError(
                        f"migration {migration.version:04d}_{migration.name} changed after it was "
                        "applied (or embedding_dim differs from the deployed schema)"
                    )
                continue
            with conn.transaction():
                conn.execute(migration.sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                    (migration.version, migration.name, migration.checksum),
                )
            applied_now.append(migration)
    return applied_now


def schema_embedding_dim(conn: psycopg.Connection) -> int | None:
    row = conn.execute("SELECT value FROM rag_meta WHERE key = 'embedding_dim'").fetchone()
    return int(row[0]) if row else None
