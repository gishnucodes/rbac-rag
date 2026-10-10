from __future__ import annotations

import psycopg
from pgvector.psycopg import register_vector


def connect(database_url: str, *, autocommit: bool = False) -> psycopg.Connection:
    """Open a psycopg connection with the pgvector type adapter registered.

    The adapter is only registered when the ``vector`` extension exists, so a
    fresh database can still be connected to in order to run migrations.
    """
    conn = psycopg.connect(database_url, autocommit=autocommit)
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        has_vector = cur.fetchone() is not None
    if not autocommit:
        conn.commit()
    if has_vector:
        register_vector(conn)
    return conn
