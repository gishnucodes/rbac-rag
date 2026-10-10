import pytest
import psycopg
from rbac_rag.db.migrate import migrate, schema_embedding_dim, load_migrations

pytestmark = pytest.mark.db


def test_migrations_rerun_applies_nothing(db_conn):
    # db_conn fixture already ran migrate(conn, 768)
    applied_again = migrate(db_conn, 768)
    assert len(applied_again) == 0


def test_migrations_edited_checksum_raises(db_conn):
    # Artificially alter the checksum recorded in schema_migrations for migration 1
    db_conn.execute("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1")

    with pytest.raises(RuntimeError, match="changed after it was applied"):
        migrate(db_conn, 768)


def test_migrations_embedding_dim_recorded(db_conn):
    dim = schema_embedding_dim(db_conn)
    assert dim == 768
