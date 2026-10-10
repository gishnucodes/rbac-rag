import os
import uuid
import pytest
import psycopg
from rbac_rag.db.migrate import migrate

TEST_DB_URL_VAR = "RBAC_RAG_TEST_DATABASE_URL"

def pytest_configure(config):
    config.addinivalue_line("markers", "db: requires a reachable Postgres with pgvector")

@pytest.fixture(scope="session")
def db_url() -> str | None:
    url = os.environ.get(TEST_DB_URL_VAR)
    if not url:
        return None
    return url

@pytest.fixture(autouse=True)
def skip_by_db_marker(request):
    if request.node.get_closest_marker("db"):
        url = os.environ.get(TEST_DB_URL_VAR)
        if not url:
            pytest.skip(f"Test skipped because {TEST_DB_URL_VAR} is unset.")

@pytest.fixture
def db_conn(db_url):
    if not db_url:
        pytest.skip(f"Test skipped because {TEST_DB_URL_VAR} is unset.")

    # Admin connection to create/drop schema and ensure extension exists
    admin_conn = psycopg.connect(db_url, autocommit=True)
    admin_conn.execute("CREATE EXTENSION IF NOT EXISTS vector SCHEMA public")

    schema_name = f"test_schema_{uuid.uuid4().hex}"
    admin_conn.execute(f"CREATE SCHEMA {schema_name}")

    conn = psycopg.connect(db_url, autocommit=True)
    conn.execute(f"SET search_path TO {schema_name}, public")

    # Apply migrations
    migrate(conn, 768)

    yield conn

    conn.close()
    admin_conn.execute(f"DROP SCHEMA {schema_name} CASCADE")
    admin_conn.close()
