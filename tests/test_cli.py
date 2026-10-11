"""CLI smoke tests using typer.testing.CliRunner against Postgres with pgvector."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rbac_rag.cli import app
from rbac_rag.config import get_settings

pytestmark = pytest.mark.db
runner = CliRunner()


@pytest.fixture
def cli_env(db_conn, db_url):
    schema_name = db_conn.execute("SELECT current_schema()").fetchone()[0]
    sep = "&" if "?" in db_url else "?"
    schema_url = f"{db_url}{sep}options=-csearch_path%3D{schema_name},public"

    s = get_settings()
    orig_url = s.database_url
    orig_embedder = s.embedder
    orig_llm = s.llm

    s.database_url = schema_url

    yield s

    s.database_url = orig_url
    s.embedder = orig_embedder
    s.llm = orig_llm


def test_cli_end_to_end_workflow(cli_env):
    # 1. Migrate
    res = runner.invoke(app, ["migrate"])
    assert res.exit_code == 0
    # Running migrate again shows up to date
    res_migrate_again = runner.invoke(app, ["migrate"])
    assert res_migrate_again.exit_code == 0
    assert "up to date" in res_migrate_again.stdout

    # 2. Publish Policy v1 and activate
    policy_v1_path = Path("examples/acme/policy_v1.yaml")
    res_pub1 = runner.invoke(app, ["policy", "publish", str(policy_v1_path), "--activate"])
    assert res_pub1.exit_code == 0
    assert "Published policy v1" in res_pub1.stdout

    # 3. Publish Policy v2 and diff
    policy_v2_path = Path("examples/acme/policy_v2.yaml")
    res_pub2 = runner.invoke(app, ["policy", "publish", str(policy_v2_path)])
    assert res_pub2.exit_code == 0
    assert "Published policy v2" in res_pub2.stdout

    res_list = runner.invoke(app, ["policy", "list"])
    assert res_list.exit_code == 0
    assert "v1" in res_list.stdout
    assert "v2" in res_list.stdout

    res_diff = runner.invoke(app, ["policy", "diff", "1", "2"])
    assert res_diff.exit_code == 0
    assert '"from": 1' in res_diff.stdout
    assert '"to": 2' in res_diff.stdout

    res_activate = runner.invoke(app, ["policy", "activate", "1"])
    assert res_activate.exit_code == 0
    assert "Activated policy v1" in res_activate.stdout

    # 4. Sync directory
    directory_path = Path("examples/acme/directory.yaml")
    res_dir = runner.invoke(app, ["directory", "sync", str(directory_path), "--prune"])
    assert res_dir.exit_code == 0
    assert "Synced" in res_dir.stdout

    # 5. Ingest manifest with --fake flag
    acl_manifest_path = Path("examples/acme/acl.yaml")
    res_ingest = runner.invoke(app, ["--fake", "ingest", str(acl_manifest_path)])
    assert res_ingest.exit_code == 0
    assert "Ingested 6 documents" in res_ingest.stdout

    # 6. Whoami
    res_whoami = runner.invoke(app, ["whoami", "--user", "alice"])
    assert res_whoami.exit_code == 0
    assert "User: alice" in res_whoami.stdout
    assert "engineer" in res_whoami.stdout

    # 7. Explain
    res_explain = runner.invoke(app, ["explain", "eng_runbook:0000", "--user", "alice"])
    assert res_explain.exit_code == 0
    assert "Allowed: True" in res_explain.stdout

    # 8. Ask --fake
    res_ask = runner.invoke(app, ["--fake", "ask", "--user", "alice", "How to restart production services?"])
    assert res_ask.exit_code == 0
    assert len(res_ask.stdout) > 0

    # 9. Ask with claims filter (--groups & --roles)
    res_ask_claims = runner.invoke(
        app,
        ["--fake", "ask", "--user", "alice", "--groups", "eng", "--roles", "engineer", "How to restart production services?"]
    )
    assert res_ask_claims.exit_code == 0
    assert len(res_ask_claims.stdout) > 0
