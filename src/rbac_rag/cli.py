"""CLI interface for rbac-rag built with Typer."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from rbac_rag.acl.directory import DirectoryStore, load_directory
from rbac_rag.acl.guard import resolve_subject
from rbac_rag.acl.policy import Acl, Principal, PrincipalType, diff_policies, load_policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.config import get_settings
from rbac_rag.db.connection import connect
from rbac_rag.db.migrate import migrate
from rbac_rag.pipeline.ingest import load_manifest
from rbac_rag.registry import build_pipeline, get_acl_filter
from rbac_rag.types import UserContext

app = typer.Typer(help="RBAC-aware RAG framework CLI", no_args_is_help=True)
policy_app = typer.Typer(help="Manage versioned policies", no_args_is_help=True)
directory_app = typer.Typer(help="Manage user directory", no_args_is_help=True)

app.add_typer(policy_app, name="policy")
app.add_typer(directory_app, name="directory")


@app.callback()
def main(
    fake: bool = typer.Option(
        False, "--fake", help="Use offline fake embedder and LLM implementations"
    ),
) -> None:
    if fake:
        s = get_settings()
        s.embedder = "fake"
        s.llm = "fake"


@app.command()
def migrate_cmd() -> None:
    """Apply pending database migrations."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        applied = migrate(conn, settings.embedding_dim)
        if applied:
            for m in applied:
                typer.echo(f"Applied migration {m.version:04d}_{m.name}")
        else:
            typer.echo("Database schema is up to date.")
    finally:
        conn.close()


# Overwrite migrate_cmd name in typer to 'migrate'
app.registered_commands[-1].name = "migrate"


@policy_app.command("publish")
def policy_publish(
    file: Path = typer.Argument(..., help="Path to policy YAML file"),
    activate: bool = typer.Option(False, "--activate", help="Activate policy upon publishing"),
) -> None:
    """Publish a new policy version from a YAML file."""
    settings = get_settings()
    policy = load_policy(file)
    conn = connect(settings.database_url, autocommit=True)
    try:
        store = PolicyStore(conn)
        created = store.publish(policy, activate=activate)
        if created:
            msg = f"Published policy v{policy.version} ('{policy.name}')"
            if activate:
                msg += " and activated it"
            typer.echo(msg)
        else:
            msg = f"Policy v{policy.version} already exists with identical content"
            if activate:
                store.activate(policy.version)
                msg += " (activated)"
            typer.echo(msg)
    finally:
        conn.close()


@policy_app.command("activate")
def policy_activate(
    version: int = typer.Argument(..., help="Policy version number to activate"),
) -> None:
    """Activate a published policy version."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        store = PolicyStore(conn)
        store.activate(version)
        typer.echo(f"Activated policy v{version}")
    finally:
        conn.close()


@policy_app.command("list")
def policy_list() -> None:
    """List all published policy versions."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        store = PolicyStore(conn)
        versions = store.list()
        if not versions:
            typer.echo("No policy versions found.")
        else:
            for v in versions:
                active_flag = " (active)" if v.is_active else ""
                typer.echo(f"v{v.version}: {v.name}{active_flag} - {v.description}")
    finally:
        conn.close()


@policy_app.command("diff")
def policy_diff(
    a: int = typer.Argument(..., help="Source policy version"),
    b: int = typer.Argument(..., help="Target policy version"),
) -> None:
    """Diff two policy versions."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        store = PolicyStore(conn)
        old = store.get(a)
        new = store.get(b)
        diff = diff_policies(old, new)
        typer.echo(json.dumps(diff, indent=2))
    finally:
        conn.close()


@directory_app.command("sync")
def directory_sync(
    file: Path = typer.Argument(..., help="Path to directory YAML file"),
    prune: bool = typer.Option(
        False, "--prune", help="Delete users from database not present in file"
    ),
) -> None:
    """Sync user directory from a YAML file into database."""
    settings = get_settings()
    users = load_directory(file)
    conn = connect(settings.database_url, autocommit=True)
    try:
        store = DirectoryStore(conn)
        store.sync(users, prune=prune)
        typer.echo(f"Synced {len(users)} users.")
    finally:
        conn.close()


@app.command()
def ingest(
    manifest: Path = typer.Argument(..., help="Path to manifest YAML file"),
) -> None:
    """Ingest documents from a manifest file."""
    settings = get_settings()
    docs = load_manifest(manifest)
    conn = connect(settings.database_url, autocommit=True)
    try:
        ingest_pipeline, _, _ = build_pipeline(settings, conn)
        ingested = ingest_pipeline.ingest(docs)
        typer.echo(f"Ingested {len(ingested)} documents.")
    finally:
        conn.close()


@app.command()
def ask(
    question: str = typer.Argument(..., help="Question to ask the RAG system"),
    user: str = typer.Option(..., "--user", "-u", help="Username asking the question"),
    policy: int | None = typer.Option(None, "--policy", "-p", help="Policy version override"),
    groups: str | None = typer.Option(
        None, "--groups", "-g", help="Comma-separated list of groups (uses claims filter)"
    ),
    roles: str | None = typer.Option(
        None, "--roles", "-r", help="Comma-separated list of roles (uses claims filter)"
    ),
) -> None:
    """Ask a question using Secure RAG."""
    settings = get_settings()

    groups_tuple: tuple[str, ...] = ()
    roles_tuple: tuple[str, ...] = ()

    if groups is not None or roles is not None:
        settings.acl_filter = "claims"
        if groups:
            groups_tuple = tuple(g.strip() for g in groups.split(",") if g.strip())
        if roles:
            roles_tuple = tuple(r.strip() for r in roles.split(",") if r.strip())

    user_ctx = UserContext(
        user_id=user,
        groups=groups_tuple,
        roles=roles_tuple,
        policy_version=policy,
    )

    conn = connect(settings.database_url, autocommit=True)
    try:
        _, _, rag_pipeline = build_pipeline(settings, conn)
        ans = rag_pipeline.answer(user_ctx, question)

        typer.echo(ans.text)

        if ans.retrieval.chunks:
            typer.echo("\nRetrieved Chunks:")
            for c in ans.retrieval.chunks:
                typer.echo(f"- Chunk ID: {c.chunk_id} | Document Title: {c.title} | Score: {c.score:.4f}")
    finally:
        conn.close()


@app.command()
def explain(
    chunk_id: str = typer.Argument(..., help="Chunk ID to evaluate decision for"),
    user: str = typer.Option(..., "--user", "-u", help="Username to evaluate access for"),
    policy: int | None = typer.Option(None, "--policy", "-p", help="Policy version override"),
) -> None:
    """Explain access decision for a user on a chunk."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        policy_store = PolicyStore(conn)
        pv = policy_store.resolve_version(policy)
        pol = policy_store.get(pv)

        user_ctx = UserContext(user_id=user, policy_version=pv)
        acl_filter = get_acl_filter(settings.acl_filter, settings)
        subject = resolve_subject(conn, acl_filter, pol, user_ctx)

        row = conn.execute(
            "SELECT c.id, c.classification, d.title FROM chunks c JOIN documents d ON d.id = c.document_id WHERE c.id = %s",
            (chunk_id,),
        ).fetchone()

        if not row:
            typer.echo(f"Chunk '{chunk_id}' not found.", err=True)
            raise typer.Exit(code=1)

        _, classification, title = row

        acl_rows = conn.execute(
            "SELECT principal_type, principal_name, effect FROM chunk_acl WHERE chunk_id = %s",
            (chunk_id,),
        ).fetchall()

        allows: set[Principal] = set()
        denies: set[Principal] = set()
        for p_type, p_name, effect in acl_rows:
            p = Principal(PrincipalType(p_type), p_name)
            if effect == "allow":
                allows.add(p)
            elif effect == "deny":
                denies.add(p)
        acl = Acl(frozenset(allows), frozenset(denies))

        decision = pol.decide(subject, classification, acl)

        typer.echo(f"Allowed: {decision.allowed}")
        typer.echo(f"Reason: {decision.reason}")
        if subject:
            typer.echo(f"Clearance: {subject.clearance}")
            typer.echo(f"Effective Roles: {', '.join(sorted(subject.effective_roles)) if subject.effective_roles else 'none'}")
            typer.echo(f"Effective Principals: {', '.join(sorted(str(p) for p in subject.principals))}")
        else:
            typer.echo("User: unknown (not found in directory)")
    finally:
        conn.close()


@app.command()
def whoami(
    user: str = typer.Option(..., "--user", "-u", help="Username to inspect"),
    policy: int | None = typer.Option(None, "--policy", "-p", help="Policy version override"),
) -> None:
    """Print user's effective roles, principals and clearance."""
    settings = get_settings()
    conn = connect(settings.database_url, autocommit=True)
    try:
        policy_store = PolicyStore(conn)
        pv = policy_store.resolve_version(policy)
        pol = policy_store.get(pv)

        user_ctx = UserContext(user_id=user, policy_version=pv)
        acl_filter = get_acl_filter(settings.acl_filter, settings)
        subject = resolve_subject(conn, acl_filter, pol, user_ctx)

        if not subject:
            typer.echo(f"User '{user}' not found in directory.", err=True)
            raise typer.Exit(code=1)

        typer.echo(f"User: {subject.user_id}")
        typer.echo(f"Policy Version: {pv}")
        typer.echo(f"Clearance: {subject.clearance}")
        typer.echo(f"Effective Roles: {', '.join(sorted(subject.effective_roles)) if subject.effective_roles else 'none'}")
        typer.echo(f"Principals: {', '.join(sorted(str(p) for p in subject.principals))}")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
