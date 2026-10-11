"""Seed script for Acme Corp example corpus, directory, and policies."""

from __future__ import annotations

import argparse
from pathlib import Path

from rbac_rag.acl.directory import DirectoryStore, load_directory
from rbac_rag.acl.policy import load_policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.config import get_settings
from rbac_rag.db.connection import connect
from rbac_rag.db.migrate import migrate
from rbac_rag.pipeline.ingest import load_manifest
from rbac_rag.registry import build_pipeline


def seed(fake: bool = False) -> None:
    settings = get_settings()
    if fake:
        settings = settings.model_copy(update={"embedder": "fake", "llm": "fake"})

    acme_dir = Path(__file__).parent.resolve()

    print("Connecting to database...")
    with connect(settings.database_url) as conn:
        print("Migrating database schema...")
        applied = migrate(conn, settings.embedding_dim)
        if applied:
            print(f"Applied {len(applied)} migration(s).")
        else:
            print("Schema is up to date.")

        policy_store = PolicyStore(conn)
        p1 = load_policy(acme_dir / "policy_v1.yaml")
        p2 = load_policy(acme_dir / "policy_v2.yaml")

        pub_v1 = policy_store.publish(p1, activate=True)
        print(f"Policy v1 published (activated): {pub_v1}")

        pub_v2 = policy_store.publish(p2, activate=False)
        print(f"Policy v2 published: {pub_v2}")

        print("Syncing directory...")
        users = load_directory(acme_dir / "directory.yaml")
        dir_store = DirectoryStore(conn)
        dir_store.sync(users)
        print(f"Synced {len(users)} user(s) into directory.")

        print("Ingesting ACL documents manifest...")
        docs = load_manifest(acme_dir / "acl.yaml")
        ingest_pipeline, _, _ = build_pipeline(settings, conn)
        ingested_ids = ingest_pipeline.ingest(docs)
        print(f"Ingested {len(ingested_ids)} document(s): {ingested_ids}")

    print("Seeding complete!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Acme example data into Postgres")
    parser.add_argument("--fake", action="store_true", help="Use fake offline embedder")
    args = parser.parse_args()
    seed(fake=args.fake)


if __name__ == "__main__":
    main()
