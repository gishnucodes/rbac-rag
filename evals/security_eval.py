"""Deterministic security evaluation (leakage, canaries, access recall, v1->v2 delta).

Runs offline without an LLM.

Usage:
    uv run python evals/security_eval.py [--fake] [--policies 1,2]
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from examples.acme.seed import seed
from evals.report import save_report
from rbac_rag.acl.directory import load_directory
from rbac_rag.acl.filters import DirectoryAclFilter
from rbac_rag.acl.guard import AccessGuard
from rbac_rag.acl.policy import Policy, load_policy
from rbac_rag.acl.policy_store import PolicyStore
from rbac_rag.config import get_settings
from rbac_rag.db.connection import connect
from rbac_rag.pipeline.retriever import SecureRetriever
from rbac_rag.store.pgvector_store import PgVectorStore
from rbac_rag.types import UserContext

CANARY_PATTERN = re.compile(r"\b[A-Z]+-\d{4}\b")


def parse_policies_arg(val: str) -> list[int]:
    parts = val.replace(",", " ").split()
    return [int(p) for p in parts]


def load_dataset(dataset_path: Path) -> list[dict[str, Any]]:
    return yaml.safe_load(dataset_path.read_text()) or []


def run_security_eval(fake: bool = True, policies: list[int] | None = None) -> dict[str, Any]:
    if policies is None:
        policies = [1, 2]

    # Step 1: Ensure DB is seeded
    print("Ensuring database is seeded...")
    seed(fake=fake)

    settings = get_settings()
    if fake:
        settings = settings.model_copy(update={"embedder": "fake", "llm": "fake"})

    acme_dir = Path("examples/acme").resolve()
    dataset_path = Path("evals/dataset.yaml").resolve()
    dataset = load_dataset(dataset_path)

    policy_files = {
        1: acme_dir / "policy_v1.yaml",
        2: acme_dir / "policy_v2.yaml",
    }
    policy_oracles: dict[int, Policy] = {
        pv: load_policy(pfile) for pv, pfile in policy_files.items() if pfile.exists()
    }
    directory_oracle = load_directory(acme_dir / "directory.yaml")

    all_personas = list(directory_oracle.keys()) + ["mallory"]

    total_checks = 0
    total_leaks = 0
    leak_details: list[dict[str, Any]] = []

    total_canary_exposures = 0
    canary_details: list[dict[str, Any]] = []

    recall_numerators = 0
    recall_denominators = 0

    per_policy_results: dict[int, dict[str, Any]] = {}
    docs_retrieved_per_persona_policy: dict[str, dict[int, set[str]]] = {
        p: {pv: set() for pv in policies} for p in all_personas
    }

    with connect(settings.database_url) as conn:
        from rbac_rag.registry import get_embedder

        embedder = get_embedder(settings.embedder, settings)
        store = PgVectorStore(conn, embedder)
        policy_store = PolicyStore(conn)
        acl_filter = DirectoryAclFilter()
        guard = AccessGuard()

        retriever = SecureRetriever(
            conn=conn,
            store=store,
            embedder=embedder,
            acl_filter=acl_filter,
            policy_store=policy_store,
            guard=guard,
            k=settings.top_k,
        )

        for pv in policies:
            if pv not in policy_oracles:
                oracle_policy = policy_store.get(pv)
            else:
                oracle_policy = policy_oracles[pv]

            pv_checks = 0
            pv_leaks = 0
            pv_canary_exposures = 0
            pv_recall_num = 0
            pv_recall_den = 0

            for row in dataset:
                row_id = row["id"]
                row_persona = row["persona"]
                question = row["question"]

                override = (row.get("by_policy") or {}).get(pv, {})
                expected_doc_ids = override.get("expected_doc_ids", row.get("expected_doc_ids", []))
                should_refuse = override.get("should_refuse", row.get("should_refuse", False))

                for persona in all_personas:
                    user_ctx = UserContext(user_id=persona, policy_version=pv)
                    if persona in directory_oracle:
                        user_dir = directory_oracle[persona]
                        subject = oracle_policy.subject(
                            user_id=persona,
                            groups=set(user_dir.groups),
                            roles=set(user_dir.roles),
                        )
                    else:
                        subject = None

                    retrieval_res = retriever.retrieve(user_ctx, question)
                    chunks = retrieval_res.chunks
                    pv_checks += 1
                    total_checks += 1

                    retrieved_doc_ids = {c.document_id for c in chunks}
                    docs_retrieved_per_persona_policy[persona][pv].update(retrieved_doc_ids)

                    # 1. Leakage Check
                    for chunk in chunks:
                        decision = oracle_policy.decide(subject, chunk.classification, chunk.acl)
                        if not decision.allowed:
                            pv_leaks += 1
                            total_leaks += 1
                            leak_details.append({
                                "persona": persona,
                                "policy": pv,
                                "question_id": row_id,
                                "chunk_id": chunk.chunk_id,
                                "document_id": chunk.document_id,
                                "classification": chunk.classification,
                                "reason": decision.reason,
                            })

                    # 2. Canary Exposure Check (canaries from unauthorized chunks)
                    for chunk in chunks:
                        decision = oracle_policy.decide(subject, chunk.classification, chunk.acl)
                        if not decision.allowed:
                            canaries_in_chunk = CANARY_PATTERN.findall(chunk.content)
                            for canary in canaries_in_chunk:
                                pv_canary_exposures += 1
                                total_canary_exposures += 1
                                canary_details.append({
                                    "persona": persona,
                                    "policy": pv,
                                    "question_id": row_id,
                                    "chunk_id": chunk.chunk_id,
                                    "canary": canary,
                                })

                    # 3. Access Recall Check (only evaluated when question is run for its target row_persona)
                    if persona == row_persona:
                        if expected_doc_ids and not should_refuse:
                            pv_recall_den += len(expected_doc_ids)
                            recall_denominators += len(expected_doc_ids)

                            hits = sum(1 for doc_id in expected_doc_ids if doc_id in retrieved_doc_ids)
                            pv_recall_num += hits
                            recall_numerators += hits

            pv_recall = (pv_recall_num / pv_recall_den) if pv_recall_den > 0 else 1.0
            per_policy_results[pv] = {
                "checks": pv_checks,
                "leaks": pv_leaks,
                "canary_exposures": pv_canary_exposures,
                "access_recall": pv_recall,
            }

    # 4. v1 -> v2 Delta per Persona
    v1_v2_delta: dict[str, dict[str, Any]] = {}
    if 1 in policies and 2 in policies:
        for persona in all_personas:
            docs_v1 = docs_retrieved_per_persona_policy[persona][1]
            docs_v2 = docs_retrieved_per_persona_policy[persona][2]
            gained = list(docs_v2 - docs_v1)
            lost = list(docs_v1 - docs_v2)

            details = []
            if gained:
                details.append(f"Gained access to {', '.join(sorted(gained))}")
            if lost:
                details.append(f"Lost access to {', '.join(sorted(lost))}")
            if not details:
                details.append("No change in document access")

            v1_v2_delta[persona] = {
                "gained": gained,
                "lost": lost,
                "details": "; ".join(details),
            }

    overall_recall = (recall_numerators / recall_denominators) if recall_denominators > 0 else 1.0
    leakage_rate = (total_leaks / total_checks) if total_checks > 0 else 0.0

    report_data = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "policies": policies,
        "total_checks": total_checks,
        "total_leaks": total_leaks,
        "leakage_rate": leakage_rate,
        "canary_exposures_count": total_canary_exposures,
        "overall_access_recall": overall_recall,
        "per_policy": per_policy_results,
        "v1_v2_delta": v1_v2_delta,
        "leak_details": leak_details,
        "canary_details": canary_details,
    }

    return report_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic Security Evaluation for RBAC-RAG")
    parser.add_argument("--fake", action="store_true", help="Use fake offline embedder")
    parser.add_argument(
        "--policies",
        type=parse_policies_arg,
        default=[1, 2],
        help="Comma or space separated policy versions to evaluate (e.g. 1,2 or '1 2')",
    )
    args = parser.parse_args()

    results = run_security_eval(fake=args.fake, policies=args.policies)
    json_path, md_path = save_report(results)

    if results["total_leaks"] > 0:
        print(f"\nSECURITY EVALUATION FAILED: {results['total_leaks']} leakage violation(s) detected!", file=sys.stderr)
        sys.exit(1)
    else:
        print("\nSECURITY EVALUATION PASSED: 0 leakage violations detected.")


if __name__ == "__main__":
    main()
