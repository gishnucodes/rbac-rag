"""Demo script running RAG queries for all personas under policy v1 and v2, plus claims filter demo."""

from __future__ import annotations

import argparse
from pathlib import Path

from rbac_rag.config import get_settings
from rbac_rag.db.connection import connect
from rbac_rag.registry import build_pipeline
from rbac_rag.types import UserContext

QUESTIONS = [
    "What is the L5 base salary?",
    "How do I get break-glass production access?",
    "What was Q3 revenue?",
    "What is Project Nightjar?",
    "How many PTO days do we get?",
]

PERSONAS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "henry",
    "mallory",
]


def truncate_text(text: str, max_len: int = 50) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3] + "..."


def print_policy_table(
    data: list[tuple[str, str, str, str, bool]],
    title: str,
    highlight_changes: bool = False,
) -> None:
    print("\n" + "=" * 90)
    print(f" {title}")
    print("=" * 90)

    # Group by question
    questions_map: dict[str, list[tuple[str, str, str, bool]]] = {}
    for persona, question, ans, docs, changed in data:
        questions_map.setdefault(question, []).append((persona, ans, docs, changed))

    for question, rows in questions_map.items():
        print(f"\nQuestion: {question}")
        headers = ["Persona", "Answer (truncated)", "Retrieved Docs"]
        if highlight_changes:
            headers.append("Status")

        col_widths = [len(h) for h in headers]
        for persona, ans, docs, changed in rows:
            col_widths[0] = max(col_widths[0], len(persona))
            col_widths[1] = max(col_widths[1], len(ans))
            col_widths[2] = max(col_widths[2], len(docs))
            if highlight_changes:
                status_str = "* CHANGED *" if changed else "UNCHANGED"
                col_widths[3] = max(col_widths[3], len(status_str))

        def fmt_row(vals: list[str]) -> str:
            return " | ".join(val.ljust(width) for val, width in zip(vals, col_widths))

        print(fmt_row(headers))
        print("-+-".join("-" * w for w in col_widths))

        for persona, ans, docs, changed in rows:
            vals = [persona, ans, docs]
            if highlight_changes:
                vals.append("* CHANGED *" if changed else "UNCHANGED")
            print(fmt_row(vals))


def run_demo(fake: bool = False) -> None:
    settings = get_settings()
    if fake:
        settings = settings.model_copy(update={"embedder": "fake", "llm": "fake"})

    with connect(settings.database_url) as conn:
        _, _, rag_pipeline = build_pipeline(settings, conn)

        # 1. Run Policy v1
        v1_data: dict[tuple[str, str], tuple[str, list[str]]] = {}
        v1_rows: list[tuple[str, str, str, str, bool]] = []

        for question in QUESTIONS:
            for persona in PERSONAS:
                user = UserContext(user_id=persona, policy_version=1)
                ans = rag_pipeline.answer(user, question)
                doc_ids = sorted(set(c.document_id for c in ans.retrieval.chunks))
                doc_str = ", ".join(doc_ids) if doc_ids else "None"
                trunc_ans = truncate_text(ans.text)

                v1_data[(persona, question)] = (ans.text, doc_ids)
                v1_rows.append((persona, question, trunc_ans, doc_str, False))

        print_policy_table(v1_rows, "POLICY V1 EVALUATION RESULTS", highlight_changes=False)

        # 2. Run Policy v2
        v2_rows: list[tuple[str, str, str, str, bool]] = []
        changed_count = 0

        for question in QUESTIONS:
            for persona in PERSONAS:
                user = UserContext(user_id=persona, policy_version=2)
                ans = rag_pipeline.answer(user, question)
                doc_ids = sorted(set(c.document_id for c in ans.retrieval.chunks))
                doc_str = ", ".join(doc_ids) if doc_ids else "None"
                trunc_ans = truncate_text(ans.text)

                v1_full_text, v1_doc_ids = v1_data[(persona, question)]
                changed = (doc_ids != v1_doc_ids) or (ans.refused != (v1_doc_ids == []))
                if changed:
                    changed_count += 1

                v2_rows.append((persona, question, trunc_ans, doc_str, changed))

        print_policy_table(
            v2_rows, "POLICY V2 EVALUATION RESULTS (HIGHLIGHTING CHANGES VS V1)", highlight_changes=True
        )
        print(f"\nTotal rows changed under Policy v2: {changed_count}")

        # 3. Claims Filter Demonstration
        print("\n" + "=" * 90)
        print(" CLAIMS FILTER DEMO: User 'zoe' (Not in Directory)")
        print("=" * 90)

        question = "How do I get break-glass production access?"

        # Directory filter (default)
        zoe_dir_context = UserContext(user_id="zoe", policy_version=1)
        dir_ans = rag_pipeline.answer(zoe_dir_context, question)
        dir_docs = sorted(set(c.document_id for c in dir_ans.retrieval.chunks))

        print(f"\nQuestion: {question}")
        print("\n1. DirectoryAclFilter (Lookup in 'users' table):")
        print(f"   Context       : UserContext(user_id='zoe')")
        print(f"   In Directory  : False")
        print(f"   Refused       : {dir_ans.refused}")
        print(f"   Retrieved Docs: {dir_docs if dir_docs else 'None'}")
        print(f"   Answer        : {truncate_text(dir_ans.text, 70)}")

        # Claims filter
        claims_settings = settings.model_copy(update={"acl_filter": "claims"})
        _, _, claims_rag = build_pipeline(claims_settings, conn)

        zoe_claims_context = UserContext(user_id="zoe", groups=("engineering",), policy_version=1)
        claims_ans = claims_rag.answer(zoe_claims_context, question)
        claims_docs = sorted(set(c.document_id for c in claims_ans.retrieval.chunks))

        print("\n2. ClaimsAclFilter (Token claims passed directly):")
        print(f"   Context       : UserContext(user_id='zoe', groups=('engineering',))")
        print(f"   In Directory  : False (Resolved via token claims)")
        print(f"   Refused       : {claims_ans.refused}")
        print(f"   Retrieved Docs: {claims_docs}")
        print(f"   Answer        : {truncate_text(claims_ans.text, 70)}")
        print("=" * 90)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Acme demo queries")
    parser.add_argument("--fake", action="store_true", help="Use fake embedder and LLM")
    args = parser.parse_args()
    run_demo(fake=args.fake)


if __name__ == "__main__":
    main()
