"""Reporting utilities for saving evaluation results as JSON and Markdown summaries."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_report(
    eval_name: str,
    policy_version: int,
    results: list[dict[str, Any]],
    summary: dict[str, Any],
    output_dir: str | Path = "evals/results",
) -> tuple[Path, Path]:
    """Save evaluation results and summary into JSON and Markdown files.

    Returns tuple of (json_path, markdown_path).
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"{timestamp}_{eval_name}_v{policy_version}"
    json_path = out_dir / f"{base_name}.json"
    md_path = out_dir / f"{base_name}.md"

    report_data = {
        "eval_name": eval_name,
        "policy_version": policy_version,
        "timestamp": timestamp,
        "summary": summary,
        "results": results,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    md_content = generate_markdown_report(eval_name, policy_version, timestamp, summary, results)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return json_path, md_path


def generate_markdown_report(
    eval_name: str,
    policy_version: int,
    timestamp: str,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
) -> str:
    lines = [
        f"# Evaluation Report: {eval_name.upper()} (Policy v{policy_version})",
        f"**Timestamp:** {timestamp} (UTC)",
        "",
        "## Summary Metrics",
        "",
    ]

    # Metrics table
    overall_metrics = summary.get("overall_metrics", {})
    if overall_metrics:
        lines.extend([
            "| Metric | Average Score |",
            "| --- | --- |",
        ])
        for k, v in overall_metrics.items():
            val_str = f"{v:.4f}" if isinstance(v, (int, float)) else str(v)
            lines.append(f"| {k} | {val_str} |")
        lines.append("")

    # Per-persona breakdown
    persona_metrics = summary.get("persona_metrics", {})
    if persona_metrics:
        lines.extend([
            "## Per-Persona Breakdown",
            "",
        ])
        # Find all metric keys
        metric_keys = sorted({m for p in persona_metrics.values() for m in p.keys()})
        headers = ["Persona"] + metric_keys
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["---"] * len(headers)) + "|")

        for persona, p_mets in persona_metrics.items():
            row = [persona]
            for mk in metric_keys:
                val = p_mets.get(mk, "N/A")
                val_str = f"{val:.4f}" if isinstance(val, (int, float)) else str(val)
                row.append(val_str)
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    # Detailed test sample results
    lines.extend([
        "## Sample Results",
        "",
        "| ID | Persona | Question | Refused | Canary Safe | Leakage Critic |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for r in results:
        sample_id = r.get("id", "N/A")
        persona = r.get("persona", "N/A")
        q = r.get("question", "").replace("|", "\\|")
        refused = "Yes" if r.get("refused") else "No"
        canary_safe = "Pass" if r.get("canary_safe", True) else "FAIL"
        leak_critic = r.get("leakage_critic", "N/A")
        lines.append(f"| {sample_id} | {persona} | {q} | {refused} | {canary_safe} | {leak_critic} |")

    lines.append("")
    return "\n".join(lines)
