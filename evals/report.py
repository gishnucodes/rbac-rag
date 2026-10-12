"""Report writer for security and RAGAS evaluation results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def save_report(
    results: dict[str, Any],
    output_dir: str | Path = "evals/results",
    filename_prefix: str = "security",
) -> tuple[Path, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = results.get("timestamp") or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = output_path / f"{timestamp}_{filename_prefix}.json"
    md_path = output_path / f"{timestamp}_{filename_prefix}.md"

    json_path.write_text(json.dumps(results, indent=2))

    if filename_prefix == "security":
        md_content = generate_markdown_report(results)
    else:
        md_content = generate_ragas_markdown_report(results)

    md_path.write_text(md_content)

    print(f"\nReport saved:\n  JSON: {json_path}\n  Markdown: {md_path}\n")
    print(md_content)

    return json_path, md_path


def generate_markdown_report(results: dict[str, Any]) -> str:
    lines = [
        "# Security Evaluation Report",
        "",
        f"**Timestamp:** {results.get('timestamp', '')}",
        f"**Policies Evaluated:** {', '.join(map(str, results.get('policies', [])))}",
        f"**Total Checks Run:** {results.get('total_checks', 0)}",
        "",
        "## Summary Metrics",
        "",
        f"- **Leakage Rate:** {results.get('leakage_rate', 0.0):.2%}",
        f"- **Canary Exposures:** {results.get('canary_exposures_count', 0)}",
        f"- **Overall Access Recall:** {results.get('overall_access_recall', 0.0):.2%}",
        "",
    ]

    per_policy = results.get("per_policy", {})
    if per_policy:
        lines.extend([
            "## Results by Policy Version",
            "",
            "| Policy | Checks | Leaks | Canary Exposures | Access Recall |",
            "|---|---|---|---|---|",
        ])
        for pv in sorted(per_policy.keys()):
            data = per_policy[pv]
            lines.append(
                f"| v{pv} | {data.get('checks', 0)} | {data.get('leaks', 0)} | "
                f"{data.get('canary_exposures', 0)} | {data.get('access_recall', 0.0):.2%} |"
            )
        lines.append("")

    delta = results.get("v1_v2_delta", {})
    if delta:
        lines.extend([
            "## Policy v1 -> v2 Delta per Persona",
            "",
            "| Persona | Docs Gained | Docs Lost | Details |",
            "|---|---|---|---|",
        ])
        for persona in sorted(delta.keys()):
            info = delta[persona]
            gained = ", ".join(sorted(info.get("gained", []))) or "None"
            lost = ", ".join(sorted(info.get("lost", []))) or "None"
            details = info.get("details", "")
            lines.append(f"| {persona} | {gained} | {lost} | {details} |")
        lines.append("")

    leaks = results.get("leak_details", [])
    if leaks:
        lines.extend([
            "## Leakage Violations",
            "",
        ])
        for leak in leaks:
            lines.append(
                f"- **Persona:** {leak.get('persona')} | **Policy:** v{leak.get('policy')} | "
                f"**Question ID:** {leak.get('question_id')} | **Chunk:** {leak.get('chunk_id')}"
            )
        lines.append("")

    canaries = results.get("canary_details", [])
    if canaries:
        lines.extend([
            "## Canary Exposure Details",
            "",
        ])
        for item in canaries:
            lines.append(
                f"- **Persona:** {item.get('persona')} | **Policy:** v{item.get('policy')} | "
                f"**Canary:** {item.get('canary')} | **Chunk:** {item.get('chunk_id')}"
            )
        lines.append("")

    return "\n".join(lines)


def generate_ragas_markdown_report(results: dict[str, Any]) -> str:
    summary = results.get("summary", {})
    samples = results.get("results", [])
    policy_version = results.get("policy_version", 1)
    timestamp = results.get("timestamp", "")

    lines = [
        f"# RAGAS Evaluation Report (Policy v{policy_version})",
        f"**Timestamp:** {timestamp}",
        "",
        "## Summary Metrics",
        "",
    ]

    overall = summary.get("overall_metrics", {})
    if overall:
        lines.extend([
            "| Metric | Score |",
            "| --- | --- |",
        ])
        for k, v in overall.items():
            val_str = f"{v:.4f}" if isinstance(v, (int, float)) else str(v)
            lines.append(f"| {k} | {val_str} |")
        lines.append("")

    persona_mets = summary.get("persona_metrics", {})
    if persona_mets:
        lines.extend([
            "## Per-Persona Breakdown",
            "",
        ])
        metric_keys = sorted({m for p in persona_mets.values() for m in p.keys()})
        headers = ["Persona"] + metric_keys
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
        for p in sorted(persona_mets.keys()):
            p_data = persona_mets[p]
            row = [p]
            for mk in metric_keys:
                v = p_data.get(mk, "N/A")
                val_str = f"{v:.4f}" if isinstance(v, (int, float)) else str(v)
                row.append(val_str)
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    lines.extend([
        "## Sample Results",
        "",
        "| ID | Persona | Question | Refused | Canary Safe | Leaked Canaries | Leakage Critic |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for r in samples:
        sample_id = r.get("id", "N/A")
        persona = r.get("persona", "N/A")
        q = str(r.get("question", "")).replace("|", "\\|")
        refused = "Yes" if r.get("refused") else "No"
        canary_safe = "Pass" if r.get("canary_safe", True) else "FAIL"
        leaked = ", ".join(r.get("leaked_canaries", [])) or "None"
        leak_critic = str(r.get("leakage_critic", "N/A"))
        lines.append(f"| {sample_id} | {persona} | {q} | {refused} | {canary_safe} | {leaked} | {leak_critic} |")

    lines.append("")
    return "\n".join(lines)
