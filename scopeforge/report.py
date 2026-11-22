from __future__ import annotations

from typing import Any


def render_report(scope_name: str, analyses: list[dict[str, Any]]) -> str:
    lines = [
        "# ScopeForge Evidence Report",
        "",
        f"Scope: {scope_name}",
        "",
        "This draft uses recorded evidence only. ScopeForge does not automatically declare vulnerabilities.",
        "",
    ]
    if not analyses:
        lines.append("No analysis records supplied.")
        return "\n".join(lines)

    lines.append("## Summary")
    lines.append("")
    lines.append("| ID | Category | Status | Score |")
    lines.append("|---|---|---|---:|")
    lines.extend(
        f"| {item.get('id', '')} | {item.get('category', '')} | {item.get('status', '')} | {item.get('score', 0)} |"
        for item in analyses
    )
    lines.append("")

    for item in analyses:
        lines.append(f"## {item.get('id', 'analysis')}")
        lines.append("")
        lines.append(f"- Category: {item.get('category', '')}")
        lines.append(f"- Status: {item.get('status', '')}")
        lines.append(f"- Score: {item.get('score', 0)}")
        lines.append(f"- URL: `{item.get('url', '')}`")
        lines.append(f"- Parameter: `{item.get('parameter', '')}`")
        lines.append(f"- Reason: {item.get('reason', '')}")
        lines.append(f"- Next step: {item.get('next_step', '')}")
        if item.get("evidence_summary"):
            lines.append(f"- Evidence summary: {item['evidence_summary']}")
        if item.get("excerpt"):
            lines.append(f"- Redacted proof: `{item['excerpt']}`")
        lines.append("")

    lines.extend(
        [
            "## Reporting checklist",
            "",
            "- Confirm scope source before submission.",
            "- Confirm the finding is not listed in Known Issues.",
            "- Keep proof minimal and redacted.",
            "- State impact without real user data.",
            "- Submit only through the official channel.",
        ]
    )
    return "\n".join(lines)
