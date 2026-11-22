from __future__ import annotations

from typing import Any

from .analyzer import redact

RANK = {"evidence-confirmed": 0, "likely": 1, "needs-validation": 2, "blocked": 3}
STATUS_ORDER = tuple(RANK)


def _sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    status = str(item.get("status", "needs-validation"))
    score = item.get("score", 0)
    try:
        numeric = int(score)
    except (TypeError, ValueError):
        numeric = 0
    return RANK.get(status, 4), -numeric, str(item.get("id", ""))


def _cell(value: Any) -> str:
    return redact(value).replace("|", "\\|").replace("\n", " ")


def _counts(analyses: list[dict[str, Any]]) -> dict[str, int]:
    result = {status: 0 for status in STATUS_ORDER}
    for item in analyses:
        status = str(item.get("status", "needs-validation"))
        result[status] = result.get(status, 0) + 1
    return result


def _table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return lines


def _confirmed_section(item: dict[str, Any], index: int) -> list[str]:
    identifier = _cell(item.get("id", f"analysis-{index}"))
    category = _cell(item.get("category", ""))
    lines = [
        f"### {identifier} - {category}",
        "",
        f"- Scope: {_cell(item.get('scope', ''))}",
        f"- Status: {_cell(item.get('status', ''))}",
        f"- Score: {_cell(item.get('score', 0))}",
        f"- Surface: {_cell(item.get('surface', ''))}",
        f"- Redacted URL: `{_cell(item.get('url', ''))}`",
        f"- Parameter: `{_cell(item.get('parameter', ''))}`",
        f"- Context: {_cell(item.get('context', ''))}",
        f"- Error family: {_cell(item.get('error_family', ''))}",
        f"- Signal: {_cell(item.get('reason', ''))}",
    ]
    if item.get("evidence_summary"):
        lines.append(f"- Evidence summary: {_cell(item['evidence_summary'])}")
    if item.get("excerpt"):
        lines.append(f"- Redacted proof: `{_cell(item['excerpt'])}`")
    lines.extend(
        [
            "",
            "#### Manual reproduction outline",
            "",
            "1. Open the redacted URL only in the recorded authorized scope.",
            "2. Observe the recorded parameter and output context; do not add attack payloads.",
            "3. Attach the minimal redacted proof above.",
            "4. Describe the expected-versus-observed behavior in one sentence.",
            "",
            "#### Impact template",
            "",
            "[Operator: state the concrete impact for the asset owner. Leave blank if impact is not proven.]",
            "",
            "#### Severity",
            "",
            "[Operator: choose severity from confirmed impact, scope rules, and duplicate status.]",
            "",
        ]
    )
    return lines


def render_report(
    scope_name: str,
    analyses: list[dict[str, Any]],
    scope_source: str = "",
) -> str:
    ordered = sorted(analyses, key=_sort_key)
    counts = _counts(ordered)
    lines = [
        "# ScopeForge Evidence Report",
        "",
        f"Scope: {_cell(scope_name)}",
        f"Scope source: {_cell(scope_source) if scope_source else '[operator: add program policy link or ID]'}",
        "",
        "Draft only. ScopeForge does not declare vulnerabilities or submit reports.",
        "",
        "## Summary",
        "",
    ]
    lines.extend(_table(("Status", "Count"), [(status, counts.get(status, 0)) for status in STATUS_ORDER]))
    lines.append("")

    confirmed = [item for item in ordered if item.get("status") == "evidence-confirmed"]
    if confirmed:
        lines.append("## Confirmed evidence drafts")
        lines.append("")
        for index, item in enumerate(confirmed, 1):
            lines.extend(_confirmed_section(item, index))
    else:
        lines.extend(
            [
                "## Confirmed evidence drafts",
                "",
                "No operator-confirmed evidence is available. Nothing here is ready to submit.",
                "",
            ]
        )

    needs_validation = [
        item for item in ordered if item.get("status") in ("likely", "needs-validation")
    ]
    if needs_validation:
        lines.extend(["## Needs validation", ""])
        lines.extend(
            _table(
                ("ID", "Category", "Status", "Score", "Reason", "Next step"),
                [
                    (
                        item.get("id", ""),
                        item.get("category", ""),
                        item.get("status", ""),
                        item.get("score", 0),
                        item.get("reason", ""),
                        item.get("next_step", ""),
                    )
                    for item in needs_validation
                ],
            )
        )
        lines.append("")

    blocked = [item for item in ordered if item.get("status") == "blocked"]
    if blocked:
        lines.extend(["## Blocked", ""])
        lines.extend(
            _table(
                ("ID", "Category", "Reason"),
                [(item.get("id", ""), item.get("category", ""), item.get("reason", "")) for item in blocked],
            )
        )
        lines.append("")

    lines.extend(
        [
            "## Pre-submit checklist",
            "",
            "- [ ] Written scope source is attached.",
            "- [ ] Target is not listed in Known Issues.",
            "- [ ] Duplicate check is complete.",
            "- [ ] Proof is minimal and redacted.",
            "- [ ] Impact is proven and written by the operator.",
            "- [ ] Exact evidence path is attached.",
            "- [ ] Submission goes through the official channel only.",
        ]
    )
    return "\n".join(lines)
