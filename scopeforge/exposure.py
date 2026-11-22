from __future__ import annotations

from .dorks import CATEGORIES, build_plan
from .models import Scope


def build_worksheet(scope_name: str, domain: str, source: str = "", per_category: int = 10) -> str:
    scope = Scope(name=scope_name, domains=[domain], source=source)
    lines = [
        "# ScopeForge Public Exposure Worksheet",
        "",
        f"Scope: {scope_name}",
        f"Domain: {domain}",
        f"Scope source: {source or 'not recorded'}",
        "",
        "Run these searches manually in your own browser. ScopeForge does not query search engines or targets.",
        "A public result is a lead, not proof of a vulnerability. Confirm scope and Known Issues before deeper work.",
        "",
    ]
    for category in CATEGORIES:
        records = build_plan(scope, category, per_category)
        lines.append(f"## {category.upper()}")
        lines.append("")
        lines.append("| ID | Query | Public? | Evidence | Decision |")
        lines.append("|---|---|---|---|---|")
        for item in records:
            lines.append(f"| {item['id']} | `{item['query']}` | [ ] | - | needs validation |")
        lines.append("")
    lines.extend(
        [
            "## Decision rules",
            "",
            "- [ ] Scope source recorded",
            "- [ ] Public result is inside written scope",
            "- [ ] Result is not listed in Known Issues",
            "- [ ] Evidence is redacted",
            "- [ ] Impact is written in one clear sentence",
            "- [ ] No payload was fired at an unscoped asset",
        ]
    )
    return "\n".join(lines)
