from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import findings, soft404
from .analyzer import redact
from .data import load
from .dorks import build_plan
from .models import Scope
from .net import Session
from .validators import resolve

TIER_ORDER = ("high", "medium", "low")


@dataclass(frozen=True)
class Rule:
    path: str
    label: str
    tier: str
    validator: Callable | None


@dataclass(frozen=True)
class ScanResult:
    findings: list
    sent: int
    skipped: int


def load_rules(tier: str = "high") -> list[Rule]:
    key = tier.strip().lower()
    if key not in (*TIER_ORDER, "all"):
        raise ValueError("tier must be high, medium, low, or all")
    allowed = set(TIER_ORDER) if key == "all" else set(TIER_ORDER[: TIER_ORDER.index(key) + 1])
    rules: list[Rule] = []
    for item in load("paths").get("rules", []):
        if str(item.get("tier")) not in allowed:
            continue
        rules.append(Rule(str(item["path"]), str(item["label"]), str(item["tier"]), resolve(item.get("validator"))))
    return rules


def run(
    session: Session,
    scope_name: str,
    host: str,
    tier: str = "high",
    include_maybe: bool = False,
    chain_git: bool = True,
    seen: set[str] | None = None,
) -> ScanResult:
    baseline = soft404.build(session, host)
    queue = load_rules(tier)
    done: set[str] = set(seen or set())
    produced: list = []
    sent = 0
    skipped = 0

    while queue:
        rule = queue.pop(0)
        if rule.path in done:
            skipped += 1
            continue
        done.add(rule.path)
        url = host.rstrip("/") + rule.path
        response = session.get(url)
        sent += 1
        verdict, reason = soft404.classify(
            rule.validator, response.status, response.body, baseline, response.content_type
        )
        if verdict == "exposed":
            confidence = "high"
        elif verdict == "maybe" and include_maybe:
            confidence = "low"
        else:
            if chain_git and rule.path == "/.git/HEAD" and verdict != "absent":
                queue = [item for item in load_rules("high") if item.path.startswith("/.git/")] + queue
            continue
        excerpt = redact(response.text[:200]) if verdict == "exposed" else ""
        produced.append(
            findings.add(
                scope=scope_name,
                kind="exposure",
                category="exposure",
                url=url,
                confidence=confidence,
                surface=rule.label,
                signal=f"{reason}: {rule.label}",
                excerpt=excerpt,
                baseline_status=baseline.status,
                baseline_size=baseline.size,
                injected_status=response.status,
                injected_size=len(response.body),
            )
        )
        if chain_git and rule.path == "/.git/HEAD":
            queue = [item for item in load_rules("high") if item.path.startswith("/.git/")] + queue
    return ScanResult(produced, sent, skipped)


def render(result: ScanResult) -> str:
    lines = [f"Exposure scan - {result.sent} requests, {result.skipped} skipped, {len(result.findings)} finding(s)", ""]
    if not result.findings:
        lines.append("Nothing matched a structural validator.")
        return "\n".join(lines)
    lines.extend(f"{item.id}  {item.confidence:<6}  {item.url}  <- {item.signal}" for item in result.findings)
    lines.extend(["", "Next: scopeforge verify <id>"])
    return "\n".join(lines)


def build_worksheet(scope_name: str, domain: str, source: str = "", per_category: int = 10) -> str:
    scope = Scope(name=scope_name, domains=[domain], source=source)
    lines = [
        "# ScopeForge Public Exposure Worksheet",
        "",
        f"Scope: {scope_name}",
        f"Domain: {domain}",
        f"Scope source: {source or 'not recorded'}",
        "",
        "Run these searches manually in a browser. A public result is a lead, not proof.",
        "",
    ]
    for category in load("dorks").get("categories", {}):
        records = build_plan(scope, category, per_category)
        lines.append(f"## {category.upper()}")
        lines.append("")
        lines.append("| ID | Query | Public? | Evidence | Decision |")
        lines.append("|---|---|---|---|---|")
        lines.extend(f"| {item['id']} | `{item['query']}` | [ ] | - | needs validation |" for item in records)
        lines.append("")
    lines.extend(
        [
            "## Decision rules",
            "",
            "- [ ] Scope source recorded",
            "- [ ] Result inside written scope",
            "- [ ] Not listed in Known Issues",
            "- [ ] Evidence redacted",
            "- [ ] Impact in one clear sentence",
        ]
    )
    return "\n".join(lines)
