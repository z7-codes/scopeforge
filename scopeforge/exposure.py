from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass
from difflib import SequenceMatcher

from .analyzer import redact
from .dorks import CATEGORIES, build_plan
from .findings import add_finding
from .models import Scope
from .paths import PathRule, rules_for
from .probe import fetch_page, validate_probe_target

HEXISH = re.compile(r"\b[0-9a-f]{16,}\b")
DIGITS = re.compile(r"\d+")
WHITESPACE = re.compile(r"\s+")


@dataclass
class Baseline:
    status: int
    size: int
    body: str


def as_bytes(body: object) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8", "replace")
    return bytes(body)


def random_path() -> str:
    return "z7sf-" + "".join(random.choice("abcdef0123456789") for _ in range(12))


def normalize_body(body: bytes) -> str:
    text = body.decode("utf-8", "replace").lower()
    text = HEXISH.sub("h", text)
    text = DIGITS.sub("0", text)
    text = WHITESPACE.sub(" ", text)
    return text[:4000].strip()


def similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


def build_baseline(host: str, samples: int = 3) -> Baseline:
    collected: list[Baseline] = []
    for _ in range(samples):
        url = host.rstrip("/") + "/" + random_path()
        try:
            status, _, body = fetch_page(url)
        except OSError:
            continue
        raw = as_bytes(body)
        collected.append(Baseline(status, len(raw), normalize_body(raw)))
    if not collected:
        raise ValueError("baseline requests failed for " + host)
    collected.sort(key=lambda item: item.size)
    return collected[len(collected) // 2]


def classify(rule: PathRule, status: int, body: bytes, baseline: Baseline, ctype: str) -> tuple[str, str]:
    if status >= 500:
        return "error", f"HTTP {status}"
    if rule.validator and rule.validator(body, ctype):
        return "exposed", "structural match: " + rule.label
    if status in (401, 403):
        return "maybe", f"HTTP {status} (exists, protected)"
    if status == 404:
        return "absent", "HTTP 404"
    normalized = normalize_body(body)
    if similarity(normalized, baseline.body) >= 0.985:
        return "soft-404", "body matches soft-404 baseline"
    if status == baseline.status and abs(len(body) - baseline.size) < 24:
        return "soft-404", "same shape as soft-404 baseline"
    return "maybe", f"HTTP {status}, body differs from baseline"


def run_scan(
    host: str,
    scope_name: str,
    tier: str = "high",
    delay: float = 0.4,
    max_requests: int = 120,
    include_maybe: bool = False,
    chain_git: bool = True,
) -> tuple[list, int]:
    validate_probe_target(host, scope_name)
    baseline = build_baseline(host)
    queue = list(rules_for(tier))
    seen: set[str] = set()
    findings = []
    sent = 0

    while queue and sent < max_requests:
        rule = queue.pop(0)
        if rule.path in seen:
            continue
        seen.add(rule.path)
        if sent and delay:
            time.sleep(delay)
        url = host.rstrip("/") + rule.path
        try:
            status, headers, body = fetch_page(url)
        except OSError:
            sent += 1
            continue
        sent += 1
        raw = as_bytes(body)
        verdict, reason = classify(rule, status, raw, baseline, headers.get("Content-Type", ""))
        if verdict not in ("exposed", "maybe"):
            continue
        if verdict == "maybe" and not include_maybe:
            continue
        excerpt = redact(raw[:200].decode("utf-8", "replace")) if verdict == "exposed" else ""
        findings.append(
            add_finding(
                scope=scope_name,
                kind="exposure",
                category="exposure",
                url=url,
                confidence="high" if verdict == "exposed" else "low",
                surface=rule.label,
                signal=reason,
                excerpt=excerpt,
                baseline_status=baseline.status,
                baseline_size=baseline.size,
                injected_status=status,
                injected_size=len(raw),
            )
        )
        if chain_git and rule.path == "/.git/HEAD":
            queue = [item for item in rules_for("high") if item.path.startswith("/.git/")] + queue
    return findings, sent


def render_scan(findings: list, sent: int) -> str:
    lines = [f"Exposure scan - {sent} requests, {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("Nothing matched a structural validator.")
        return "\n".join(lines)
    lines.extend(f"{item.id}  {item.confidence:<6}  {item.url}  <- {item.signal}" for item in findings)
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
