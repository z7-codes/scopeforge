from __future__ import annotations

import json
from pathlib import Path

from .errors import UsageError
from .search import SearchHit, SearchResult

SENSITIVE_MARKERS = (
    ".env",
    ".git/",
    "id_rsa",
    "private_key",
    "credentials",
    "secrets",
    "wp-config",
    "api_key",
    "secret_key",
    "access_key",
    "database_password",
    "backup",
    ".sql",
    ".zip",
    ".tar",
    ".bak",
)
DIRECTORY_MARKERS = ("index of", "parent directory", "directory listing")
ADMIN_MARKERS = ("admin", "login", "signin", "phpmyadmin", "adminer", "jenkins", "grafana", "kibana", "console")
PARAMETER_MARKERS = ("inurl:?", "id=", "file=", "path=", "url=", "redirect=", "download=", "include=", "template=")
DEVELOPMENT_MARKERS = ("staging", "dev", "test", "sandbox", "preview", "internal")

PRIORITY_ORDER = {
    "High-priority exposure signal": 0,
    "Directory exposure signal": 1,
    "Administrative surface signal": 2,
    "Development surface signal": 3,
    "Parameter surface signal": 4,
    "Public information signal": 5,
}


def classify(hit: SearchHit) -> tuple[str, str]:
    haystack = " ".join((hit.url, hit.query, hit.category)).lower()
    if any(marker in haystack for marker in SENSITIVE_MARKERS):
        return (
            "High-priority exposure signal",
            "Publicly indexed sensitive material. Confirm ownership, check context, and follow the disclosure process.",
        )
    if any(marker in haystack for marker in DIRECTORY_MARKERS):
        return (
            "Directory exposure signal",
            "A directory index may be public. Confirm whether contents are sensitive and restrict access if needed.",
        )
    if any(marker in haystack for marker in ADMIN_MARKERS):
        return (
            "Administrative surface signal",
            "An administrative surface is indexed. Confirm authentication, exposure, and intended access policy.",
        )
    if any(marker in haystack for marker in DEVELOPMENT_MARKERS):
        return (
            "Development surface signal",
            "A non-production surface is indexed. Confirm it is intended to be public and protected.",
        )
    if any(marker in haystack for marker in PARAMETER_MARKERS):
        return (
            "Parameter surface signal",
            "A parameterized URL is indexed. Review parameters manually with permission and record observations.",
        )
    return (
        "Public information signal",
        "Publicly indexed information. Review context and decide whether any follow-up is warranted.",
    )


def _cell(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(result: SearchResult) -> str:
    ranked = sorted(
        result.hits,
        key=lambda item: (PRIORITY_ORDER.get(classify(item)[0], 9), item.url),
    )
    counts: dict[str, int] = {}
    for hit in result.hits:
        label = classify(hit)[0]
        counts[label] = counts.get(label, 0) + 1

    lines = [
        "# DorkLens Public Exposure Report",
        "",
        f"- Domain: {result.domain}",
        f"- Category: {result.category}",
        f"- Provider: {result.provider}",
        f"- Queries generated: {len(result.queries)}",
        f"- Results collected: {len(result.hits)}",
        "",
        "## Reading this report",
        "",
        "Results are public search signals, not automatic verdicts. Confirm ownership, check the live context, "
        "and follow the official disclosure process before taking action.",
        "",
        "## Signal summary",
        "",
        "| Signal | Count |",
        "|---|---:|",
    ]
    for label in sorted(counts, key=lambda item: PRIORITY_ORDER.get(item, 9)):
        lines.append(f"| {label} | {counts[label]} |")
    if not counts:
        lines.append("| No signals | 0 |")

    lines.extend(
        [
            "",
            "## Collected results",
            "",
            "| Priority | URL | Why it matters | Next step | Source dork |",
            "|---|---|---|---|---|",
        ]
    )
    for hit in ranked:
        label, reason = classify(hit)
        lines.append(
            "| "
            + " | ".join(
                (
                    _cell(label),
                    _cell(hit.url),
                    _cell(reason),
                    _cell("Manual verification required."),
                    _cell(hit.query),
                )
            )
            + " |"
        )
    if not ranked:
        lines.append("| No results | - | - | - | - |")

    if result.warnings:
        lines.extend(["", "## Provider warnings", ""])
        for warning in result.warnings:
            lines.append(f"- {warning}")

    lines.extend(
        [
            "",
            "## Verification checklist",
            "",
            "- [ ] Confirm the result belongs to the intended target.",
            "- [ ] Open the public result and record what is actually visible.",
            "- [ ] Check ownership and intended exposure policy.",
            "- [ ] Keep evidence local and redacted.",
            "- [ ] Submit through the official channel only.",
            "",
        ]
    )
    return "\n".join(lines)


def render_text(result: SearchResult) -> str:
    lines = ["DorkLens Results", f"Domain: {result.domain}", f"Results: {len(result.hits)}", ""]
    for hit in sorted(result.hits, key=lambda item: item.url):
        label, _reason = classify(hit)
        lines.append(f"[{label}] {hit.url}")
        lines.append(f"  dork: {hit.query}")
    if not result.hits:
        lines.append("No public results found.")
    return "\n".join(lines)


def render_json(result: SearchResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


def load_results(path: str) -> SearchResult:
    raw = Path(path).read_text(encoding="utf-8")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError("invalid results JSON: " + str(exc)) from exc
    if not isinstance(value, dict):
        raise UsageError("results JSON must be an object")
    hits: list[SearchHit] = []
    for item in value.get("hits", []):
        if isinstance(item, dict):
            hits.append(
                SearchHit(
                    url=str(item.get("url", "")),
                    query=str(item.get("query", "")),
                    category=str(item.get("category", "")),
                    provider=str(item.get("provider", "")),
                )
            )
    return SearchResult(
        domain=str(value.get("domain", "")),
        category=str(value.get("category", "all")),
        provider=str(value.get("provider", "auto")),
        queries=[str(item) for item in value.get("queries", []) if isinstance(item, str)],
        hits=hits,
        warnings=[str(item) for item in value.get("warnings", []) if isinstance(item, str)],
    )
