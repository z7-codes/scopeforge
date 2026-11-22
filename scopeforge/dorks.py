from __future__ import annotations

import hashlib
import json
from typing import Any

from .scope import base_domain
from .models import Scope

CATEGORIES = ("recon", "exposure", "sqli", "xss", "ctf")

TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "recon": [
        ("robots", "site:{domain} inurl:robots.txt"),
        ("sitemap", "site:{domain} inurl:sitemap.xml"),
        ("docs", "site:{domain} inurl:/docs"),
        ("api-docs", "site:{domain} inurl:/api"),
        ("status", "site:{domain} inurl:/status"),
        ("security-txt", "site:{domain} inurl:security.txt"),
        ("changelog", "site:{domain} inurl:/changelog"),
    ],
    "exposure": [
        ("public-pdf", "site:{domain} ext:pdf"),
        ("public-csv", "site:{domain} ext:csv"),
        ("sample-config", "site:{domain} inurl:/sample"),
        ("legacy-path", "site:{domain} inurl:/legacy"),
        ("backup-label", "site:{domain} inurl:/backup"),
        ("public-directory", "site:{domain} inurl:/public"),
    ],
    "sqli": [
        ("id-surface", "site:{domain} inurl:?id="),
        ("product-surface", "site:{domain} inurl:/product?"),
        ("category-surface", "site:{domain} inurl:/category?"),
        ("search-surface", "site:{domain} inurl:/search?"),
        ("report-surface", "site:{domain} inurl:/report?"),
    ],
    "xss": [
        ("query-surface", "site:{domain} inurl:?q="),
        ("search-surface", "site:{domain} inurl:/search?q="),
        ("ref-surface", "site:{domain} inurl:?ref="),
        ("redirect-surface", "site:{domain} inurl:/redirect?"),
        ("profile-surface", "site:{domain} inurl:/user?"),
    ],
    "ctf": [
        ("challenge-hints", "site:{domain} inurl:/challenge"),
        ("static-assets", "site:{domain} ext:js"),
        ("notes", "site:{domain} inurl:/note"),
        ("admin-label", "site:{domain} inurl:/admin"),
    ],
}

SAFETY = "scoped discovery only; no payloads, no automated requests"


def make_id(value: str) -> str:
    return "q-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def build_plan(scope: Scope, category: str, limit: int = 50) -> list[dict[str, Any]]:
    key = str(category).strip().lower()
    if key not in TEMPLATES:
        raise ValueError("unknown category: " + str(category))
    if limit < 1:
        raise ValueError("limit must be at least 1")
    domains = [base_domain(item) for item in scope.domains]
    records: list[dict[str, Any]] = []
    for domain in domains:
        for technique, template in TEMPLATES[key]:
            if len(records) >= limit:
                return records
            query = template.format(domain=domain)
            records.append(
                {
                    "id": make_id(query),
                    "scope": scope.name,
                    "domain": domain,
                    "category": key,
                    "technique": technique,
                    "query": query,
                    "safety": SAFETY,
                }
            )
    return records


def render_plan(records: list[dict[str, Any]], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(records, indent=2)
    if fmt == "md":
        lines = ["# ScopeForge Dork Plan", "", f"Queries: {len(records)}", ""]
        lines.append("| ID | Category | Query |")
        lines.append("|---|---|---|")
        lines.extend(f"| {item['id']} | {item['category']} | `{item['query']}` |" for item in records)
        lines.extend(["", f"Safety: {SAFETY}"])
        return "\n".join(lines)
    if fmt != "text":
        raise ValueError("format must be text, json, or md")
    lines = [f"ScopeForge plan — {len(records)} queries", ""]
    lines.extend(f"{item['id']}  [{item['category']}/{item['technique']}]  {item['query']}" for item in records)
    lines.extend(["", SAFETY])
    return "\n".join(lines)
