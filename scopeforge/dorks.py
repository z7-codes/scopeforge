from __future__ import annotations

import hashlib
import json

from .data import load
from .models import Scope
from .scope import base_domain

SAFETY = "scoped discovery only; no payloads, no automated requests"
CATEGORIES = tuple(load("dorks").get("categories", {}))


def make_id(value: str) -> str:
    return "q-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def build_plan(scope: Scope, category: str, limit: int = 50) -> list[dict]:
    key = str(category).strip().lower()
    library = load("dorks").get("categories", {})
    if key not in library:
        raise ValueError("unknown category: " + str(category))
    if limit < 1:
        raise ValueError("limit must be at least 1")
    records: list[dict] = []
    for domain in [base_domain(item) for item in scope.domains]:
        for entry in library[key]:
            if len(records) >= limit:
                return records
            query = str(entry["query"]).format(domain=domain)
            records.append(
                {
                    "id": make_id(query),
                    "scope": scope.name,
                    "domain": domain,
                    "category": key,
                    "technique": str(entry["technique"]),
                    "query": query,
                    "safety": SAFETY,
                }
            )
    return records


def render_plan(records: list[dict], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(records, indent=2)
    if fmt == "md":
        lines = ["# ScopeForge Dork Plan", "", f"Queries: {len(records)}", "", "| ID | Category | Query |", "|---|---|---|"]
        lines.extend(f"| {item['id']} | {item['category']} | `{item['query']}` |" for item in records)
        lines.extend(["", f"Safety: {SAFETY}"])
        return "\n".join(lines)
    if fmt != "text":
        raise ValueError("format must be text, json, or md")
    lines = [f"ScopeForge plan - {len(records)} queries", ""]
    lines.extend(f"{item['id']}  [{item['category']}/{item['technique']}]  {item['query']}" for item in records)
    lines.extend(["", SAFETY])
    return "\n".join(lines)
