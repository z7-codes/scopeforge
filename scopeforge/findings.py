from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .analyzer import redact
from .models import Finding
from .storage import read_json, write_json

FINDINGS_FILE = "findings.json"
STATUSES = ("new", "confirmed", "false-positive", "skipped")
CONFIDENCE = ("low", "medium", "high")


def load() -> list[dict[str, Any]]:
    value = read_json(FINDINGS_FILE, [])
    return value if isinstance(value, list) else []


def add(scope: str, kind: str, category: str, url: str, confidence: str = "low", **extra: Any) -> Finding:
    if not str(scope).strip():
        raise ValueError("scope is required")
    if not str(url).strip():
        raise ValueError("url is required")
    if confidence not in CONFIDENCE:
        raise ValueError("confidence must be low, medium, or high")
    reserved = {"id", "scope", "kind", "category", "url", "confidence"}
    clash = reserved.intersection(extra)
    if clash:
        raise ValueError("duplicate finding field: " + ", ".join(sorted(clash)))
    seed = f"{scope}|{url}|{extra.get('parameter', '')}|{extra.get('payload', '')}|{uuid.uuid4().hex}"
    finding = Finding(
        id="f-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8],
        scope=str(scope).strip(),
        kind=str(kind).strip().lower(),
        category=str(category).strip().lower(),
        url=str(url).strip(),
        confidence=confidence,
        **extra,
    )
    items = load()
    items.append(finding.to_dict())
    write_json(FINDINGS_FILE, items)
    return finding


def get(finding_id: str) -> Finding:
    for value in load():
        if isinstance(value, dict) and value.get("id") == finding_id:
            return Finding.from_dict(value)
    raise ValueError("finding not found: " + finding_id)


def list_all(scope: str | None = None, status: str | None = None, min_confidence: str = "low") -> list[Finding]:
    floor = CONFIDENCE.index(min_confidence)
    items = [Finding.from_dict(value) for value in load() if isinstance(value, dict)]
    if scope:
        items = [item for item in items if item.scope == scope]
    if status:
        items = [item for item in items if item.status == status]
    items = [item for item in items if CONFIDENCE.index(item.confidence) >= floor]
    order = {key: index for index, key in enumerate(CONFIDENCE)}
    items.sort(key=lambda item: (order[item.confidence], item.created), reverse=True)
    return items


def set_status(finding_id: str, status: str, note: str = "") -> Finding:
    if status not in STATUSES:
        raise ValueError("status must be " + ", ".join(STATUSES))
    items = load()
    updated: Finding | None = None
    for value in items:
        if isinstance(value, dict) and value.get("id") == finding_id:
            value["status"] = status
            if note:
                value["note"] = redact(note)
            updated = Finding.from_dict(value)
            break
    if updated is None:
        raise ValueError("finding not found: " + finding_id)
    write_json(FINDINGS_FILE, items)
    return updated


def render(items: list[Finding], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps([item.to_dict() for item in items], indent=2)
    if fmt != "text":
        raise ValueError("format must be text or json")
    if not items:
        return "No findings recorded."
    lines = [f"Findings - {len(items)}", ""]
    lines.extend(
        f"{item.id}  {item.confidence:<6}  {item.status:<14}  [{item.category}]  {item.url}" for item in items
    )
    return "\n".join(lines)
