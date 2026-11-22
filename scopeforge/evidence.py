from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding
from .storage import ensure_data_dir


def folder() -> Path:
    path = ensure_data_dir() / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def path_for(scope: str) -> Path:
    return folder() / f"{scope}.json"


def to_record(finding: Finding, note: str = "") -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": "EV-" + finding.id[2:],
        "scope": finding.scope,
        "category": finding.category,
        "url": finding.url,
        "parameter": finding.parameter,
        "surface": finding.surface,
        "context": finding.context,
        "reflection": finding.reflection,
        "error_family": finding.error_family,
        "excerpt": finding.excerpt,
        "authorized": True,
        "manual_confirmed": True,
        "evidence_summary": note or finding.signal,
    }
    return {key: value for key, value in record.items() if value not in ("", None)}


def write(finding: Finding, note: str = "") -> Path:
    path = path_for(finding.scope)
    existing: list[Any] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            existing = loaded if isinstance(loaded, list) else []
        except json.JSONDecodeError:
            existing = []
    record = to_record(finding, note)
    existing = [item for item in existing if not (isinstance(item, dict) and item.get("id") == record["id"])]
    existing.append(record)
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return path
