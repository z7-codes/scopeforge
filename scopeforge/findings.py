from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from .analyzer import redact
from .models import utc_now
from .storage import read_json, write_json

FINDINGS_FILE = "findings.json"
STATUSES = ("new", "confirmed", "false-positive", "skipped")
CONFIDENCE = ("low", "medium", "high")


@dataclass(frozen=True)
class Finding:
    id: str
    scope: str
    kind: str
    category: str
    url: str
    request_url: str = ""
    parameter: str = ""
    payload: str = ""
    surface: str = ""
    context: str = ""
    reflection: bool = False
    error_family: str = ""
    confidence: str = "low"
    signal: str = ""
    excerpt: str = ""
    baseline_status: int = 0
    baseline_size: int = 0
    injected_status: int = 0
    injected_size: int = 0
    similarity: float = 1.0
    status: str = "new"
    note: str = ""
    created: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        known = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: value[key] for key in value if key in known})


def load_findings() -> list[dict[str, Any]]:
    value = read_json(FINDINGS_FILE, [])
    return value if isinstance(value, list) else []


def add_finding(
    scope: str,
    kind: str,
    category: str,
    url: str,
    confidence: str = "low",
    **extra: Any,
) -> Finding:
    if not str(scope).strip():
        raise ValueError("scope is required")
    if not str(url).strip():
        raise ValueError("url is required")
    if confidence not in CONFIDENCE:
        raise ValueError("confidence must be low, medium, or high")
    seed = f"{scope}|{url}|{extra.get('parameter', '')}|{extra.get('payload', '')}|{uuid.uuid4().hex}"
    item = Finding(
        id="f-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8],
        scope=str(scope).strip(),
        kind=str(kind).strip().lower(),
        category=str(category).strip().lower(),
        url=str(url).strip(),
        confidence=confidence,
        **extra,
    )
    findings = load_findings()
    findings.append(item.to_dict())
    write_json(FINDINGS_FILE, findings)
    return item


def get_finding(finding_id: str) -> Finding:
    for value in load_findings():
        if isinstance(value, dict) and value.get("id") == finding_id:
            return Finding.from_dict(value)
    raise ValueError("finding not found: " + finding_id)


def list_findings(scope: str | None = None, status: str | None = None) -> list[Finding]:
    items = [Finding.from_dict(value) for value in load_findings() if isinstance(value, dict)]
    if scope:
        items = [item for item in items if item.scope == scope]
    if status:
        items = [item for item in items if item.status == status]
    return items


def set_status(finding_id: str, status: str, note: str = "") -> Finding:
    if status not in STATUSES:
        raise ValueError("status must be " + ", ".join(STATUSES))
    findings = load_findings()
    updated: Finding | None = None
    for value in findings:
        if isinstance(value, dict) and value.get("id") == finding_id:
            value["status"] = status
            if note:
                value["note"] = redact(note)
            updated = Finding.from_dict(value)
            break
    if updated is None:
        raise ValueError("finding not found: " + finding_id)
    write_json(FINDINGS_FILE, findings)
    return updated


def to_evidence(finding: Finding, note: str = "") -> dict[str, Any]:
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


def render_findings(items: list[Finding], fmt: str = "text") -> str:
    if fmt == "json":
        import json

        return json.dumps([item.to_dict() for item in items], indent=2)
    if fmt != "text":
        raise ValueError("format must be text or json")
    if not items:
        return "No findings recorded."
    lines = [f"Findings - {len(items)}", ""]
    lines.extend(
        f"{item.id}  [{item.kind}/{item.category}]  {item.confidence:<6}  {item.status:<14}  {item.url}"
        for item in items
    )
    return "\n".join(lines)
