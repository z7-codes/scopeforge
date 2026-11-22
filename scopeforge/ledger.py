from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .models import Lead, utc_now
from .storage import read_json, write_json

LEADS_FILE = "leads.json"


def load_leads() -> list[dict[str, Any]]:
    value = read_json(LEADS_FILE, [])
    return value if isinstance(value, list) else []


def add_lead(scope: str, source: str, candidate: str, category: str, note: str = "") -> Lead:
    scope_name = str(scope).strip()
    candidate_name = str(candidate).strip()
    if not scope_name:
        raise ValueError("scope is required")
    if not candidate_name:
        raise ValueError("candidate is required")
    seed = f"{scope_name}|{candidate_name}|{utc_now()}|{uuid.uuid4().hex}"
    item = Lead(
        id="L-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8],
        scope=scope_name,
        source=str(source).strip(),
        candidate=candidate_name,
        category=str(category).strip().lower(),
        note=str(note).strip(),
    )
    leads = load_leads()
    leads.append(item.to_dict())
    write_json(LEADS_FILE, leads)
    return item


def list_leads(scope: str | None = None) -> list[Lead]:
    leads = [Lead.from_dict(value) for value in load_leads() if isinstance(value, dict)]
    if scope:
        leads = [item for item in leads if item.scope == scope]
    return leads


def render_leads(leads: list[Lead], fmt: str = "text") -> str:
    values = [item.to_dict() for item in leads]
    if fmt == "json":
        return json.dumps(values, indent=2)
    if fmt != "text":
        raise ValueError("format must be text or json")
    if not leads:
        return "No leads recorded."
    lines = [f"Lead ledger — {len(leads)} entries", ""]
    lines.extend(
        f"{item.id}  [{item.scope}/{item.category}]  {item.candidate}  <- {item.source or 'unknown source'}"
        for item in leads
    )
    return "\n".join(lines)
