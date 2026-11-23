from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from urllib.parse import urlsplit

from .errors import UsageError


@dataclass(frozen=True)
class Dork:
    category: str
    description: str
    query: str

    def to_dict(self) -> dict[str, str]:
        return {"category": self.category, "description": self.description, "query": self.query}


def _catalog() -> dict:
    raw = files("dorklens").joinpath("data").joinpath("dorks.json").read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get("categories"), dict):
        raise UsageError("dork catalog is invalid")
    return value


def normalize_domain(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise UsageError("domain is required")
    if "://" not in text:
        text = "//" + text
    parsed = urlsplit(text)
    host = (parsed.hostname or "").strip(".").lower()
    if not host or any(char.isspace() for char in host):
        raise UsageError("invalid domain: " + str(value))
    return host


def categories() -> tuple[str, ...]:
    return tuple(_catalog()["categories"])


def description(category: str) -> str:
    value = _catalog()["categories"].get(category)
    return str(value.get("description", "")) if isinstance(value, dict) else ""


def build(domain: str, category: str = "all", limit: int = 0) -> list[Dork]:
    target = normalize_domain(domain)
    catalog = _catalog()["categories"]
    selected = tuple(catalog) if category == "all" else (category,)
    unknown = [item for item in selected if item not in catalog]
    if unknown:
        raise UsageError("unknown category: " + ", ".join(unknown))
    records: list[Dork] = []
    for name in selected:
        entry = catalog[name]
        note = str(entry.get("description", ""))
        for template in entry.get("templates", []):
            query = str(template).replace("{domain}", target)
            records.append(Dork(name, note, query))
            if limit and len(records) >= limit:
                return records
    return records
