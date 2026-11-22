from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Scope:
    name: str
    domains: list[str]
    exclusions: list[str] = field(default_factory=list)
    source: str = ""
    created: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Scope":
        return cls(
            name=str(value.get("name", "")),
            domains=[str(item) for item in value.get("domains", [])],
            exclusions=[str(item) for item in value.get("exclusions", [])],
            source=str(value.get("source", "")),
            created=str(value.get("created") or utc_now()),
        )


@dataclass(frozen=True)
class Lead:
    id: str
    scope: str
    source: str
    candidate: str
    category: str
    note: str = ""
    status: str = "new"
    created: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Lead":
        return cls(
            id=str(value.get("id", "")),
            scope=str(value.get("scope", "")),
            source=str(value.get("source", "")),
            candidate=str(value.get("candidate", "")),
            category=str(value.get("category", "")),
            note=str(value.get("note", "")),
            status=str(value.get("status", "new")),
            created=str(value.get("created") or utc_now()),
        )
