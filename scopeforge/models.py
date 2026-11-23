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
    def from_dict(cls, value: dict[str, Any]) -> Scope:
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
    def from_dict(cls, value: dict[str, Any]) -> Lead:
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


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched: str = ""


@dataclass(frozen=True)
class Verdict:
    hit: bool
    confidence: str = "low"
    signal: str = ""
    context: str = ""
    excerpt: str = ""
    error_family: str = ""


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
    def from_dict(cls, value: dict[str, Any]) -> Finding:
        known = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: value[key] for key in value if key in known})
