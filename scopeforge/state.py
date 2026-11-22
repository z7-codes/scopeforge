from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .scope import safe_name
from .storage import ensure_data_dir


def run_key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def state_path(scope: str) -> Path:
    name = safe_name(scope)
    folder = ensure_data_dir() / "state"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{name}.jsonl"


def load_seen(scope: str) -> set[str]:
    path = state_path(scope)
    if not path.exists():
        return set()
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            seen.add(str(json.loads(line)["key"]))
        except (ValueError, KeyError):
            continue
    return seen


def remember(scope: str, key: str, note: str = "") -> None:
    with state_path(scope).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"key": key, "note": note}) + "\n")


def clear(scope: str) -> None:
    path = state_path(scope)
    if path.exists():
        path.unlink()
