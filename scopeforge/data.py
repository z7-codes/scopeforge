from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .errors import DataError

DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    path = DATA_DIR / f"{name}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DataError(f"cannot load data/{name}.json: {exc}") from exc
    if not isinstance(value, dict):
        raise DataError(f"data/{name}.json must be an object")
    return value
