from __future__ import annotations

import json
from functools import cache
from importlib.resources import files

from .errors import DataError


@cache
def load(name: str) -> dict:
    try:
        raw = files("scopeforge").joinpath("data").joinpath(f"{name}.json").read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, ModuleNotFoundError, json.JSONDecodeError) as exc:
        raise DataError(f"cannot load data/{name}.json: {exc}") from exc
    if not isinstance(value, dict):
        raise DataError(f"data/{name}.json must be an object")
    return value
