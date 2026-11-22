from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def data_dir() -> Path:
    override = os.environ.get("SCOPEFORGE_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".scopeforge"


def ensure_data_dir() -> Path:
    path = data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(name: str, default: Any) -> Any:
    path = ensure_data_dir() / name
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_json(name: str, value: Any) -> Path:
    root = ensure_data_dir()
    path = root / name
    fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=str(root))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path
