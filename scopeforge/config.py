from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .storage import read_json, write_json

CONFIG_FILE = "config.json"


@dataclass(frozen=True)
class Config:
    delay: float = 0.4
    max_requests: int = 300
    max_per_host: int = 120
    max_urls: int = 25
    max_params: int = 5
    max_queries: int = 40
    timeout: float = 8.0
    max_bytes: int = 65536
    provider: str = "auto"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_config() -> Config:
    value = read_json(CONFIG_FILE, {})
    if not isinstance(value, dict):
        return Config()
    known = set(Config.__dataclass_fields__)
    return Config(**{key: value[key] for key in value if key in known})


def set_value(key: str, raw: str) -> Config:
    config = load_config()
    if key not in Config.__dataclass_fields__:
        raise ValueError("unknown config key: " + key)
    current = getattr(config, key)
    if isinstance(current, bool):
        value: Any = raw.strip().lower() in ("1", "true", "yes", "on")
    elif isinstance(current, int):
        value = int(raw)
    elif isinstance(current, float):
        value = float(raw)
    else:
        value = raw.strip()
    updated = Config(**{**config.to_dict(), key: value})
    write_json(CONFIG_FILE, updated.to_dict())
    return updated
