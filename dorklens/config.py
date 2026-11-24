from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .scope import Scope

DATA = Path(__file__).parent / "data"
TAGLINE = "point it, and it sees"


@dataclass
class Config:
    domain: str
    scope: Scope
    stages: list[str] = field(default_factory=lambda: ["passive", "dork", "dirs", "payload"])
    max_dork_queries: int = 40
    schemes: list[str] = field(default_factory=lambda: ["http", "https"])
    concurrency: int = 8
    rps_per_host: float = 3.0
    timeout: float = 15.0
    retries: int = 2
    insecure: bool = False
    deep: bool = False
    dry_run: bool = False
    post: bool = False
    post_paths: list[str] = field(default_factory=list)
    proxy: str | None = None
    user_agent: str = "dorklens/1.0 (+authorized testing)"
    min_confidence: int = 2
    max_payload_urls: int = 200
    out_dir: Path = Path("dorklens-out")
    backends: list[str] = field(default_factory=lambda: ["mojeek", "ddg"])
    wordlist: Path = DATA / "wordlist.txt"
    dorks: Path = DATA / "dorks.yaml"
    payloads: Path = DATA / "payloads.yaml"

    def _resolve_paths(self, base: Path) -> Config:
        for key in ("wordlist", "dorks", "payloads"):
            value = getattr(self, key)
            if isinstance(value, str):
                path = Path(value)
                setattr(self, key, path if path.is_absolute() else base / path)
        return self

    def apply_profile(self, name: str) -> Config:
        raw = yaml.safe_load((DATA / "profiles.yaml").read_text(encoding="utf-8")) or {}
        if name not in raw:
            raise ValueError(f"unknown profile: {name}")
        for key, value in raw[name].items():
            setattr(self, key, value)
        return self._resolve_paths(DATA)

    @classmethod
    def from_file(cls, path: str) -> Config:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or not raw.get("domain"):
            raise ValueError("config missing domain")
        domain = str(raw["domain"])
        scope_raw = raw.get("scope") or {}
        scope = Scope(
            allow=scope_raw.get("allow") or [domain, f"*.{domain}"],
            deny=scope_raw.get("deny") or [],
        )
        known = set(cls.__dataclass_fields__) - {"domain", "scope"}
        values: dict[str, Any] = {key: value for key, value in raw.items() if key in known}
        if "out_dir" in values:
            values["out_dir"] = Path(values["out_dir"])
        if not values.get("proxy") and os.environ.get("DORKLENS_PROXY"):
            values["proxy"] = os.environ["DORKLENS_PROXY"]
        config = cls(domain=domain, scope=scope, **values)._resolve_paths(Path.cwd())
        profile = raw.get("profile")
        if profile:
            config.apply_profile(str(profile))
        return config

    @classmethod
    def from_domain(cls, domain: str, **kwargs: Any) -> Config:
        return cls(
            domain=domain,
            scope=Scope(allow=[domain, f"*.{domain}"]),
            **kwargs,
        )
