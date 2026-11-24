from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


class ScopeError(ValueError):
    pass


@dataclass
class Scope:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._allow = [self._norm(item) for item in self.allow if item and item.strip()]
        self._deny = [self._norm(item) for item in self.deny if item and item.strip()]
        if not self._allow:
            raise ScopeError("scope is empty - at least one domain is required")

    @staticmethod
    def _norm(host: str) -> str:
        text = host.strip().lower()
        for prefix in ("http://", "https://"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
        return text.split("/")[0].split(":")[0].strip(".")

    @staticmethod
    def _match(host: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if pattern.startswith("*."):
                root = pattern[2:]
                if host == root or host.endswith("." + root):
                    return True
            elif fnmatch.fnmatch(host, pattern):
                return True
        return False

    def in_scope(self, host: str | None) -> bool:
        if not host:
            return False
        text = host.lower().strip(".")
        if self._deny and self._match(text, self._deny):
            return False
        return self._match(text, self._allow)
