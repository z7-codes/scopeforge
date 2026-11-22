from __future__ import annotations

import time
from dataclasses import dataclass, field

from .errors import BudgetExhausted


@dataclass
class Budget:
    max_requests: int = 300
    max_per_host: int = 120
    delay: float = 0.4
    sent: int = 0
    per_host: dict[str, int] = field(default_factory=dict)

    def remaining(self) -> int:
        return max(0, self.max_requests - self.sent)

    def spend(self, host: str) -> None:
        if self.sent >= self.max_requests:
            raise BudgetExhausted(f"global request budget reached ({self.max_requests})")
        if self.per_host.get(host, 0) >= self.max_per_host:
            raise BudgetExhausted(f"per-host budget reached for {host} ({self.max_per_host})")
        if self.sent and self.delay > 0:
            time.sleep(self.delay)
        self.sent += 1
        self.per_host[host] = self.per_host.get(host, 0) + 1

    def snapshot(self) -> dict[str, object]:
        return {"sent": self.sent, "max_requests": self.max_requests, "per_host": dict(self.per_host)}
