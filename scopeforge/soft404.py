from __future__ import annotations

import random
import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from .errors import BudgetExhausted
from .net import Session
from .validators import Validator

HEXISH = re.compile(r"\b[0-9a-f]{16,}\b")
DIGITS = re.compile(r"\d+")
WHITESPACE = re.compile(r"\s+")
SOFT_THRESHOLD = 0.985
SIZE_TOLERANCE = 24


@dataclass(frozen=True)
class Baseline:
    status: int
    size: int
    body: str


def random_path() -> str:
    return "z7sf-" + "".join(random.choice("abcdef0123456789") for _ in range(12))


def normalize(body: bytes) -> str:
    text = body.decode("utf-8", "replace").lower()
    text = HEXISH.sub("h", text)
    text = DIGITS.sub("0", text)
    text = WHITESPACE.sub(" ", text)
    return text[:4000].strip()


def similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


def build(session: Session, host: str, samples: int = 3) -> Baseline:
    collected: list[Baseline] = []
    for _ in range(samples):
        try:
            response = session.get(host.rstrip("/") + "/" + random_path())
        except BudgetExhausted:
            raise
        except Exception:
            continue
        collected.append(Baseline(response.status, len(response.body), normalize(response.body)))
    if not collected:
        raise ValueError("baseline requests failed for " + host)
    collected.sort(key=lambda item: item.size)
    return collected[len(collected) // 2]


def classify(
    validator: Validator | None,
    status: int,
    body: bytes,
    baseline: Baseline,
    ctype: str,
) -> tuple[str, str]:
    if status >= 500:
        return "error", f"HTTP {status}"
    if validator and validator(body, ctype):
        return "exposed", "structural match"
    if status in (401, 403):
        return "maybe", f"HTTP {status} (exists, protected)"
    if status == 404:
        return "absent", "HTTP 404"
    normalized = normalize(body)
    if similarity(normalized, baseline.body) >= SOFT_THRESHOLD:
        return "soft-404", "body matches soft-404 baseline"
    if status == baseline.status and abs(len(body) - baseline.size) < SIZE_TOLERANCE:
        return "soft-404", "same shape as soft-404 baseline"
    return "maybe", f"HTTP {status}, body differs from baseline"
