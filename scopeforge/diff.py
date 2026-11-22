from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

CSRF = re.compile(r'name=["\']?(csrf|_token|authenticity_token|__requestverificationtoken)[^>]*', re.IGNORECASE)
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
HEXISH = re.compile(r"\b[0-9a-f]{16,}\b")
EPOCH = re.compile(r"\b1[6-9]\d{8,12}\b")
ASSET_VER = re.compile(r"\?v=[\w.-]+")
BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
WHITESPACE = re.compile(r"\s+")

DIFFERENT = 0.92
SIZE_DELTA = 200


@dataclass(frozen=True)
class Comparison:
    similarity: float
    size_delta: int
    interesting: bool
    reason: str


def normalize(body: bytes) -> str:
    text = body.decode("utf-8", "replace")
    text = CSRF.sub(" ", text)
    text = UUID.sub("u", text)
    text = HEXISH.sub("h", text)
    text = EPOCH.sub("t", text)
    text = ASSET_VER.sub("?v=x", text)
    text = BASE64.sub("b", text)
    text = WHITESPACE.sub(" ", text)
    return text[:6000].strip().lower()


def compare(baseline: bytes, injected: bytes) -> Comparison:
    left = normalize(baseline)
    right = normalize(injected)
    ratio = 1.0 if left == right else SequenceMatcher(None, left, right).ratio()
    delta = len(injected) - len(baseline)
    if ratio < DIFFERENT:
        return Comparison(ratio, delta, True, f"body diverged (sim {ratio:.3f})")
    if abs(delta) > SIZE_DELTA:
        return Comparison(ratio, delta, True, f"size delta {delta:+d}")
    return Comparison(ratio, delta, False, f"no meaningful delta (sim {ratio:.3f})")
