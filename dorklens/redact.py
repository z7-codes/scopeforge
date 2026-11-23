from __future__ import annotations

import re

SENSITIVE_PARAMS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "access_key",
    "private_key",
    "authorization",
)
KEY_PATTERN = re.compile(r"(?i)([?&](?:" + "|".join(SENSITIVE_PARAMS) + r")=)[^&\s\"']+")
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
TOKEN_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\b")
HEX_PATTERN = re.compile(r"\b[A-Fa-f0-9]{32,}\b")


def redact(value: object) -> str:
    text = str(value or "")
    text = KEY_PATTERN.sub(r"\1[redacted]", text)
    text = EMAIL_PATTERN.sub("[email]", text)
    text = TOKEN_PATTERN.sub("[token]", text)
    text = HEX_PATTERN.sub("[hex]", text)
    return text[:500]
