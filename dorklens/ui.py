from __future__ import annotations

import os
import sys

COLORS = {
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "reset": "\033[0m",
}


def color(text: str, name: str = "cyan") -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return COLORS.get(name, "") + text + COLORS["reset"]


def banner() -> str:
    line = "=" * 68
    return "\n".join(
        [
            line,
            color("  DORKLENS  ::  PUBLIC EXPOSURE DISCOVERY", "bold"),
            line,
        ]
    )


def section(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}"
