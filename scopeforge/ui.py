from __future__ import annotations

import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import TextIO

from .storage import ensure_data_dir

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

CODES = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def color(text: str, name: str) -> str:
    if not USE_COLOR:
        return text
    return f"{CODES.get(name, '')}{text}{CODES['reset']}"


def banner(version: str) -> None:
    print(color("  ==========================================================", "cyan"))
    print(color("   SCOPEFORGE  ::  AUTHORIZED RECON CONSOLE", "cyan"))
    print(color("  ==========================================================", "cyan"))
    print(f"  {color(f'ScopeForge {version}', 'bold')}  |  scope-safe recon  |  offline-first")
    print()


def log_dir(scope: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", scope or "session").strip("._") or "session"
    path = ensure_data_dir() / "logs" / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def session_log(scope: str) -> TextIO:
    path = log_dir(scope) / time.strftime("session-%Y%m%d-%H%M%S.log")
    return path.open("a", encoding="utf-8")


def tee(line: str, log: TextIO | None = None, *, stream: TextIO | None = None) -> None:
    target = stream or sys.stdout
    print(line, file=target)
    if log is not None:
        log.write(line + "\n")
        log.flush()


def info(line: str, log: TextIO | None = None) -> None:
    tee(color("[*]", "cyan") + " " + line, log)


def ok(line: str, log: TextIO | None = None) -> None:
    tee(color("[+]", "green") + " " + line, log)


def warn(line: str, log: TextIO | None = None) -> None:
    tee(color("[!]", "yellow") + " " + line, log, stream=sys.stderr)


def error(line: str, log: TextIO | None = None) -> None:
    tee(color("[x]", "red") + " " + line, log, stream=sys.stderr)


def trap_sigint() -> None:
    def handler(_signum: int, _frame: object) -> None:
        print("\ninterrupted - local state is saved", file=sys.stderr)
        raise SystemExit(130)

    signal.signal(signal.SIGINT, handler)
