from __future__ import annotations

import os
import signal
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Any, TextIO

from . import __version__, ui
from .scope import list_scopes
from .storage import ensure_data_dir, read_json, write_json

TUI_STATE_FILE = "tui-state.json"
DEFAULT_STATE: dict[str, Any] = {"active_scope": "", "devil": False, "lab": False}
LAB_PORT = "8099"

MENUS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "main": (
        ("1", "Scopes and targets", "menu:scopes"),
        ("2", "Passive recon", "menu:passive"),
        ("3", "Active checks", "menu:active"),
        ("4", "Findings and reports", "menu:findings"),
        ("5", "Offline lab", "menu:lab"),
        ("d", "Devil mode toggle", "action:devil"),
        ("s", "Select active scope", "action:scope-select"),
        ("0", "Exit", "action:exit"),
    ),
    "scopes": (
        ("1", "List scopes", "action:scope-list"),
        ("2", "Add scope", "action:scope-add"),
        ("3", "Select active scope", "action:scope-select"),
        ("4", "Show active scope", "action:scope-show"),
        ("0", "Back", "menu:main"),
    ),
    "passive": (
        ("1", "Dork plan", "action:plan"),
        ("2", "Passive search", "action:search"),
        ("3", "Exposure worksheet", "action:exposure"),
        ("0", "Back", "menu:main"),
    ),
    "active": (
        ("1", "Exposure scan", "action:scan"),
        ("2", "Benign param probe", "action:probe"),
        ("3", "Authorized payload ladder", "action:inject"),
        ("0", "Back", "menu:main"),
    ),
    "findings": (
        ("1", "List findings", "action:findings"),
        ("2", "Verify finding", "action:verify"),
        ("3", "Analyze evidence", "action:analyze"),
        ("4", "Render report", "action:report"),
        ("0", "Back", "menu:main"),
    ),
    "lab": (
        ("1", "Start lab server", "action:lab-start"),
        ("2", "Stop lab server", "action:lab-stop"),
        ("3", "Lab server status", "action:lab-status"),
        ("4", "Open lab URL", "action:lab-open"),
        ("5", "Scenario guide", "action:lab-guide"),
        ("0", "Back", "menu:main"),
    ),
}


def load_state() -> dict[str, Any]:
    value = read_json(TUI_STATE_FILE, {})
    if not isinstance(value, dict):
        return dict(DEFAULT_STATE)
    active = value.get("active_scope") or value.get("scope") or ""
    return {
        "active_scope": str(active),
        "devil": bool(value.get("devil", False)),
        "lab": bool(value.get("lab", False)),
    }


def save_state(state: dict[str, Any]) -> None:
    write_json(TUI_STATE_FILE, dict(state))


def _prompt(label: str, default: str = "") -> str:
    value = input(f"{label}{f' [{default}]' if default else ''}: ").strip()
    return value or default


def _scope(state: dict[str, Any]) -> str:
    return _prompt("scope", state["active_scope"])


def _argv_scope(state: dict[str, Any]) -> list[str]:
    return ["--scope", _scope(state)] if not state["lab"] else ["--lab"]


def _owned() -> list[str]:
    return ["--i-own-this"]


def _run(argv: list[str], log: TextIO | None) -> int:
    from .cli import main

    ui.info("$ " + " ".join(argv), log)
    return main(argv)


def _pid_file() -> Path:
    return ensure_data_dir() / "lab-serve.pid"


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _lab_pid() -> int | None:
    path = _pid_file()
    if not path.exists():
        return None
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        path.unlink(missing_ok=True)
        return None
    if not _pid_alive(pid):
        path.unlink(missing_ok=True)
        return None
    return pid


def _lab_start(log: TextIO | None) -> int:
    pid = _lab_pid()
    if pid is not None:
        ui.warn(f"lab server already running (pid {pid})", log)
        return 0
    command = [sys.executable, "-m", "scopeforge", "--skip-preflight", "lab", "serve", "--port", LAB_PORT]
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
        process = subprocess.Popen(command, creationflags=flags)
    else:
        process = subprocess.Popen(command, start_new_session=True)
    _pid_file().write_text(str(process.pid), encoding="utf-8")
    ui.ok(f"lab server started on http://127.0.0.1:{LAB_PORT} (pid {process.pid})", log)
    return 0


def _lab_stop(log: TextIO | None) -> int:
    pid = _lab_pid()
    if pid is None:
        ui.warn("lab server is not running", log)
        return 0
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, check=False)
    else:
        os.kill(pid, signal.SIGTERM)
    _pid_file().unlink(missing_ok=True)
    ui.ok(f"lab server stopped (pid {pid})", log)
    return 0


def _lab_status(log: TextIO | None) -> int:
    pid = _lab_pid()
    if pid is None:
        ui.info(f"lab server stopped | http://127.0.0.1:{LAB_PORT}", log)
    else:
        ui.ok(f"lab server running | pid {pid} | http://127.0.0.1:{LAB_PORT}", log)
    return 0


def _run_action(action: str, state: dict[str, Any], log: TextIO | None) -> tuple[int, str | None]:
    if action.startswith("menu:"):
        return 0, action.split(":", 1)[1]
    if action == "exit":
        return 0, "__exit__"
    if action == "devil":
        state["devil"] = not state["devil"]
        save_state(state)
        ui.ok(f"devil mode {'on' if state['devil'] else 'off'}", log)
        return 0, None
    if action == "scope-select":
        state["active_scope"] = _prompt("active scope", state["active_scope"])
        save_state(state)
        ui.ok("active scope: " + state["active_scope"], log)
        return 0, None
    if action == "scope-list":
        return _run(["scope", "list"], log), None
    if action == "scope-add":
        name = _prompt("name")
        domains = [item.strip() for item in _prompt("domains (comma separated)").split(",") if item.strip()]
        source = _prompt("scope source")
        return _run(["scope", "add", name, *domains, "--source", source], log), None
    if action == "scope-show":
        return _run(["scope", "show", _scope(state)], log), None
    if action == "plan":
        return _run(["plan", _scope(state), "--category", _prompt("category", "recon")], log), None
    if action == "search":
        return _run(["search", _scope(state), "--category", _prompt("category", "exposure")], log), None
    if action == "exposure":
        return _run(
            ["exposure", _prompt("domain"), "--scope", _scope(state), "--source", _prompt("scope source")],
            log,
        ), None
    if action == "scan":
        argv = ["scan", _prompt("host url"), *_owned(), *_argv_scope(state)]
        return _run(argv, log), None
    if action == "probe":
        argv = ["probe", _prompt("url"), *_owned(), *_argv_scope(state)]
        return _run(argv, log), None
    if action == "inject":
        argv = [
            "inject",
            _prompt("url"),
            *_owned(),
            *_argv_scope(state),
            "--classes",
            _prompt("classes (comma separated)", "sqli_boolean,xss_reflect"),
            "--max-classes",
            _prompt("max classes", "2"),
        ]
        return _run(argv, log), None
    if action == "findings":
        argv = ["findings", "list"]
        if state["devil"]:
            argv.append("--devil")
        if state["active_scope"]:
            argv.extend(["--scope", state["active_scope"]])
        return _run(argv, log), None
    if action == "verify":
        return _run(["verify", _prompt("finding id"), "--status", _prompt("status", "confirmed")], log), None
    if action == "analyze":
        return _run(["analyze", _prompt("evidence json path"), "--format", _prompt("format", "text")], log), None
    if action == "report":
        return _run(
            [
                "report",
                _prompt("analysis json path"),
                "--scope",
                _scope(state),
                "--scope-source",
                _prompt("scope source"),
            ],
            log,
        ), None
    if action == "lab-start":
        return _lab_start(log), None
    if action == "lab-stop":
        return _lab_stop(log), None
    if action == "lab-status":
        return _lab_status(log), None
    if action == "lab-open":
        webbrowser.open(f"http://127.0.0.1:{LAB_PORT}")
        return 0, None
    if action == "lab-guide":
        return _run(["lab", "localhost"], log), None
    return 2, None


def _header(state: dict[str, Any], current: str, last: int) -> None:
    devil = "on" if state["devil"] else "off"
    lab = "on" if state["lab"] else "off"
    print()
    print(ui.color(f"  {current.upper()}  |  scope={state['active_scope'] or '-'}  devil={devil}  lab={lab}", "bold"))
    print(f"  last={last}  budget=config.max_requests  log={ui.log_dir(state['active_scope'] or 'session')}")
    print(ui.color("  " + "-" * 68, "cyan"))
    for key, label, _ in MENUS[current]:
        print(f"  [{key}] {label}")


def run_interactive(log: TextIO | None = None) -> int:
    state = load_state()
    active = state["active_scope"]
    selected = next((item for item in list_scopes() if item.name == active), None)
    if selected is None or not selected.domains:
        ui.error("No active scope with domains. Add or select a scope before starting.", log)
        return 2
    ui.banner(__version__)
    current = "main"
    last = 0
    while True:
        _header(state, current, last)
        try:
            choice = input("\n  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        entries = MENUS[current]
        action = next((item[2] for item in entries if item[0] == choice), None)
        if action is None:
            ui.warn("unknown choice", log)
            last = 2
            continue
        if action.startswith("action:"):
            action = action.split(":", 1)[1]
        try:
            last, target = _run_action(action, state, log)
        except (EOFError, KeyboardInterrupt):
            ui.warn("interrupted", log)
            last = 130
            continue
        except Exception as exc:
            ui.error(f"error: {exc}", log)
            last = 2
            continue
        if target == "__exit__":
            return 0
        if target:
            current = target
