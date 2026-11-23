from __future__ import annotations

from typing import Any

from . import __version__
from .storage import read_json, write_json

TUI_STATE_FILE = "tui-state.json"
DEFAULT_STATE: dict[str, Any] = {"active_scope": "", "devil": False, "lab": False}

MENU = (
    ("1", "Scope management", "scope list"),
    ("2", "Dork plan", "plan"),
    ("3", "Passive search", "search"),
    ("4", "Exposure worksheet", "exposure"),
    ("5", "Exposure scan", "scan"),
    ("6", "Benign param probe", "probe"),
    ("7", "Findings", "findings list"),
    ("8", "Verify finding", "verify"),
    ("9", "Config", "config"),
    ("s", "Set active scope", ""),
    ("d", "Devil mode toggle", ""),
    ("l", "Lab mode toggle", ""),
    ("0", "Exit", ""),
)


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


def _dispatch(choice: str, state: dict[str, Any]) -> None:
    from .cli import main

    if choice == "1":
        main(["scope", "list"])
    elif choice == "2":
        main(["plan", _scope(state), "--category", _prompt("category", "recon")])
    elif choice == "3":
        main(["search", _scope(state), "--category", _prompt("category", "exposure")])
    elif choice == "4":
        main(["exposure", _prompt("domain"), "--scope", _scope(state)])
    elif choice == "5":
        host = _prompt("host url")
        argv = ["scan", host, "--i-own-this"]
        if state["lab"]:
            argv.append("--lab")
        else:
            argv.extend(["--scope", _scope(state)])
        main(argv)
    elif choice == "6":
        url = _prompt("url")
        argv = ["probe", url, "--i-own-this"]
        if state["lab"]:
            argv.append("--lab")
        else:
            argv.extend(["--scope", _scope(state)])
        main(argv)
    elif choice == "7":
        argv = ["findings", "list"]
        if state["devil"]:
            argv.append("--devil")
        if state["active_scope"]:
            argv.extend(["--scope", state["active_scope"]])
        main(argv)
    elif choice == "8":
        main(["verify", _prompt("finding id")])
    elif choice == "9":
        main(["config"])
    elif choice == "s":
        state["active_scope"] = _prompt("active scope", state["active_scope"])
        save_state(state)
    elif choice == "d":
        state["devil"] = not state["devil"]
        save_state(state)
    elif choice == "l":
        state["lab"] = not state["lab"]
        save_state(state)


def run_interactive() -> int:
    state = load_state()
    print(f"ScopeForge {__version__} - scope-safe recon")
    while True:
        devil = "on" if state["devil"] else "off"
        lab = "on" if state["lab"] else "off"
        print(f"scope={state['active_scope'] or '-'} devil={devil} lab={lab}")
        for key, label, _ in MENU:
            print(f"[{key}] {label}")
        choice = input("\n> ").strip().lower()
        if choice in ("0", "q"):
            return 0
        try:
            _dispatch(choice, state)
        except Exception as exc:
            print(f"error: {exc}")
        print()
