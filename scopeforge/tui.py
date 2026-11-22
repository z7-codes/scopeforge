from __future__ import annotations

from . import __version__

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
    ("0", "Exit", ""),
)


def _prompt(label: str, default: str = "") -> str:
    value = input(f"{label}{f' [{default}]' if default else ''}: ").strip()
    return value or default


def _dispatch(choice: str) -> None:
    from .cli import main

    if choice == "1":
        main(["scope", "list"])
    elif choice == "2":
        main(["plan", _prompt("scope"), "--category", _prompt("category", "recon")])
    elif choice == "3":
        main(["search", _prompt("scope"), "--category", _prompt("category", "exposure")])
    elif choice == "4":
        main(["exposure", _prompt("domain"), "--scope", _prompt("scope")])
    elif choice == "5":
        main(["scan", _prompt("host url"), "--scope", _prompt("scope"), "--i-own-this"])
    elif choice == "6":
        main(["probe", _prompt("url"), "--scope", _prompt("scope"), "--i-own-this"])
    elif choice == "7":
        main(["findings", "list"])
    elif choice == "8":
        main(["verify", _prompt("finding id")])
    elif choice == "9":
        main(["config"])


def run_interactive() -> int:
    print(f"ScopeForge {__version__} - scope-safe recon\n")
    while True:
        for key, label, _ in MENU:
            print(f"[{key}] {label}")
        choice = input("\n> ").strip()
        if choice in ("0", "q"):
            return 0
        try:
            _dispatch(choice)
        except Exception as exc:
            print(f"error: {exc}")
        print()
