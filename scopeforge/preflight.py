from __future__ import annotations

import os
import shutil
import sys

from . import ui

REQUIRED: tuple[tuple[str, str], ...] = (("python", "interpreter"),)
OPTIONAL: tuple[tuple[str, str], ...] = (
    ("nmap", "port scan helper"),
    ("subfinder", "passive subdomain helper"),
    ("httpx", "http probe helper"),
    ("whatweb", "fingerprint helper"),
    ("dnsx", "dns helper"),
    ("nuclei", "template scanner helper"),
)

INSTALL: dict[str, str] = {
    "nmap": "nmap",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx",
    "whatweb": "whatweb",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
}


def _install(command: str) -> str:
    package = INSTALL.get(command, command)
    if package.startswith("github.com/"):
        return f"go install {package}@latest"
    if shutil.which("apt-get"):
        return f"sudo apt-get install -y {package}"
    if shutil.which("pacman"):
        return f"sudo pacman -S {package}"
    if shutil.which("dnf"):
        return f"sudo dnf install -y {package}"
    return f"install {package}"


def _present(command: str) -> bool:
    if command == "python":
        return bool(sys.executable or shutil.which("python3") or shutil.which("python"))
    return shutil.which(command) is not None


def check() -> int:
    missing_required: list[str] = []
    missing_optional: list[str] = []
    print(ui.color("preflight", "bold"))
    for command, label in REQUIRED:
        if _present(command):
            print(f"  {ui.color('[ok]', 'green')} {label}")
        else:
            missing_required.append(command)
            print(f"  {ui.color('[!!]', 'red')} {label} missing: {command}")
    for command, label in OPTIONAL:
        if _present(command):
            print(f"  {ui.color('[ok]', 'green')} {label}: {command}")
        else:
            missing_optional.append(command)
            print(f"  {ui.color('[--]', 'yellow')} {label}: {command} not found")
    if missing_optional:
        print("  optional install hints:")
        for command in missing_optional:
            print(f"    {command}: {_install(command)}")
    if os.environ.get("SCOPEFORGE_SKIP_PREFLIGHT"):
        print("  preflight failures ignored via SCOPEFORGE_SKIP_PREFLIGHT")
        return 0
    if missing_required:
        print(f"  required tools missing: {', '.join(missing_required)}")
        return 2
    return 0
