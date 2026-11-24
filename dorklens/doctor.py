from __future__ import annotations

import importlib
import socket

from . import ui

REQUIRED = ("httpx", "yaml", "rich", "selectolax")


def run() -> bool:
    healthy = True
    ui.head("doctor")
    for module in REQUIRED:
        try:
            importlib.import_module(module)
            ui.ok(f"{module} installed")
        except ImportError:
            ui.err(f"{module} missing -> pip install -e .")
            healthy = False
    for host, port in (("1.1.1.1", 53), ("example.com", 443), ("www.mojeek.com", 443)):
        try:
            socket.create_connection((host, port), timeout=4).close()
            ui.ok(f"{host}:{port} reachable")
        except OSError:
            ui.warn(f"{host}:{port} band - proxy ya network dekhein")
    if not healthy:
        ui.err("pehle missing packages theek karein")
    return healthy
