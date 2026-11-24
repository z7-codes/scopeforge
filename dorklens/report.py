from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from . import ui


def dedupe(data: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], dict] = {}
    for item in data:
        parts = urlsplit(str(item["url"]))
        key = (parts.hostname or "", parts.path, str(item["category"]))
        if key not in groups:
            clone = dict(item)
            clone["variants"] = 0
            clone["confirmed"] = item["category"] != "sqli_time"
            groups[key] = clone
        else:
            groups[key]["variants"] += 1
    return list(groups.values())


def collect(store) -> list[dict]:
    return [
        {
            "url": row[1],
            "param": row[2],
            "category": row[3],
            "payload": row[4],
            "confidence": row[5],
            "signals": json.loads(str(row[6])),
            "evidence": row[7],
            "advice": row[8],
            "ts": row[9],
        }
        for row in store.findings()
    ]


def write(store, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    data = dedupe(collect(store))
    path = out / "findings.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    ui.report(data)
    return path
