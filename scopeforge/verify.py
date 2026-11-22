from __future__ import annotations

import json
import shlex
from pathlib import Path

from .analyzer import redact
from .findings import Finding, get_finding, set_status, to_evidence
from .probe import USER_AGENT
from .storage import ensure_data_dir


def build_curl(finding: Finding) -> str:
    target = finding.request_url or finding.url
    return " ".join(["curl -s -D -", "-A", shlex.quote(USER_AGENT), shlex.quote(target)])


def verify_hint(finding: Finding) -> str:
    if finding.category == "xss":
        marker = finding.payload or "z7sf7q"
        return f"response me {marker!r} ko unencoded dhundo; browser me URL khol ke confirm karo"
    if finding.category == "sqli":
        return "baseline vs injected body ka difference dekho; error family ya boolean delta confirm karo"
    if finding.kind == "exposure":
        return f"file kholo aur {finding.surface or 'content'} ka asli data confirm karo; secrets redact karke note karo"
    return "manually confirm karo aur ek line me impact likho"


def render_finding(finding: Finding) -> str:
    lines = [
        f"Finding {finding.id}  {finding.kind}/{finding.category}  confidence={finding.confidence}",
        f"url      {finding.url}",
    ]
    if finding.parameter:
        lines.append(f"param    {finding.parameter}")
    if finding.payload:
        lines.append(f"payload  {finding.payload}")
    lines.append(f"signal   {finding.signal}")
    if finding.context:
        lines.append(f"context  {finding.context}")
    if finding.baseline_status:
        lines.append(
            f"baseline {finding.baseline_status} / {finding.baseline_size}b"
            f"  vs  injected {finding.injected_status} / {finding.injected_size}b"
            f"  sim {finding.similarity:.3f}"
        )
    if finding.excerpt:
        lines.append(f"proof    {finding.excerpt}")
    lines.extend(["", build_curl(finding), "", verify_hint(finding), ""])
    lines.append("[c]onfirmed  [f]alse-positive  [s]kip  [q]uit")
    return "\n".join(lines)


def evidence_path(scope: str) -> Path:
    folder = ensure_data_dir() / "evidence"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{scope}.json"


def write_evidence(finding: Finding, note: str = "") -> Path:
    path = evidence_path(finding.scope)
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
    if not isinstance(existing, list):
        existing = []
    existing.append(to_evidence(finding, note))
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return path


def apply_decision(finding_id: str, decision: str, note: str = "") -> str:
    key = decision.strip().lower()
    if key in ("c", "confirm", "confirmed"):
        finding = set_status(finding_id, "confirmed", note)
        path = write_evidence(finding, note)
        return f"confirmed {finding.id} -> evidence written: {path}"
    if key in ("f", "false", "false-positive"):
        set_status(finding_id, "false-positive", note)
        return f"marked {finding.id} as false-positive"
    if key in ("s", "skip", "skipped"):
        set_status(finding_id, "skipped", note)
        return f"skipped {finding.id}"
    raise ValueError("decision must be c, f, or s")


def verify_interactive(finding_id: str) -> None:
    while True:
        finding = get_finding(finding_id)
        print(render_finding(finding))
        answer = input("> ").strip().lower()
        if answer == "q":
            return
        note = ""
        if answer in ("c", "f"):
            note = input("note (optional): ").strip()
        print(apply_decision(finding_id, answer, note))
        return
