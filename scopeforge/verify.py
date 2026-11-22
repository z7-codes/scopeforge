from __future__ import annotations

import shlex

from .evidence import write as write_evidence
from .findings import get, set_status
from .models import Finding
from .net import USER_AGENT

HINTS = {
    "reflection": "marker response me hai? encoded/unencoded context manually confirm karo",
    "exposure": "file kholo, asli data confirm karo, secrets redact karke note likho",
}


def build_curl(finding: Finding) -> str:
    target = finding.request_url or finding.url
    return " ".join(["curl -s -D -", "-A", shlex.quote(USER_AGENT), shlex.quote(target)])


def render(finding: Finding) -> str:
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
            f"baseline {finding.baseline_status}/{finding.baseline_size}b"
            f"  vs  observed {finding.injected_status}/{finding.injected_size}b"
            f"  sim {finding.similarity:.3f}"
        )
    if finding.excerpt:
        lines.append(f"proof    {finding.excerpt}")
    lines.extend(["", build_curl(finding), "", HINTS.get(finding.category, "manually confirm karo, ek line impact likho"), ""])
    lines.append("[c]onfirmed  [f]alse-positive  [s]kip  [q]uit")
    return "\n".join(lines)


def decide(finding_id: str, decision: str, note: str = "") -> str:
    key = decision.strip().lower()
    if key in ("c", "confirm", "confirmed"):
        finding = set_status(finding_id, "confirmed", note)
        path = write_evidence(finding, note)
        return f"confirmed {finding.id} -> evidence: {path}"
    if key in ("f", "false", "false-positive"):
        set_status(finding_id, "false-positive", note)
        return f"false-positive: {finding_id}"
    if key in ("s", "skip", "skipped"):
        set_status(finding_id, "skipped", note)
        return f"skipped: {finding_id}"
    raise ValueError("decision must be c, f, or s")


def interactive(finding_id: str) -> None:
    print(render(get(finding_id)))
    answer = input("> ").strip().lower()
    if answer == "q":
        return
    note = input("note (optional): ").strip() if answer in ("c", "f") else ""
    print(decide(finding_id, answer, note))
