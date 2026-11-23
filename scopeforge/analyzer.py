from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SQL_FAMILIES = {
    "sql_syntax",
    "mysql_error",
    "postgres_error",
    "oracle_error",
    "mssql_error",
    "odbc_error",
    "boolean_behavior",
    "query_error",
}
XSS_CONTEXTS = {
    "html-text",
    "html-attribute",
    "javascript",
    "url",
    "html-comment",
}
SECRET_LINE = re.compile(
    r"(?im)^(\s*[\"']?[A-Z0-9_.]*(?:KEY|SECRET|PASSWORD|PASSWD|TOKEN|DSN|CONN|CREDENTIAL)[A-Z0-9_]*[\"']?\s*[=:]\s*)(.*)$"
)


def redact_secrets(text: str) -> str:
    return SECRET_LINE.sub(r"\1[redacted]", text)


def redact(text: Any) -> str:
    value = redact_secrets(str(text or ""))
    value = re.sub(r"([A-Za-z0-9_.-]+)=([^\s&\"']+)", r"\1=[redacted]", value)
    value = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[email]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\b", "[token]", value)
    value = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "[hex]", value)
    return value[:500]


def make_id(record: dict[str, Any]) -> str:
    raw = "|".join(
        str(record.get(key, ""))
        for key in ("category", "url", "parameter", "context", "error_family", "surface")
    )
    return "a-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]


def analyze_record(record: dict[str, Any]) -> dict[str, Any]:
    category = str(record.get("category", "unknown")).strip().lower()
    result: dict[str, Any] = {
        "id": str(record.get("id") or make_id(record)),
        "category": category,
        "scope": str(record.get("scope", "")),
        "url": redact(record.get("url", "")),
        "parameter": redact(record.get("parameter", "")),
        "context": str(record.get("context", "")).strip().lower(),
        "error_family": str(record.get("error_family", "")).strip().lower(),
        "surface": redact(record.get("surface", "")),
        "status": "needs-validation",
        "score": 10,
        "reason": "Not enough evidence has been recorded for this lead.",
        "next_step": "Capture an authorized observation, then re-run analysis.",
        "excerpt": redact(record.get("excerpt", "")),
    }

    if not bool(record.get("authorized")):
        result.update(
            status="blocked",
            score=0,
            reason="Authorization was not recorded for this evidence.",
            next_step="Only add authorized:true for written scope, owned assets, labs, or CTF targets.",
        )
        return result

    if category == "xss":
        if bool(record.get("reflection")) and result["context"] in XSS_CONTEXTS:
            result.update(
                status="likely",
                score=68 if result["context"] != "html-text" else 58,
                reason=f"Benign marker reflected in {result['context']} context.",
                next_step="Confirm encoding and context handling manually inside scope; keep proof redacted.",
            )
        else:
            result.update(
                reason="No reflected marker and recognized output context pair was recorded.",
                next_step="Record reflection result, output context, and encoding behavior from an authorized test.",
            )

    elif category == "sqli":
        if result["error_family"] in SQL_FAMILIES:
            result.update(
                status="likely",
                score=66,
                reason=f"Database-family behavior recorded: {result['error_family']}.",
                next_step="Verify with one controlled authorized input; do not extract data.",
            )
        else:
            result.update(
                reason="No recognized database error family was recorded.",
                next_step="Record the error family and parameter context from an authorized test.",
            )

    elif category == "exposure":
        if result["surface"]:
            result.update(
                status="likely",
                score=52,
                reason=f"Public exposure surface recorded: {result['surface']}.",
                next_step="Confirm sensitivity, ownership, and impact before writing a report.",
            )

    elif category == "recon":
        if result["surface"]:
            result.update(
                score=24,
                reason=f"Recon surface recorded: {result['surface']}.",
                next_step="Convert to a scoped query and add it to the lead ledger.",
            )

    if bool(record.get("manual_confirmed")) and (record.get("evidence_summary") or record.get("excerpt")):
        result.update(
            status="evidence-confirmed",
            score=92,
            reason="Manual confirmation and evidence summary were supplied by the operator.",
            next_step="Write the report with minimal redacted proof and exact scope source.",
        )
        result["evidence_summary"] = redact(record.get("evidence_summary", ""))
    return result


def analyze_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [analyze_record(record) for record in records]


def render_analysis(records: list[dict[str, Any]], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(records, indent=2)
    if fmt == "md":
        lines = [
            "# ScopeForge Analysis",
            "",
            "Status values are evidence signals, not automatic vulnerability declarations.",
            "",
        ]
        lines.append("| ID | Category | Status | Score | Reason |")
        lines.append("|---|---|---|---:|---|")
        lines.extend(
            f"| {item['id']} | {item['category']} | {item['status']} | {item['score']} | {item['reason']} |"
            for item in records
        )
        return "\n".join(lines)
    if fmt != "text":
        raise ValueError("format must be text, json, or md")
    lines = ["ScopeForge analysis - evidence signals only", ""]
    for item in records:
        lines.append(f"{item['id']}  [{item['category']}]  {item['status']}  score={item['score']}")
        lines.append(f"  reason: {item['reason']}")
        lines.append(f"  next:   {item['next_step']}")
        if item.get("excerpt"):
            lines.append(f"  proof:  {item['excerpt']}")
        lines.append("")
    return "\n".join(lines).rstrip()
