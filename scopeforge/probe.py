from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from . import findings
from .analyzer import redact
from .data import load
from .diff import compare
from .net import Session
from .state import load_seen, remember, run_key

CTX_TAG = re.compile(r"<[^>]*$")
CTX_ATTR = re.compile(r"=\s*[\"'][^\"']*$")


@dataclass(frozen=True)
class ProbeResult:
    findings: list
    sent: int
    skipped: int


def params_of(url: str, limit: int = 5) -> list[str]:
    query = urllib.parse.urlsplit(url).query
    names = [name for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)]
    return names[:limit]


def substitute(url: str, parameter: str, value: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    updated = [(key, value if key == parameter else current) for key, current in pairs]
    query = urllib.parse.urlencode(updated, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def context_of(body: str, index: int, marker: str) -> tuple[str, str]:
    prefix = body[:index].lower()
    if "<script" in prefix and "</script>" not in prefix:
        context = "javascript"
    elif CTX_ATTR.search(prefix):
        context = "html-attribute"
    elif CTX_TAG.search(prefix):
        context = "html-tag"
    else:
        context = "html-text"
    start = max(0, index - 40)
    end = min(len(body), index + len(marker) + 40)
    return context, body[start:end]


def marker_for(name: str | None = None) -> str:
    if name:
        return str(name)
    classes = load("payloads").get("classes", {})
    return str(classes.get("marker", {}).get("canary", "z7sf7q"))


def run(
    session: Session,
    scope_name: str,
    urls: list[str],
    marker: str | None = None,
    max_params: int = 5,
    resume: bool = True,
    seen: set[str] | None = None,
) -> ProbeResult:
    canary = marker_for(marker)
    done = set(seen or set())
    if resume and scope_name:
        done |= load_seen(scope_name)
    produced: list = []
    sent = 0
    skipped = 0
    plans: list[tuple[str, list[str]]] = []

    for url in urls:
        parameters = params_of(url, max_params)
        if not parameters:
            skipped += 1
            continue
        pending = [name for name in parameters if not (resume and run_key(url, name, canary) in done)]
        skipped += len(parameters) - len(pending)
        if pending:
            plans.append((url, pending))

    for url, parameters in plans:
        baseline = session.get(url)
        sent += 1
        for parameter in parameters:
            key = run_key(url, parameter, canary)
            done.add(key)
            observed = session.get(substitute(url, parameter, canary))
            sent += 1
            remember(scope_name, key, "marker")
            comparison = compare(baseline.body, observed.body)
            index = observed.text.find(canary)
            context = ""
            excerpt = ""
            if index >= 0:
                context, excerpt = context_of(observed.text, index, canary)
            if index < 0 and not comparison.interesting:
                continue
            confidence = "medium" if context in ("html-attribute", "html-tag", "javascript") else "low"
            produced.append(
                findings.add(
                    scope=scope_name,
                    kind="probe",
                    category="reflection",
                    url=url,
                    request_url=observed.url,
                    parameter=parameter,
                    payload=canary,
                    confidence=confidence,
                    signal="benign marker reflected" if index >= 0 else comparison.reason,
                    context=context,
                    reflection=index >= 0,
                    excerpt=redact(excerpt),
                    baseline_status=baseline.status,
                    baseline_size=len(baseline.body),
                    injected_status=observed.status,
                    injected_size=len(observed.body),
                    similarity=comparison.similarity,
                )
            )
    return ProbeResult(produced, sent, skipped)


def render(result: ProbeResult) -> str:
    lines = [f"Benign probe - {result.sent} requests, {result.skipped} skipped, {len(result.findings)} finding(s)", ""]
    if not result.findings:
        lines.extend(["No benign marker reflection recorded.", "", "Reflection is a signal, not a vulnerability declaration."])
        return "\n".join(lines)
    lines.extend(
        f"{item.id}  {item.confidence:<6}  {item.url}?{item.parameter}  [{item.context or 'delta-only'}]" for item in result.findings
    )
    lines.extend(["", "Reflection is a signal, not a vulnerability declaration.", "Next: scopeforge verify <id>"])
    return "\n".join(lines)
