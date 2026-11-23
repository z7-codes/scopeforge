from __future__ import annotations

import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from . import findings
from .analyzer import redact
from .data import load
from .diff import Comparison, compare
from .errors import UsageError
from .net import Response, Session, normalize_token
from .probe import context_of, params_of, substitute

Verdict = Callable[[Response, Response, Comparison, str], str | None]


@dataclass(frozen=True)
class InjectResult:
    findings: list
    sent: int
    skipped: int
    classes: list[str]


def _original(url: str, parameter: str) -> str:
    query = urllib.parse.urlsplit(url).query
    for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if name == parameter:
            return value
    return "1"


def _verdict_sqli(baseline: Response, injected: Response, comparison: Comparison, _marker: str) -> str | None:
    text = str(injected.text).lower()
    authenticated = "welcome" in text or "admin" in text
    sql_error = "sql" in text and ("syntax" in text or "error" in text)
    if authenticated or sql_error:
        return "boolean response diverged from baseline"
    return None


def _verdict_xss(baseline: Response, injected: Response, _comparison: Comparison, marker: str) -> str | None:
    if marker in injected.text and marker not in baseline.text:
        return f"marker {marker} reflected in response"
    if "<script>" in injected.text.lower() and "<script>" not in baseline.text.lower():
        return "script payload reflected in response"
    return None


def _verdict_traversal(baseline: Response, injected: Response, _comparison: Comparison, _marker: str) -> str | None:
    text = injected.text.lower()
    if "root:" in text and "/bin/sh" in text:
        return "passwd-like content returned"
    return None


def _verdict_ssti(baseline: Response, injected: Response, _comparison: Comparison, _marker: str) -> str | None:
    if "49" in injected.text and "49" not in baseline.text:
        return "template expression evaluated"
    return None


def _verdict_redirect(baseline: Response, injected: Response, _comparison: Comparison, _marker: str) -> str | None:
    target = injected.location
    if target and target != baseline.location:
        return "redirect target followed user input"
    return None


VERDICTS: dict[str, Verdict] = {
    "sqli_boolean": _verdict_sqli,
    "xss_reflect": _verdict_xss,
    "traversal": _verdict_traversal,
    "ssti": _verdict_ssti,
    "open_redirect": _verdict_redirect,
}


def available_classes() -> list[str]:
    return [name for name in load("payloads").get("classes", {}) if name in VERDICTS]


def _selected(requested: list[str] | None, limit: int) -> list[str]:
    available = available_classes()
    if requested:
        unknown = [name for name in requested if name not in available]
        if unknown:
            raise UsageError("unknown payload class: " + ", ".join(unknown))
        selected = [name for name in available if name in requested]
    else:
        selected = available
    if not selected:
        raise UsageError("no payload classes selected")
    limit = max(1, min(int(limit), 5))
    return selected[:limit]


def _cost(urls: list[str], params_per_url: dict[str, int], classes: list[str], definitions: dict) -> int:
    pairs = sum(len(definitions[name].get("pairs", [])) for name in classes)
    return sum(params * (1 + pairs) for params in params_per_url.values())


def run(
    session: Session,
    scope_name: str,
    urls: list[str],
    classes: list[str] | None = None,
    max_classes: int = 2,
) -> InjectResult:
    chosen = _selected(classes, max_classes)
    definitions = load("payloads").get("classes", {})
    params_per_url = {url: len(params_of(url)) for url in urls}
    projected = _cost(urls, params_per_url, chosen, definitions)
    host_budget = session.budget.max_per_host - session.budget.per_host.get(normalize_token(urls[0]), 0)
    allowed = min(session.budget.remaining(), host_budget)
    if projected > allowed:
        raise UsageError(f"request budget too small: need {projected}, have {allowed}")

    sent = session.budget.sent
    skipped = 0
    found: list = []
    for url in urls:
        parameters = params_of(url)
        for parameter in parameters:
            baseline_url = substitute(url, parameter, _original(url, parameter))
            baseline = session.get(baseline_url)
            for name in chosen:
                definition = definitions[name]
                marker = str(definition.get("canary", name))
                verdict = VERDICTS[name]
                pairs = definition.get("pairs", [])
                if not pairs:
                    skipped += 1
                    continue
                for original, payload in pairs:
                    injected_url = substitute(url, parameter, str(payload))
                    injected = session.get(injected_url)
                    comparison = compare(baseline.body, injected.body)
                    reason = verdict(baseline, injected, comparison, marker)
                    if not reason:
                        continue
                    index = injected.text.find(marker)
                    context, reflection = context_of(injected.text, index, marker) if index >= 0 else ("", False)
                    found.append(
                        findings.add(
                            scope_name,
                            "inject",
                            str(definition.get("category", "injection")),
                            url,
                            confidence="medium",
                            parameter=parameter,
                            payload_class=name,
                            payload=str(payload),
                            surface="query",
                            context=context,
                            reflection=reflection or name in ("xss_reflect", "ssti"),
                            error_family=name,
                            excerpt=redact(injected.text[:300]),
                            baseline_status=baseline.status,
                            baseline_size=len(baseline.body),
                            injected_status=injected.status,
                            injected_size=len(injected.body),
                            similarity=round(comparison.similarity, 3),
                            signal=reason,
                            note=f"baseline={original!r} | {reason}",
                        )
                    )
    return InjectResult(found, session.budget.sent - sent, skipped, chosen)


def render(result: InjectResult) -> str:
    lines = [
        "# ScopeForge Authorized Payload Ladder",
        "",
        f"Classes: {', '.join(result.classes)}",
        f"Requests: {result.sent} | skipped: {result.skipped} | findings: {len(result.findings)}",
        "",
    ]
    for item in result.findings:
        lines.append(
            f"- {item.id} [{item.payload_class}] {item.url} | param={item.parameter} | {item.signal}"
        )
    if not result.findings:
        lines.append("No payload-class signal observed. Treat this as absence of evidence, not proof of safety.")
    return "\n".join(lines)
