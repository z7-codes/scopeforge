from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .analyzer import redact
from .scope import check_scope, get_scope, normalize_token

NO_REDIRECT = type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda self, *args, **kwargs: None})
USER_AGENT = "ScopeForge/0.3 benign-marker-check"


def is_lab_host(host: str) -> bool:
    value = normalize_token(host)
    if value in {"localhost", "127.0.0.1", "::1"}:
        return True
    return value.endswith(".localhost") or value.endswith(".test") or value.endswith(".local")


def validate_probe_target(url: str, scope_name: str = "") -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("url must start with http:// or https://")
    host = normalize_token(url)
    if not host:
        raise ValueError("url has no hostname")
    if not is_lab_host(host) and not scope_name:
        raise ValueError("non-lab hosts require --scope and --i-own-this")
    if scope_name:
        decision = check_scope(get_scope(scope_name), url)
        if not decision.allowed:
            raise ValueError("probe target blocked by scope: " + decision.reason)
    return host


def build_marker_urls(url: str, marker: str, max_params: int = 5) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("url must start with http:// or https://")
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    variants: list[str] = []
    if pairs:
        for target_name, _ in pairs[:max_params]:
            changed = [(key, marker if key == target_name else value) for key, value in pairs]
            query = urllib.parse.urlencode(changed)
            variants.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")))
    else:
        query = urllib.parse.urlencode({"q": marker})
        variants.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")))
    return variants


def fetch_page(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
    )
    opener = urllib.request.build_opener(NO_REDIRECT())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            headers = {str(key): str(value) for key, value in response.headers.items()}
            body = response.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        headers = {str(key): str(value) for key, value in exc.headers.items()} if exc.headers else {}
        body = exc.read(8192).decode("utf-8", "replace")
    return status, headers, body


def classify_reflection(body: str, marker: str) -> tuple[str, str]:
    index = body.find(marker)
    if index < 0:
        return "not-reflected", ""
    prefix = body[:index].lower()
    if "<script" in prefix and "</script>" not in prefix:
        context = "javascript"
    elif re.search(r"=\s*[\"'][^\"']*$", prefix):
        context = "html-attribute"
    elif re.search(r"<[^>]*$", prefix):
        context = "html-tag"
    else:
        context = "html-text"
    start = max(0, index - 40)
    end = min(len(body), index + len(marker) + 40)
    return context, redact(body[start:end])


def probe_variant(url: str, marker: str, timeout: float = 5.0) -> dict[str, Any]:
    status, headers, body = fetch_page(url, timeout)
    context, excerpt = classify_reflection(body, marker)
    return {
        "url": redact(url),
        "status_code": status,
        "content_type": headers.get("Content-Type", ""),
        "reflected": context != "not-reflected",
        "context": context,
        "excerpt": excerpt,
        "status": "needs-validation",
        "next_step": "Confirm encoding and impact manually inside scope." if context != "not-reflected" else "No benign marker reflection observed.",
    }


def probe_urls(
    urls: list[str],
    marker: str,
    scope_name: str = "",
    owned: bool = False,
    delay: float = 0.5,
) -> list[dict[str, Any]]:
    if not owned:
        raise ValueError("explicit --i-own-this confirmation is required")
    if not urls:
        raise ValueError("at least one URL is required")
    if len(urls) > 10:
        raise ValueError("maximum 10 URLs per probe run")
    results: list[dict[str, Any]] = []
    for index, url in enumerate(urls):
        validate_probe_target(url, scope_name)
        variants = build_marker_urls(url, marker)
        if index and delay:
            time.sleep(delay)
        for variant in variants:
            if len(results) >= 25:
                return results
            results.append(probe_variant(variant, marker))
    return results


def render_probe(results: list[dict[str, Any]], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(results, indent=2)
    if fmt == "md":
        lines = [
            "# ScopeForge Benign Marker Probe",
            "",
            "Reflection is a signal, not a vulnerability declaration.",
            "",
            "| URL | Status | Reflected | Context | Next step |",
            "|---|---:|---|---|---|",
        ]
        lines.extend(
            f"| `{item['url']}` | {item['status_code']} | {item['reflected']} | {item['context']} | {item['next_step']} |"
            for item in results
        )
        return "\n".join(lines)
    if fmt != "text":
        raise ValueError("format must be text, json, or md")
    lines = ["ScopeForge benign marker probe - reflection is a signal only", ""]
    for item in results:
        lines.append(f"{item['url']} | HTTP {item['status_code']} | reflected={item['reflected']} | context={item['context']}")
        lines.append(f"  next: {item['next_step']}")
        if item.get("excerpt"):
            lines.append(f"  proof: {item['excerpt']}")
        lines.append("")
    return "\n".join(lines).rstrip()
