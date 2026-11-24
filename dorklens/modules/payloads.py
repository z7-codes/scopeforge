from __future__ import annotations

import difflib
import re
import time
import urllib.parse
from typing import Any

import yaml

from .. import ui
from ..storage import Store

SCORE = {
    "id": 3,
    "file": 3,
    "url": 3,
    "cmd": 3,
    "to": 3,
    "redirect": 3,
    "path": 3,
    "q": 2,
    "page": 1,
}


def replace_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not any(key == param for key, _ in pairs):
        pairs.append((param, value))
    replaced = [(key, value if key == param else old) for key, old in pairs]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(replaced)))


def similarity(first: str, second: str) -> float:
    return difflib.SequenceMatcher(None, first[:8000], second[:8000]).quick_ratio()


def evaluate(signal: dict, base, probe, payload: str) -> tuple[bool, str]:
    kind = signal.get("type")
    if kind == "regex":
        match = re.search(str(signal.get("pattern", "")), probe.text, re.I)
        return (True, f"regex {match.group(0)[:40]}") if match else (False, "")
    if kind == "status_change":
        return (probe.status != base.status, f"status {base.status}->{probe.status}")
    if kind == "length_delta":
        delta = abs(probe.length - base.length)
        percent = delta / max(base.length, 1) * 100
        matched = percent >= float(signal.get("pct", 20)) and delta > 40
        return matched, f"len {base.length}->{probe.length} ({percent:.0f}%)"
    if kind == "reflect":
        raw = payload in probe.text
        encoded = urllib.parse.quote(payload, safe="") in probe.text
        if encoded:
            return True, "reflected encoded (XSS unlikely - check context)"
        if raw:
            return True, "reflected raw (XSS likely)"
        return False, ""
    if kind == "location_match":
        location = str(probe.headers.get("location", ""))
        return str(signal.get("contains", "")) in location, f"location {location[:60]}"
    if kind == "similarity":
        score = similarity(base.text, probe.text)
        return score < float(signal.get("below", 0.92)), f"similarity {score:.2f}"
    return False, ""


def request_kwargs(spec: dict, value: object) -> dict[str, Any]:
    body = str(spec.get("body", "")).replace("{{INJECT}}", str(value))
    kwargs: dict[str, Any] = {"content": body}
    content_type = spec.get("content_type")
    if content_type:
        kwargs["headers"] = {"Content-Type": str(content_type)}
    return kwargs


async def send(cfg, client, method: str, url: str, param: str, value: object, spec: dict):
    if method == "POST":
        return await client.request(method, url, **request_kwargs(spec, value))
    return await client.get(replace_param(url, param, str(value)))


async def check_spec(cfg, client, store: Store, url: str, param: str, category: str, spec: dict) -> int:
    method = str(spec.get("method", "GET")).upper()
    if cfg.dry_run:
        ui.info(f"{method} {category}: {param} -> {url[:60]}")
        return 0
    if method == "POST":
        baseline = spec.get("baseline", "1")
        first = await send(cfg, client, method, url, param, baseline, spec)
        second = await send(cfg, client, method, url, param, baseline, spec)
    else:
        first = await client.get(url)
        second = await client.get(url)
    if not first or not second:
        return 0
    unstable = abs(first.length - second.length) > max(40, first.length * 0.08)
    needed = cfg.min_confidence + (1 if unstable else 0)
    advice = str(spec.get("advice", ""))
    hits = 0

    if "pairs" in spec:
        for left, right in spec["pairs"]:
            left_response = await send(cfg, client, method, url, param, left, spec)
            right_response = await send(cfg, client, method, url, param, right, spec)
            if not left_response or not right_response:
                continue
            delta = abs(right_response.length - left_response.length)
            percent = delta / max(left_response.length, 1) * 100
            threshold = float(spec.get("signals", [{}])[0].get("pct", 10))
            if percent >= threshold and delta > 25:
                stored = store.add_finding(
                    url=url,
                    param=param,
                    category=category,
                    payload=f"{left} || {right}",
                    confidence=2,
                    signals=["pair_delta"],
                    evidence=f"{method} {left_response.length} vs {right_response.length} ({percent:.0f}%)",
                    advice=advice,
                )
                if stored:
                    hits += 1
                    ui.hit(2, category, param, left, url)
        return hits

    for payload in spec.get("payloads", []):
        probe = await send(cfg, client, method, url, param, payload, spec)
        if not probe:
            continue
        matched: list[str] = []
        reasons: list[str] = []
        for signal in spec.get("signals", []):
            good, reason = evaluate(signal, first, probe, str(payload))
            if good:
                matched.append(str(signal.get("type", "signal")))
                reasons.append(reason)
        if len(matched) >= needed:
            stored = store.add_finding(
                url=url,
                param=param,
                category=category,
                payload=str(payload),
                confidence=len(matched),
                signals=matched,
                evidence=f"{method} " + "; ".join(reasons),
                advice=advice,
            )
            if stored:
                hits += 1
                ui.hit(len(matched), category, param, str(payload), url)
    return hits


async def run(
    cfg,
    client,
    store: Store,
    targets: list[tuple[str, list[str]]],
    post_targets: list[str] | None = None,
) -> int:
    specs = yaml.safe_load(cfg.payloads.read_text(encoding="utf-8")) or {}
    ranked = sorted(targets, key=lambda item: -sum(SCORE.get(str(param).lower(), 0) for param in item[1]))
    hits = 0
    for url, params in ranked[: cfg.max_payload_urls]:
        for param in params:
            for category, spec in specs.items():
                if str(spec.get("method", "GET")).upper() == "POST":
                    continue
                allowed = [str(item).lower() for item in spec.get("params", [])]
                if param.lower() not in allowed:
                    continue
                hits += await check_spec(cfg, client, store, url, param, category, spec)
    if cfg.post:
        for category, spec in specs.items():
            if str(spec.get("method", "GET")).upper() != "POST":
                continue
            paths = [str(item).lower() for item in spec.get("paths", [])]
            for url in post_targets or []:
                if paths and urllib.parse.urlsplit(url).path.lower() not in paths:
                    continue
                for param in spec.get("params", []):
                    hits += await check_spec(cfg, client, store, url, str(param), category, spec)
    return hits


async def blind(cfg, client, store: Store, targets: list[tuple[str, list[str]]]) -> int:
    payloads = ["1 AND SLEEP(4)", "1' AND SLEEP(4)-- -", "1);SELECT pg_sleep(4)--"]
    hits = 0
    for url, params in targets[: cfg.max_payload_urls]:
        for param in params[:2]:
            base = await client.get(url)
            if not base:
                continue
            for payload in payloads:
                started = time.monotonic()
                probe = await client.get(replace_param(url, param, payload))
                elapsed = time.monotonic() - started
                if probe and elapsed > 3.2 and elapsed > base.elapsed * 2.5:
                    stored = store.add_finding(
                        url=url,
                        param=param,
                        category="sqli_time",
                        payload=payload,
                        confidence=2,
                        signals=["elapsed"],
                        evidence=f"GET {elapsed:.1f}s vs {base.elapsed:.1f}s",
                        advice='sqlmap -u "URL" -p PARAM --batch --level 3',
                    )
                    if stored:
                        hits += 1
                        ui.hit(2, "sqli_time", param, payload, url)
    return hits
