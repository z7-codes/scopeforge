from __future__ import annotations

import difflib
import re
import time
import urllib.parse

import yaml

from .. import ui
from ..storage import Store


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
        needle = payload if signal.get("raw") else urllib.parse.quote(payload, safe="")
        return needle in probe.text, "payload wapas mila"
    if kind == "location_match":
        location = str(probe.headers.get("location", ""))
        return str(signal.get("contains", "")) in location, f"location {location[:60]}"
    if kind == "similarity":
        score = similarity(base.text, probe.text)
        return score < float(signal.get("below", 0.92)), f"similarity {score:.2f}"
    return False, ""


async def run(cfg, client, store: Store, targets: list[tuple[str, list[str]]]) -> int:
    specs = yaml.safe_load(cfg.payloads.read_text(encoding="utf-8")) or {}
    urls = targets[: cfg.max_payload_urls]
    hits = 0
    for url, params in urls:
        for param in params:
            for category, spec in specs.items():
                allowed = [str(item).lower() for item in spec.get("params", [])]
                if param.lower() not in allowed:
                    continue
                if cfg.dry_run:
                    ui.info(f"{category}: {param} -> {url[:60]}")
                    continue
                first = await client.get(url)
                second = await client.get(url)
                if not first or not second:
                    continue
                unstable = abs(first.length - second.length) > max(40, first.length * 0.08)
                needed = cfg.min_confidence + (1 if unstable else 0)
                advice = str(spec.get("advice", ""))

                if "pairs" in spec:
                    for left, right in spec["pairs"]:
                        left_response = await client.get(replace_param(url, param, left))
                        right_response = await client.get(replace_param(url, param, right))
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
                                evidence=f"{left_response.length} vs {right_response.length} ({percent:.0f}%)",
                                advice=advice,
                            )
                            if stored:
                                hits += 1
                                ui.hit(2, category, param, left, url)
                    continue

                for payload in spec.get("payloads", []):
                    probe = await client.get(replace_param(url, param, payload))
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
                            evidence="; ".join(reasons),
                            advice=advice,
                        )
                        if stored:
                            hits += 1
                            ui.hit(len(matched), category, param, str(payload), url)
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
                        evidence=f"{elapsed:.1f}s vs {base.elapsed:.1f}s",
                        advice='sqlmap -u "URL" -p PARAM --batch --level 3',
                    )
                    if stored:
                        hits += 1
                        ui.hit(2, "sqli_time", param, payload, url)
    return hits
