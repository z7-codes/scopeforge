from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import urlsplit

SEV = {
    2: ("low", "#2c2a12"),
    3: ("medium", "#3a2c0c"),
    4: ("high", "#3d1a10"),
    5: ("critical", "#4a0f0f"),
}


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


def markdown_card(item: dict) -> list[str]:
    level = SEV.get(int(item["confidence"]), ("info", ""))[0].upper()
    lines = [
        f"## {level} - {item['category']} on `{item['param']}`",
        f"- URL: {item['url']}",
        f"- Payload: `{item['payload']}`",
        f"- Signals: {', '.join(item['signals'])}",
        f"- Evidence: {item['evidence']}",
        f"- Next: {item['advice']}",
    ]
    if item["variants"]:
        lines.append(f"- Variants: +{item['variants']}")
    return lines + [""]


def html_card(item: dict) -> str:
    level, background = SEV.get(int(item["confidence"]), ("info", "#1a1f26"))
    variants = (
        f'<div class="row dim">+{item["variants"]} variants</div>' if item["variants"] else ""
    )
    return (
        f'<div class="card" style="background:{background}">'
        f'<div class="top"><span class="sev">{level}</span>'
        f'<span class="conf">{item["confidence"]}/5</span>'
        f"<b>{html.escape(str(item['category']))}</b> on "
        f"<code>{html.escape(str(item['param']))}</code></div>"
        f'<div class="row"><a href="{html.escape(str(item["url"]))}" target="_blank">'
        f"{html.escape(str(item['url']))}</a></div>"
        f'<div class="row">payload <code>{html.escape(str(item["payload"]))}</code></div>'
        f'<div class="row dim">{html.escape(str(item["evidence"]))}</div>'
        f'{variants}'
        f'<div class="row next"><b>next:</b> {html.escape(str(item["advice"]))}</div></div>'
    )


def write(store, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    rows = store.findings()
    raw = [
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
        for row in rows
    ]
    data = dedupe(raw)
    confirmed = [item for item in data if item["confirmed"]]
    unconfirmed = [item for item in data if not item["confirmed"]]
    (out / "findings.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    markdown = [
        "# DorkLens report",
        "",
        f"URLs: {store.count('urls')} | Findings: {len(confirmed)} | Unconfirmed: {len(unconfirmed)}",
        "",
    ]
    for item in confirmed:
        markdown += markdown_card(item)
    if unconfirmed:
        markdown += ["## Unconfirmed (timing-based)", ""]
        for item in unconfirmed:
            markdown += markdown_card(item)
    (out / "report.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")

    cards = "".join(html_card(item) for item in confirmed)
    if unconfirmed:
        cards += '<h2 class="section">Unconfirmed (timing-based)</h2>'
        cards += "".join(html_card(item) for item in unconfirmed)

    counts: dict[str, int] = {}
    for item in confirmed:
        category = str(item["category"])
        counts[category] = counts.get(category, 0) + 1
    pills = "".join(
        f"<span class=p>{html.escape(name)} {number}</span>" for name, number in sorted(counts.items())
    )
    empty = '<span class=dim>koi finding nahi</span>'
    url_count = store.count("urls")
    meta = f"{url_count} URLs &middot; {len(confirmed)} findings &middot; {len(unconfirmed)} unconfirmed"
    document = f"""<!doctype html><meta charset="utf-8"><title>DorkLens report</title>
<style>
body{{font:14px/1.6 ui-monospace,monospace;background:#0b0d10;color:#c9d1d9;margin:0;padding:2rem;max-width:1000px}}
h1{{font-size:1.4rem;margin:0 0 .3rem}} h2.section{{font-size:1.05rem;margin:1.4rem 0 .6rem}}
.meta{{color:#8b949e;margin-bottom:1.2rem}}
.p{{display:inline-block;border:1px solid #30363d;border-radius:99px;
padding:2px 10px;margin:0 6px 8px 0;font-size:12px}}
.card{{border:1px solid #21262d;border-radius:8px;padding:.8rem 1rem;margin-bottom:.7rem}}
.top{{display:flex;gap:.7rem;align-items:baseline;flex-wrap:wrap}}
.sev{{text-transform:uppercase;font-size:11px;letter-spacing:.08em;
color:#0b0d10;background:#c9d1d9;padding:1px 7px;border-radius:4px}}
.conf{{font-size:11px;color:#8b949e}} code{{color:#e3b341}} a{{color:#58a6ff;text-decoration:none;word-break:break-all}}
.row{{margin-top:.35rem;word-break:break-all}} .dim{{color:#8b949e;font-size:12px}}
.next{{font-size:12px;color:#7ee787}}
</style>
<h1>DorkLens</h1>
<div class="meta">{meta}</div>
<div>{pills or empty}</div><br>{cards}"""
    path = out / "report.html"
    path.write_text(document, encoding="utf-8")
    return path
