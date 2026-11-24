from __future__ import annotations

import asyncio
import random
import re
import urllib.parse

import yaml
from selectolax.lexbor import LexborHTMLParser as HTMLParser

from .. import ui
from ..storage import Store

BACKENDS = {
    "mojeek": ("https://www.mojeek.com/search?q={q}", "a.ob"),
    "ddg": ("https://html.duckduckgo.com/html/?q={q}", "a.result__a"),
    "bing": ("https://www.bing.com/search?q={q}&count=30", "li.b_algo h2 a"),
}
SKIP = ("duckduckgo.com", "mojeek.com", "bing.com", "microsoft.com", "google.com")
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def extract(html: str, selector: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for anchor in HTMLParser(html).css(selector):
        href = (anchor.attributes.get("href") or "").strip()
        if "uddg=" in href:
            match = re.search(r"uddg=([^&]+)", href)
            if not match:
                continue
            href = urllib.parse.unquote(match.group(1))
        if not href.startswith("http"):
            continue
        href = href.split("&rut=")[0]
        if any(item in urllib.parse.urlsplit(href).netloc for item in SKIP):
            continue
        if href not in seen:
            seen.add(href)
            found.append(href)
    return found


def plans(cfg) -> list[tuple[str, str, str]]:
    blocks = yaml.safe_load(cfg.dorks.read_text(encoding="utf-8")) or []
    items: list[tuple[str, str, str]] = []
    for block in blocks:
        category = str(block.get("cat", "dork"))
        priority = str(block.get("priority", "medium"))
        for template in block.get("q", []):
            query = str(template).replace("{{d}}", cfg.domain)
            items.append((priority, category, query))
    items.sort(key=lambda item: PRIORITY_ORDER.get(item[0], 1))
    limit = int(cfg.max_dork_queries)
    return items[:limit] if limit > 0 else items


async def run(cfg, client, store: Store) -> int:
    total = 0
    for _, category, query in plans(cfg):
        for backend in cfg.backends:
            if backend not in BACKENDS:
                continue
            url_template, selector = BACKENDS[backend]
            if cfg.dry_run:
                ui.info(f"{category}: {query}")
                continue
            response = await client.get(
                url_template.format(q=urllib.parse.quote(query)),
                scope_check=False,
            )
            if not response or response.status != 200:
                continue
            new = 0
            for href in extract(response.text, selector):
                host = urllib.parse.urlsplit(href).hostname
                if cfg.scope.in_scope(host):
                    new += store.add_url(href, f"dork:{category}")
            total += new
            if new:
                ui.info(f"{category} @{backend}: +{new}")
            await asyncio.sleep(random.uniform(1.6, 3.2))
    return total
