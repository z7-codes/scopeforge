from __future__ import annotations

import urllib.parse
from collections import deque

from selectolax.lexbor import LexborHTMLParser as HTMLParser

from .. import ui

MAX_PAGES = 200
MAX_DEPTH = 2


def clean(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return parts._replace(fragment="").geturl()


async def run(cfg, client, store) -> int:
    seeds = [f"{scheme}://{cfg.domain}/" for scheme in cfg.schemes]
    seeds.extend(url for _, url in reversed(store.urls()))
    queue: deque[tuple[str, int]] = deque()
    queued: set[str] = set()
    for seed in seeds:
        seed = clean(seed)
        parts = urllib.parse.urlsplit(seed)
        if parts.scheme not in cfg.schemes or not cfg.scope.in_scope(parts.hostname):
            continue
        if seed in queued:
            continue
        queued.add(seed)
        queue.append((seed, 0))
    seen: set[str] = set()
    total = 0
    while queue and len(seen) < MAX_PAGES:
        url, depth = queue.popleft()
        url = clean(url)
        if url in seen:
            continue
        parts = urllib.parse.urlsplit(url)
        if not cfg.scope.in_scope(parts.hostname) or parts.scheme not in cfg.schemes:
            continue
        seen.add(url)
        response = await client.get(url)
        if not response or response.status != 200:
            continue
        content_type = str(response.headers.get("content-type", "")).lower()
        if content_type and "html" not in content_type:
            continue
        parser = HTMLParser(response.text)
        for anchor in parser.css("a[href]"):
            href = (anchor.attributes.get("href") or "").strip()
            if not href or href.startswith(("javascript:", "mailto:", "data:")):
                continue
            found = clean(urllib.parse.urljoin(url, href))
            found_parts = urllib.parse.urlsplit(found)
            if found_parts.scheme not in cfg.schemes:
                continue
            host = found_parts.hostname
            if not host or not cfg.scope.in_scope(host):
                continue
            if store.add_url(found, f"crawl:{depth}"):
                total += 1
            if (
                depth < MAX_DEPTH
                and found not in queued
                and len(seen) + len(queue) < MAX_PAGES
            ):
                queued.add(found)
                queue.append((found, depth + 1))
    if total:
        ui.info(f"crawl: +{total}")
    return total
