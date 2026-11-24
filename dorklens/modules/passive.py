from __future__ import annotations

import json
import re
import urllib.parse

from .. import ui


async def crtsh(cfg, client, store) -> int:
    response = await client.get(
        f"https://crt.sh/?q=%25.{cfg.domain}&output=json",
        scope_check=False,
    )
    if not response or response.status != 200:
        return 0
    try:
        rows = json.loads(response.text)
    except json.JSONDecodeError:
        return 0
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value", "")).split("\n"):
            host = name.strip().lower().lstrip("*.")
            if host.endswith(cfg.domain) and cfg.scope.in_scope(host):
                total += store.add_url(f"https://{host}/", "crt.sh")
    if total:
        ui.info(f"crt.sh: {total} subdomains")
    return total


async def wayback(cfg, client, store) -> int:
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{cfg.domain}/*"
        "&output=json&collapse=urlkey&fl=original&limit=5000"
    )
    response = await client.get(url, scope_check=False)
    if not response or response.status != 200:
        return 0
    try:
        rows = json.loads(response.text)[1:]
    except (json.JSONDecodeError, IndexError):
        return 0
    total = 0
    for row in rows:
        if not row:
            continue
        value = str(row[0])
        if cfg.scope.in_scope(urllib.parse.urlsplit(value).hostname):
            total += store.add_url(value, "wayback")
    if total:
        ui.info(f"wayback: {total} purane URLs")
    return total


async def seeds(cfg, client, store) -> int:
    total = 0
    for scheme in cfg.schemes:
        base = f"{scheme}://{cfg.domain}"
        response = await client.get(f"{base}/robots.txt")
        if response and response.status == 200:
            for line in response.text.splitlines():
                text = line.strip()
                if text.lower().startswith(("disallow:", "allow:")):
                    path = text.split(":", 1)[1].strip()
                    if path and path != "/":
                        total += store.add_url(urllib.parse.urljoin(base, path), "robots")
        response = await client.get(f"{base}/sitemap.xml")
        if response and response.status == 200:
            for location in re.findall(r"<loc>([^<]+)</loc>", response.text)[:500]:
                if cfg.scope.in_scope(urllib.parse.urlsplit(location).hostname):
                    total += store.add_url(location, "sitemap")
    if total:
        ui.info(f"robots/sitemap: {total} paths")
    return total
