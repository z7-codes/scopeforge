from __future__ import annotations

import json
import os
import re
import urllib.parse

from .errors import SearchError, UsageError
from .net import fetch

DDG_URL = "https://html.duckduckgo.com/html/?q="
CSE_URL = "https://www.googleapis.com/customsearch/v1"
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
LINK = re.compile(r'href="(/l/\?uddg=[^"]+|https?://[^"]+)"')


def from_file(path: str, limit: int = 10) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")][:limit]


def ddg(query: str, limit: int = 10) -> list[str]:
    response = fetch(DDG_URL + urllib.parse.quote_plus(query))
    urls: list[str] = []
    for match in LINK.finditer(response.text):
        candidate = match.group(1)
        if candidate.startswith("/l/"):
            parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(candidate).query)
            candidate = (parsed.get("uddg") or [""])[0]
        if candidate.startswith("http") and candidate not in urls:
            urls.append(candidate)
        if len(urls) >= limit:
            break
    return urls


def google_cse(query: str, limit: int = 10) -> list[str]:
    key = os.environ.get("SCOPEFORGE_CSE_KEY")
    cx = os.environ.get("SCOPEFORGE_CSE_CX")
    if not key or not cx:
        raise UsageError("google_cse needs SCOPEFORGE_CSE_KEY and SCOPEFORGE_CSE_CX")
    url = f"{CSE_URL}?key={key}&cx={cx}&num={min(limit, 10)}&q={urllib.parse.quote_plus(query)}"
    payload = json.loads(fetch(url).text)
    return [str(item["link"]) for item in payload.get("items", []) if item.get("link")][:limit]


def brave(query: str, limit: int = 10) -> list[str]:
    token = os.environ.get("SCOPEFORGE_BRAVE_KEY")
    if not token:
        raise UsageError("brave provider needs SCOPEFORGE_BRAVE_KEY")
    url = f"{BRAVE_URL}?count={min(limit, 20)}&q={urllib.parse.quote_plus(query)}"
    response = fetch(url, headers={"X-Subscription-Token": token, "Accept": "application/json"})
    payload = json.loads(response.text)
    results = payload.get("web", {}).get("results", [])
    return [str(item["url"]) for item in results if item.get("url")][:limit]


PROVIDERS = {"ddg": ddg, "google_cse": google_cse, "brave": brave}


def search(query: str, provider: str = "auto", limit: int = 10, source: str | None = None) -> list[str]:
    if provider == "file":
        if not source:
            raise UsageError("file provider needs --input")
        return from_file(source, limit)
    if provider != "auto":
        handler = PROVIDERS.get(provider)
        if handler is None:
            raise UsageError("unknown provider: " + provider)
        return handler(query, limit)
    failures: list[str] = []
    for name in ("google_cse", "brave", "ddg"):
        try:
            results = PROVIDERS[name](query, limit)
        except Exception as exc:
            failures.append(f"{name}: {exc}")
            continue
        if results:
            return results
        failures.append(f"{name}: 0 results")
    raise SearchError("all providers failed :: " + " | ".join(failures))
