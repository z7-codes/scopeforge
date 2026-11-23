from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html import unescape

from . import dorks
from .errors import SearchError, UsageError
from .redact import redact

DDG_URL = "https://html.duckduckgo.com/html/?q="
CSE_URL = "https://customsearch.googleapis.com/customsearch/v1"
BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
USER_AGENT = "DorkLens/1.0 passive-exposure-discovery"
LINK = re.compile(r'href="(/l/\?uddg=[^"]+|https?://[^"]+)"')


@dataclass(frozen=True)
class SearchHit:
    url: str
    query: str
    category: str
    provider: str

    def to_dict(self) -> dict[str, str]:
        return {
            "url": self.url,
            "query": self.query,
            "category": self.category,
            "provider": self.provider,
        }


@dataclass
class SearchResult:
    domain: str
    category: str
    provider: str
    queries: list[str] = field(default_factory=list)
    hits: list[SearchHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": "DorkLens",
            "domain": self.domain,
            "category": self.category,
            "provider": self.provider,
            "queries": self.queries,
            "hits": [item.to_dict() for item in self.hits],
            "warnings": self.warnings,
        }


def fetch(url: str, timeout: float = 10.0, max_bytes: int = 262144, headers: dict[str, str] | None = None) -> str:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(max_bytes).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SearchError(str(exc)) from exc


def from_file(path: str, limit: int = 100) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        values = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    return values[:limit]


def ddg(query: str, limit: int = 10) -> list[str]:
    body = fetch(DDG_URL + urllib.parse.quote_plus(query))
    urls: list[str] = []
    for match in LINK.finditer(body):
        candidate = unescape(match.group(1))
        if candidate.startswith("/l/"):
            parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(candidate).query)
            candidate = (parsed.get("uddg") or [""])[0]
        if candidate.startswith(("http://", "https://")) and candidate not in urls:
            urls.append(candidate)
        if len(urls) >= limit:
            break
    return urls


def google_cse(query: str, limit: int = 10) -> list[str]:
    key = os.environ.get("DORKLENS_CSE_KEY") or os.environ.get("SCOPEFORGE_CSE_KEY")
    cx = os.environ.get("DORKLENS_CSE_CX") or os.environ.get("SCOPEFORGE_CSE_CX")
    if not key or not cx:
        raise UsageError("google_cse needs DORKLENS_CSE_KEY and DORKLENS_CSE_CX")
    params = {"key": key, "cx": cx, "num": str(min(limit, 10)), "q": query}
    body = fetch(CSE_URL + "?" + urllib.parse.urlencode(params))
    payload = json.loads(body)
    return [str(item["link"]) for item in payload.get("items", []) if item.get("link")][:limit]


def brave(query: str, limit: int = 10) -> list[str]:
    token = os.environ.get("DORKLENS_BRAVE_KEY") or os.environ.get("SCOPEFORGE_BRAVE_KEY")
    if not token:
        raise UsageError("brave needs DORKLENS_BRAVE_KEY")
    params = {"count": str(min(limit, 20)), "q": query}
    body = fetch(
        BRAVE_URL + "?" + urllib.parse.urlencode(params),
        headers={"X-Subscription-Token": token, "Accept": "application/json"},
    )
    payload = json.loads(body)
    return [str(item["url"]) for item in payload.get("web", {}).get("results", []) if item.get("url")][:limit]


PROVIDERS = {"ddg": ddg, "google_cse": google_cse, "brave": brave}


def _call_provider(query: str, provider: str, limit: int) -> list[str]:
    handler = PROVIDERS.get(provider)
    if handler is None:
        raise UsageError("unknown provider: " + provider)
    return handler(query, limit)


def search(
    domain: str,
    category: str = "all",
    provider: str = "auto",
    limit: int = 10,
    max_queries: int = 40,
    max_results: int = 100,
    input_file: str = "",
    delay: float = 0.0,
) -> SearchResult:
    if provider == "file" and not input_file:
        raise UsageError("file provider needs --input")
    target = dorks.normalize_domain(domain)
    plans = dorks.build(target, category, max_queries)
    result = SearchResult(target, category, provider, [item.query for item in plans])
    seen: set[str] = set()
    failed: set[str] = set()

    def add(urls: list[str], dork: dorks.Dork | None, origin: str) -> None:
        for url in urls:
            safe = redact(url)
            if not safe or safe in seen:
                continue
            seen.add(safe)
            result.hits.append(
                SearchHit(safe, dork.query if dork else "local import", dork.category if dork else "import", origin)
            )
            if len(result.hits) >= max_results:
                return

    if input_file:
        add(from_file(input_file, max_results), None, "file")
    if provider == "file" or len(result.hits) >= max_results:
        return result

    for plan in plans:
        chosen = provider
        if provider == "auto":
            chosen = next((name for name in ("google_cse", "brave", "ddg") if name not in failed), "")
            if not chosen:
                result.warnings.append("all passive providers failed")
                break
        try:
            urls = _call_provider(plan.query, chosen, limit)
        except Exception as exc:
            message = f"{chosen}: {exc}"
            if message not in result.warnings:
                result.warnings.append(message)
            if provider == "auto":
                failed.add(chosen)
            continue
        add(urls, plan, chosen)
        if len(result.hits) >= max_results:
            break
        if delay > 0:
            time.sleep(delay)
    return result
