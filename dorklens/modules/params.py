from __future__ import annotations

import urllib.parse

INTERESTING = {
    "id", "pid", "cat", "item", "page", "file", "path", "url", "redirect",
    "next", "return", "target", "download", "doc", "include", "template",
    "view", "src", "callback", "q", "s", "search", "keyword", "name",
    "lang", "user", "username", "email", "host", "ip", "cmd", "feed", "dest", "to",
}


def collect(cfg, store) -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    for _, url in store.urls():
        parts = urllib.parse.urlsplit(url)
        if not parts.query or not cfg.scope.in_scope(parts.hostname):
            continue
        keys = [key for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
        interesting = [key for key in keys if key.lower() in INTERESTING]
        if interesting:
            found.append((url, interesting))
    return found
