from __future__ import annotations

import html
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .errors import UsageError

ENV_BODY = "APP_ENV=local\nAPI_URL=http://127.0.0.1:8099\nSECRET_KEY=lab-only-value\n"
GIT_BODY = "ref: refs/heads/main\n"
BACKUP_BODY = "PK\x03\x04 scopeforge-lab-placeholder"


def _query(handler: BaseHTTPRequestHandler, name: str) -> str:
    values = parse_qs(urlsplit(handler.path).query).get(name, [""])
    return values[0]


def _page(title: str, body: str) -> bytes:
    return f"<!doctype html><html><head><title>{html.escape(title)}</title></head><body>{body}</body></html>".encode()


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ScopeForgeLab/0.4"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            payload = _query(self, "q")
            self._send(_page("reflect", f"<h1>ScopeForge Lab</h1><div id='result'>{payload}</div>"))
            return
        if path == "/sqli":
            payload = _query(self, "id")
            low = payload.lower()
            matched = "or 1=1" in low or "' or" in low or "admin'--" in low
            body = "<div id='result'>Welcome, admin</div>" if matched else "<div id='result'>no rows</div>"
            self._send(_page("sqli", body))
            return
        if path == "/traverse":
            payload = _query(self, "file")
            body = "<pre>root:x:0:0:root:/root:/bin/sh</pre>" if "../" in payload else "<pre>not found</pre>"
            self._send(_page("traversal", body))
            return
        if path == "/ssti":
            payload = _query(self, "name")
            body = "<pre>RESULT:49</pre>" if "{{7*7}}" in payload else f"<pre>{html.escape(payload)}</pre>"
            self._send(_page("ssti", body))
            return
        if path == "/redirect":
            target = _query(self, "url") or "http://127.0.0.1:8099/"
            self._send(_page("redirect", "<a>continue</a>"), 302, {"Location": target})
            return
        if path == "/.git/HEAD":
            self._send(GIT_BODY.encode())
            return
        if path == "/.env":
            self._send(ENV_BODY.encode())
            return
        if path == "/backup.zip":
            self._send(BACKUP_BODY.encode("utf-8"))
            return
        self._send(_page("not found", "<h1>404</h1>"), 404)


def serve(port: int = 8099, bind: str = "127.0.0.1") -> None:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise UsageError("bind must be an IP address") from exc
    if not address.is_loopback:
        raise UsageError("lab server is loopback-only; refusing to bind " + bind)
    if not 1 <= port <= 65535:
        raise UsageError("port must be between 1 and 65535")
    server = ThreadingHTTPServer((bind, port), LabHandler)
    print(f"ScopeForge lab listening on http://{bind}:{port}")
    print("endpoints: / ?q= | /sqli?id= | /traverse?file= | /ssti?name= | /redirect?url=")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
