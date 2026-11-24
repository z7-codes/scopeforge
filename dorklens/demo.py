from __future__ import annotations

import threading
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "data" / "demo"
PAGE = "<html><body><h1>demo page</h1><p>id={}</p>{}</body></html>"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(FIXTURES), **kwargs)

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parts = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path == "/page":
            identifier = query.get("id", "1")
            if "'" in identifier:
                body = PAGE.format(identifier, "<b>SQLSTATE[42000]: syntax error near '''</b>")
                self._send(500, body)
                return
            body = PAGE.format(identifier, "x" * (900 if identifier == "1 and 1=1" else 40))
            self._send(200, body)
            return
        if parts.path == "/go":
            self.send_response(302)
            self.send_header("Location", query.get("url", "/"))
            self.end_headers()
            return
        if parts.path == "/read":
            name = query.get("file", "")
            if "passwd" in name:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
                self._send(200, body)
                return
            self._send(200, "file not found")
            return
        super().do_GET()

    def _send(self, code: int, body: str) -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
