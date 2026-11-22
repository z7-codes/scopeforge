from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping

from .budget import Budget
from .errors import NetworkError
from .models import Scope
from .scope import guard, normalize_token

USER_AGENT = "ScopeForge/0.4 scope-safe-recon"
ACCEPT = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    elapsed: float

    @property
    def content_type(self) -> str:
        return str(self.headers.get("Content-Type", "")).lower()

    @property
    def location(self) -> str:
        return str(self.headers.get("Location", ""))

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def fetch(
    url: str,
    timeout: float = 8.0,
    max_bytes: int = 65536,
    headers: Mapping[str, str] | None = None,
) -> Response:
    request_headers = {"User-Agent": USER_AGENT, "Accept": ACCEPT}
    if headers:
        request_headers.update({str(key): str(value) for key, value in headers.items()})
    request = urllib.request.Request(url, headers=request_headers)
    started = time.monotonic()
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(max_bytes)
            headers = dict(response.headers.items())
            return Response(url, int(response.status), headers, body, time.monotonic() - started)
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
        try:
            body = exc.read(max_bytes)
        except OSError:
            body = b""
        return Response(url, int(exc.code), headers, body, time.monotonic() - started)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"{url}: {exc}") from exc


@dataclass
class Session:
    budget: Budget
    scope: Scope | None = None
    lab: bool = False
    timeout: float = 8.0
    max_bytes: int = 65536

    def get(self, url: str) -> Response:
        guard(self.scope, url, self.lab)
        self.budget.spend(normalize_token(url))
        return fetch(url, self.timeout, self.max_bytes)
