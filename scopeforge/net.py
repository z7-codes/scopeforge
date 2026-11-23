from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field

from . import __version__
from .budget import Budget
from .errors import NetworkError
from .models import Scope
from .scope import guard, normalize_token

USER_AGENT = f"ScopeForge/{__version__} scope-safe-recon"
ACCEPT = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


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
    headers: dict[str, str] = field(default_factory=dict)
    allow_redirect: bool = False
    max_redirects: int = 1

    def __post_init__(self) -> None:
        self.max_redirects = max(0, min(int(self.max_redirects), 1))

    def get(self, url: str) -> Response:
        guard(self.scope, url, self.lab)
        current = url
        response = self._fetch_checked(current)
        hop = 0
        while (
            self.allow_redirect
            and hop < self.max_redirects
            and response.status in REDIRECT_CODES
            and response.location
        ):
            current = urllib.parse.urljoin(current, response.location)
            guard(self.scope, current, self.lab)
            response = self._fetch_checked(current)
            hop += 1
        return response

    def _fetch_checked(self, url: str) -> Response:
        self.budget.spend(normalize_token(url))
        return fetch(url, self.timeout, self.max_bytes, self.headers)
