from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from .config import Config


class Bucket:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / max(rps, 0.1)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def take(self) -> None:
        async with self.lock:
            wait = self.interval - (time.monotonic() - self.last)
            if wait > 0:
                await asyncio.sleep(wait + random.uniform(0, 0.05))
            self.last = time.monotonic()


class Response:
    __slots__ = ("status", "headers", "text", "elapsed", "length", "url")

    def __init__(self, response: httpx.Response, elapsed: float) -> None:
        self.status = response.status_code
        self.headers = response.headers
        self.text = response.text
        self.elapsed = elapsed
        self.length = len(response.content)
        self.url = str(response.url)

    def __repr__(self) -> str:
        return f"<{self.status} {self.length}B {self.elapsed:.2f}s>"


class Client:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.sem = asyncio.Semaphore(cfg.concurrency)
        self.buckets: dict[str, Bucket] = {}
        self.loose_hosts: set[str] = set()
        common: dict[str, Any] = {
            "timeout": cfg.timeout,
            "follow_redirects": False,
            "headers": {"User-Agent": cfg.user_agent},
            "limits": httpx.Limits(max_connections=cfg.concurrency * 2),
            "proxy": cfg.proxy,
        }
        self.secure = httpx.AsyncClient(verify=True, **common)
        self.loose = httpx.AsyncClient(verify=False, **common)

    @staticmethod
    def _host(url: str) -> str:
        try:
            return httpx.URL(url).host or ""
        except Exception:
            return ""

    def _bucket(self, host: str) -> Bucket:
        bucket = self.buckets.get(host)
        if bucket is None:
            bucket = self.buckets[host] = Bucket(self.cfg.rps_per_host)
        return bucket

    def _client(self, host: str) -> httpx.AsyncClient:
        return self.loose if self.cfg.insecure or host in self.loose_hosts else self.secure

    async def get(self, url: str, *, scope_check: bool = True, **kwargs: Any) -> Response | None:
        host = self._host(url)
        if not host or (scope_check and not self.cfg.scope.in_scope(host)):
            return None
        async with self.sem:
            await self._bucket(host).take()
            for attempt in range(self.cfg.retries + 1):
                started = time.monotonic()
                try:
                    response = await self._client(host).get(url, **kwargs)
                    return Response(response, time.monotonic() - started)
                except httpx.ConnectError as exc:
                    if "ssl" in str(exc).lower() and host not in self.loose_hosts:
                        self.loose_hosts.add(host)
                        try:
                            fallback_started = time.monotonic()
                            response = await self.loose.get(url, **kwargs)
                            return Response(response, time.monotonic() - fallback_started)
                        except Exception:
                            continue
                    if attempt < self.cfg.retries:
                        await asyncio.sleep(1.4 ** (attempt + 1))
                except httpx.TransportError:
                    if attempt < self.cfg.retries:
                        await asyncio.sleep(1.4 ** (attempt + 1))
                except Exception:
                    return None
        return None

    async def close(self) -> None:
        await self.secure.aclose()
        await self.loose.aclose()
