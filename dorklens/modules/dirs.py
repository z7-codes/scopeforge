from __future__ import annotations

import asyncio
import random
import string
import urllib.parse

from rich.progress import TaskID

from .. import ui

ALLOWED = {200, 204, 301, 302, 307, 401, 403}


def randpath() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=14))


async def soft404(client, base: str) -> list[tuple[int, int]]:
    signature: list[tuple[int, int]] = []
    for _ in range(2):
        for probe in (f"zz{randpath()}.html", f"zz{randpath()}/"):
            response = await client.get(urllib.parse.urljoin(base, probe))
            if response:
                signature.append((response.status, response.length))
    return signature


def is_soft(signature: list[tuple[int, int]], status: int, length: int) -> bool:
    return any(
        status == value and abs(length - size) <= max(40, size * 0.02)
        for value, size in signature
    )


async def run(cfg, client, store, bases: list[str]) -> int:
    words = [
        line.strip()
        for line in cfg.wordlist.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    total = 0
    for base in bases:
        if cfg.dry_run:
            ui.info(f"{base} x {len(words)} words")
            continue
        signature = await soft404(client, base)
        if not signature:
            ui.warn(f"{base} jawab nahi de raha, skip")
            continue
        found = 0
        done = 0
        with ui.progress(len(words), base) as bar:
            task: TaskID = bar.add_task("dirs", total=len(words))

            async def probe(
                word: str,
                base: str = base,
                task: TaskID = task,
                signature: list[tuple[int, int]] = signature,
            ) -> None:
                nonlocal found, done
                url = urllib.parse.urljoin(base, word)
                response = await client.get(url)
                done += 1
                bar.update(task, completed=done)
                if (
                    response
                    and response.status in ALLOWED
                    and not is_soft(signature, response.status, response.length)
                    and store.add_url(url, f"dir:{response.status}")
                ):
                    found += 1

            await asyncio.gather(*(probe(word) for word in words))
        if found:
            ui.info(f"{base}: +{found}")
        total += found
    return total
