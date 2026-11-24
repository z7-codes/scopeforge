import asyncio
import socket

from dorklens import demo
from dorklens.config import Config
from dorklens.http import Client
from dorklens.modules import crawl
from dorklens.scope import Scope
from dorklens.storage import Store


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def scan(port: int, cfg: Config, store: Store) -> int:
    client = Client(cfg)
    try:
        return await crawl.run(cfg, client, store)
    finally:
        await client.close()


def test_crawler_finds_scoped_links(tmp_path) -> None:
    port = free_port()
    server = demo.serve(port)
    cfg = Config.from_domain(f"127.0.0.1:{port}", stages=["crawl"], out_dir=tmp_path / "out")
    cfg.scope = Scope(allow=["127.0.0.1"])
    cfg.schemes = ["http"]
    cfg.rps_per_host = 50.0
    store = Store(cfg.out_dir / "state.db")
    try:
        total = asyncio.run(scan(port, cfg, store))
    finally:
        server.shutdown()
        server.server_close()
        store.close()
    reopened = Store(cfg.out_dir / "state.db")
    urls = {url for _, url in reopened.urls()}
    reopened.close()
    assert total > 0
    assert any("id=1" in url for url in urls)
    assert any("url=/x" in url for url in urls)
