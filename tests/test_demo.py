import asyncio
import socket

from dorklens import demo
from dorklens.cli import pipeline
from dorklens.config import DATA, Config
from dorklens.scope import Scope
from dorklens.storage import Store


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_offline_demo_produces_real_findings(tmp_path) -> None:
    port = free_port()
    server = demo.serve(port)
    cfg = Config.from_domain(
        f"127.0.0.1:{port}",
        stages=["dirs", "payload"],
        out_dir=tmp_path / "out",
    )
    cfg.scope = Scope(allow=["127.0.0.1"])
    cfg.schemes = ["http"]
    cfg.wordlist = DATA / "demo-wordlist.txt"
    cfg.rps_per_host = 50.0
    cfg.min_confidence = 1
    try:
        asyncio.run(pipeline(cfg))
    finally:
        server.shutdown()
        server.server_close()
    store = Store(tmp_path / "out" / "state.db")
    categories = {str(row[3]) for row in store.findings()}
    store.close()
    assert {"sqli_error", "sqli_bool", "open_redirect", "lfi"} <= categories
