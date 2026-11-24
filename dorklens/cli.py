from __future__ import annotations

import argparse
import asyncio
import sys
import time
import webbrowser
from pathlib import Path

from . import __version__, demo, doctor, selftest, ui
from .config import TAGLINE, Config
from .http import Client
from .modules import dirs, dork, params, passive, payloads
from .report import write
from .scope import Scope
from .storage import Store

SUBS = {"wizard", "doctor", "demo", "report", "init", "selftest"}


def build_cfg(args: argparse.Namespace) -> Config:
    config_path = getattr(args, "config", None)
    if config_path:
        cfg = Config.from_file(config_path)
    else:
        cfg = Config.from_domain(str(getattr(args, "domain", "example.com")))
    scope_value = getattr(args, "scope", None)
    if scope_value:
        cfg.scope = Scope(
            allow=[item.strip() for item in str(scope_value).split(",") if item.strip()],
            deny=cfg.scope.deny,
        )
    profile = getattr(args, "profile", None)
    if profile:
        cfg.apply_profile(profile)
    for name in ("insecure", "min_confidence", "concurrency", "proxy", "out"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(cfg, "out_dir" if name == "out" else name, value)
    if getattr(args, "dry_run", False):
        cfg.dry_run = True
    return cfg


async def run_stage(name: str, action, *arguments: object) -> int:
    with ui.stage(name):
        try:
            return int(await action(*arguments))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            ui.err(f"{name}: {exc}")
            return 0


async def pipeline(cfg: Config) -> int:
    store = Store(cfg.out_dir / "state.db")
    client = Client(cfg)
    started = time.monotonic()
    try:
        if "passive" in cfg.stages:
            async def collect_passive() -> int:
                total = await run_stage("passive", passive.crtsh, cfg, client, store)
                total += await run_stage("passive", passive.wayback, cfg, client, store)
                total += await run_stage("passive", passive.seeds, cfg, client, store)
                ui.info(f"total +{total}")
                return total

            await collect_passive()

        if "dork" in cfg.stages:
            total = await run_stage("dork", dork.run, cfg, client, store)
            ui.info(f"+{total}")

        bases = [f"{scheme}://{cfg.domain}/" for scheme in cfg.schemes]
        if "dirs" in cfg.stages:
            total = await run_stage("dirs", dirs.run, cfg, client, store, bases)
            ui.info(f"+{total}")

        targets = params.collect(cfg, store)
        ui.info(f"{len(targets)} parametrized URLs mile")

        if "payload" in cfg.stages and targets:
            total = await run_stage("payload", payloads.run, cfg, client, store, targets)
            ui.info(f"{total} findings")

        if "blind" in cfg.stages and targets and cfg.deep:
            total = await run_stage("blind", payloads.blind, cfg, client, store, targets)
            ui.info(f"{total} timing findings")
    finally:
        await client.close()
        path = write(store, cfg.out_dir)
        ui.summary(store.count("urls"), store.count("findings"), time.monotonic() - started, path)
        store.close()
    return 0


def cmd_wizard(args: argparse.Namespace | None) -> int:
    domain = ui.ask_domain()
    profile = ui.ask_profile()
    ui.info(f"scope: {domain}, *.{domain}")
    if not ui.ask_go():
        return 0
    cfg = Config.from_domain(domain).apply_profile(profile)
    return asyncio.run(pipeline(cfg))


def cmd_demo(args: argparse.Namespace) -> int:
    port = int(args.port)
    server = demo.serve(port)
    ui.head("demo")
    ui.info(f"local site: http://127.0.0.1:{port}  (asli target nahi, sirf dikhane ke liye)")
    cfg = Config.from_domain(
        f"127.0.0.1:{port}",
        stages=["dirs", "payload"],
        out_dir=Path(args.out or "dorklens-demo"),
    )
    cfg.scope = Scope(allow=["127.0.0.1"])
    cfg.schemes = ["http"]
    cfg.wordlist = Path(__file__).parent / "data" / "demo-wordlist.txt"
    cfg.rps_per_host = 50.0
    cfg.min_confidence = 1
    cfg.dry_run = False
    try:
        return asyncio.run(pipeline(cfg))
    finally:
        server.shutdown()
        server.server_close()


def cmd_report(args: argparse.Namespace) -> int:
    out = Path(args.out)
    store = Store(out / "state.db")
    path = write(store, out)
    ui.ok(f"report: {path}")
    store.close()
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    template = Path(__file__).parent / "data" / "dorklens.yaml.example"
    destination = Path("dorklens.yaml")
    if destination.exists():
        ui.warn("dorklens.yaml pehle se hai")
        return 1
    destination.write_text(
        template.read_text(encoding="utf-8").replace("{{d}}", args.domain),
        encoding="utf-8",
    )
    ui.ok(f"{destination} bana - ab: dorklens -c dorklens.yaml")
    return 0


def subparser(sub: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"dorklens {sub}")
    if sub == "demo":
        parser.add_argument("--port", type=int, default=8765)
        parser.add_argument("-o", "--out", default=None)
    if sub == "report":
        parser.add_argument("-o", "--out", default="dorklens-out")
    if sub == "init":
        parser.add_argument("domain")
    return parser


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    ui.banner()
    if not values:
        return cmd_wizard(None)

    if values[0] in SUBS:
        sub = values[0]
        args = subparser(sub).parse_args(values[1:])
        dispatch = {
            "wizard": cmd_wizard,
            "demo": cmd_demo,
            "report": cmd_report,
            "init": cmd_init,
            "doctor": lambda _: 0 if doctor.run() else 1,
            "selftest": lambda _: 0 if selftest.run_all() else 1,
        }
        try:
            return dispatch[sub](args)
        except ValueError as exc:
            ui.err(str(exc))
            return 2

    parser = argparse.ArgumentParser(prog="dorklens", description=TAGLINE)
    parser.add_argument("domain")
    parser.add_argument("-c", "--config")
    parser.add_argument("-p", "--profile", choices=("quick", "full", "deep", "lab"))
    parser.add_argument("-s", "--scope")
    parser.add_argument("--insecure", action="store_true", help="TLS error ignore")
    parser.add_argument("-k", "--min-confidence", type=int)
    parser.add_argument("-C", "--concurrency", type=int)
    parser.add_argument("--proxy")
    parser.add_argument("-o", "--out", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--open", action="store_true", help="report browser mein kholo")
    parser.add_argument("-y", "--yes", action="store_true", help="bina puche chalao")
    parser.add_argument("-V", "--version", action="version", version=f"dorklens {__version__}")
    args = parser.parse_args(values)

    try:
        cfg = build_cfg(args)
    except ValueError as exc:
        ui.err(str(exc))
        return 2

    ui.head("target")
    ui.info(f"{cfg.domain}  |  scope {cfg.scope.allow}  |  profile {args.profile or 'full'}")
    if not args.yes and not ui.ask_go():
        return 0
    try:
        code = asyncio.run(pipeline(cfg))
    except KeyboardInterrupt:
        ui.warn("ruk gaya - progress save hai, resume ke liye wahi command dobara chalayein")
        code = 130
    except ValueError as exc:
        ui.err(str(exc))
        return 2
    if args.open:
        webbrowser.open((cfg.out_dir / "report.html").resolve().as_uri())
    return code


if __name__ == "__main__":
    sys.exit(main())
