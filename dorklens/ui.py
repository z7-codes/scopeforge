from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table

from .config import TAGLINE

console = Console(emoji=False)
LABEL = {
    "passive": "Passive discovery",
    "dork": "Dork search",
    "crawl": "Crawling",
    "dirs": "Directory check",
    "params": "Parameter collection",
    "payload": "Payload testing",
    "blind": "Timing checks",
}
CONF = {2: "yellow", 3: "orange3", 4: "green", 5: "bright_green"}
SEV = {2: "low", 3: "medium", 4: "high", 5: "critical"}
BANNER = r"""
 ____             _  _     _
|  _ \  ___  _ __| || |   | | ___ _ __  ___
| | | |/ _ \| '__| || |_  | |/ _ \ '_ \/ __|
| |_| | (_) | |  | || |_  | |  __/ | | \__ \
|____/ \___/|_|  |_||_(_) |_|\___|_| |_|___/
"""


def banner() -> None:
    console.print(BANNER, style="bright_red", highlight=False)
    console.print(f"  {TAGLINE}\n", style="dim")


def head(text: str) -> None:
    console.print(Rule(f"[bold]{escape(text)}", style="grey37"))


@contextmanager
def stage(name: str) -> Iterator[None]:
    head(LABEL.get(name, name))
    yield


def ok(message: str) -> None:
    console.print(f"  [green]+[/] {message}")


def info(message: str) -> None:
    console.print(f"  [grey62]{message}[/]")


def warn(message: str) -> None:
    console.print(f"  [yellow]![/] {message}")


def err(message: str) -> None:
    console.print(f"  [red]x[/] {message}")


def hit(conf: int, category: str, param: str, payload: str, url: str) -> None:
    color = CONF.get(conf, "white")
    console.print(
        f"  [{color}]HIT {conf}/5[/] [bold]{escape(category)}[/] "
        f"param=[cyan]{escape(param)}[/] pay=[magenta]{escape(payload[:30])}[/] "
        f"[dim]{escape(url[:64])}[/]"
    )


def report(items: list[dict]) -> None:
    confirmed = [item for item in items if item["confirmed"]]
    unconfirmed = [item for item in items if not item["confirmed"]]

    def card(item: dict) -> None:
        level = SEV.get(int(item["confidence"]), "info").upper()
        signals = ", ".join(str(signal) for signal in item["signals"])
        console.print(f"  [bold]{level}[/] {escape(str(item['category']))} on [cyan]{escape(str(item['param']))}[/]")
        console.print(f"    URL: {escape(str(item['url']))}")
        console.print(f"    Payload: {escape(str(item['payload']))}")
        console.print(f"    Signals: {escape(signals)}")
        console.print(f"    Evidence: {escape(str(item['evidence']))}")
        console.print(f"    Next: {escape(str(item['advice']))}")
        if item["variants"]:
            console.print(f"    Variants: +{item['variants']}")
        console.print()

    head("Report")
    info(f"Findings: {len(confirmed)} | Unconfirmed: {len(unconfirmed)}")
    if not items:
        info("No findings.")
        return
    for item in confirmed:
        card(item)
    if unconfirmed:
        head("Unconfirmed (timing-based)")
        for item in unconfirmed:
            card(item)


def progress(total: int, label: str) -> Progress:
    return Progress(
        TextColumn(f"[grey62]{escape(label)}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    )


def summary(urls: int, findings: int, seconds: float, out: Path) -> None:
    body = (
        f"[bold]{findings}[/] findings  |  [bold]{urls}[/] URLs  |  {seconds:.0f}s\n\n"
        f"state: [cyan]{escape(str(out / 'state.db'))}[/]\n"
        f"findings: [cyan]{escape(str(out / 'findings.json'))}[/]"
    )
    console.print(Panel(body, title="Done", border_style="red" if findings else "grey37"))


def table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    rendered = Table(title=title)
    for column in columns:
        rendered.add_column(column)
    for row in rows:
        rendered.add_row(*row)
    console.print(rendered)


def ask_domain() -> str:
    while True:
        domain = Prompt.ask("[bold]Target domain[/]").strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if domain.count(".") >= 1 and " " not in domain:
            return domain
        warn("Invalid domain, for example: example.com")


def ask_profile() -> str:
    console.print("  [cyan]1[/] quick  - discovery only, fast, no payloads")
    console.print("  [cyan]2[/] full   - full scan with payload testing")
    console.print("  [cyan]3[/] deep   - full plus timing checks (slower)")
    choice = Prompt.ask("[bold]How deep?[/]", choices=["1", "2", "3"], default="2")
    return {"1": "quick", "2": "full", "3": "deep"}[choice]


def ask_go() -> bool:
    return Confirm.ask("[bold]Start?[/]", default=True)
