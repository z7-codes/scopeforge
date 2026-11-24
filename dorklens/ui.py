from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table

from .config import TAGLINE

console = Console()
LABEL = {
    "passive": "Dhoondh raha (passive)",
    "dork": "Dorking",
    "dirs": "Folders check",
    "params": "Param dhoondh raha",
    "payload": "Payload test",
    "blind": "Blind test",
}
CONF = {2: "yellow", 3: "orange3", 4: "green", 5: "bright_green"}
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
    console.print(Rule(f"[bold]{text}", style="grey37"))


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
        f"  [{color}]HIT {conf}/5[/] [bold]{category}[/] param=[cyan]{param}[/] "
        f"pay=[magenta]{payload[:30]}[/] [dim]{url[:64]}[/]"
    )


def progress(total: int, label: str) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn(f"[grey62]{label}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    )


def summary(urls: int, findings: int, seconds: float, path: Path) -> None:
    body = (
        f"[bold]{findings}[/] findings  |  [bold]{urls}[/] URLs  |  {seconds:.0f}s\n\n"
        f"report: [cyan]{path}[/]"
    )
    console.print(Panel(body, title="khatam", border_style="red" if findings else "grey37"))


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
        warn("domain theek nahi lag raha (jaise: example.com)")


def ask_profile() -> str:
    console.print("  [cyan]1[/] quick  - sirf dhoondhna, tez, payload nahi")
    console.print("  [cyan]2[/] full   - poora scan + payload test")
    console.print("  [cyan]3[/] deep   - full + blind test (dheema)")
    choice = Prompt.ask("[bold]Kitna gehra?[/]", choices=["1", "2", "3"], default="2")
    return {"1": "quick", "2": "full", "3": "deep"}[choice]


def ask_go() -> bool:
    return Confirm.ask("[bold]Shuru karein?[/]", default=True)
