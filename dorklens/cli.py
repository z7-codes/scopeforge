from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, dorks, ui
from . import report as report_module
from . import search as search_module
from .errors import DorkLensError

COMMANDS = {"dorks", "search", "report", "categories"}


def _write(text: str, output: str) -> None:
    if not output:
        print(text)
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"saved: {path}", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dorklens",
        description="DorkLens generates advanced dorks and collects passive public exposure signals.",
    )
    parser.add_argument("--version", action="version", version=f"DorkLens {__version__}")
    commands = parser.add_subparsers(dest="command")

    gen = commands.add_parser("dorks", help="generate dork queries for a domain")
    gen.add_argument("domain", help="example.com or https://example.com")
    gen.add_argument("--category", default="all", help="category name or all")
    gen.add_argument("--limit", type=int, default=0, help="maximum queries; 0 means all")
    gen.add_argument("--format", choices=("text", "json", "md"), default="text")

    find = commands.add_parser("search", help="run passive searches and collect public results")
    find.add_argument("domain", help="example.com or https://example.com")
    find.add_argument("--category", default="all", help="category name or all")
    find.add_argument(
        "--provider",
        choices=("auto", "ddg", "google_cse", "brave", "file"),
        default="auto",
    )
    find.add_argument("--input", default="", help="local URL file for the file provider or import")
    find.add_argument("--limit", type=int, default=10, help="results per query")
    find.add_argument("--max-queries", type=int, default=40, help="queries to run; 0 means all")
    find.add_argument("--max-results", type=int, default=100, help="maximum collected results")
    find.add_argument("--delay", type=float, default=0.0, help="delay between queries in seconds")
    find.add_argument("--format", choices=("text", "json", "md"), default="text")
    find.add_argument("--output", default="", help="write output to a file")

    make_report = commands.add_parser("report", help="render a report from saved results JSON")
    make_report.add_argument("input", help="results JSON from search --format json")
    make_report.add_argument("--format", choices=("md", "text", "json"), default="md")
    make_report.add_argument("--output", default="", help="write output to a file")

    listing = commands.add_parser("categories", help="list dork categories")
    listing.add_argument("--format", choices=("text", "json"), default="text")

    return parser


def _dork_text(plans: list[dorks.Dork], domain: str) -> str:
    lines = [ui.banner(), f"Target: {domain}", f"Queries: {len(plans)}", ""]
    current = ""
    for plan in plans:
        if plan.category != current:
            current = plan.category
            lines.append(ui.section(current))
            if plan.description:
                lines.append(plan.description)
                lines.append("")
        lines.append(plan.query)
    lines.extend(
        [
            "",
            "Passive dork plan only. No requests were sent to the target.",
            "Public results are signals that require manual verification.",
            "",
        ]
    )
    return "\n".join(lines)


def _dork_markdown(plans: list[dorks.Dork], domain: str) -> str:
    lines = [
        "# DorkLens Query Plan",
        "",
        f"- Domain: {domain}",
        f"- Queries: {len(plans)}",
        "",
        "Passive dork plan only. No requests were sent to the target.",
        "",
    ]
    current = ""
    for plan in plans:
        if plan.category != current:
            current = plan.category
            lines.extend([f"## {current}", ""])
            if plan.description:
                lines.extend([plan.description, ""])
        lines.append(f"- `{plan.query}`")
    return "\n".join(lines) + "\n"


def _dorks(args: argparse.Namespace) -> int:
    target = dorks.normalize_domain(args.domain)
    plans = dorks.build(target, args.category, args.limit)
    if args.format == "json":
        payload = {
            "tool": "DorkLens",
            "domain": target,
            "queries": [item.to_dict() for item in plans],
        }
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif args.format == "md":
        text = _dork_markdown(plans, target)
    else:
        text = _dork_text(plans, target)
    _write(text, getattr(args, "output", ""))
    return 0


def _search(args: argparse.Namespace) -> int:
    result = search_module.search(
        args.domain,
        category=args.category,
        provider=args.provider,
        limit=args.limit,
        max_queries=args.max_queries,
        max_results=args.max_results,
        input_file=args.input,
        delay=args.delay,
    )
    for warning in result.warnings:
        print("warn: " + warning, file=sys.stderr)
    if args.format == "json":
        text = report_module.render_json(result)
    elif args.format == "md":
        text = report_module.render_markdown(result)
    else:
        text = ui.banner() + "\n" + report_module.render_text(result)
    _write(text, args.output)
    return 0


def _report(args: argparse.Namespace) -> int:
    result = report_module.load_results(args.input)
    if args.format == "json":
        text = report_module.render_json(result)
    elif args.format == "text":
        text = report_module.render_text(result)
    else:
        text = report_module.render_markdown(result)
    _write(text, args.output)
    return 0


def _categories(args: argparse.Namespace) -> int:
    values = [{"name": name, "description": dorks.description(name)} for name in dorks.categories()]
    if args.format == "json":
        text = json.dumps(values, indent=2, sort_keys=True) + "\n"
    else:
        lines = [ui.banner(), "Categories", ""]
        lines.extend(f"{item['name']:<24} {item['description']}" for item in values)
        text = "\n".join(lines) + "\n"
    print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not values:
        parser.print_help()
        return 2
    if values[0] not in COMMANDS and values[0] not in ("-h", "--help", "--version"):
        values = ["dorks", *values]
    args = parser.parse_args(values)
    try:
        if args.command == "search":
            return _search(args)
        if args.command == "report":
            return _report(args)
        if args.command == "categories":
            return _categories(args)
        if args.command == "dorks":
            return _dorks(args)
        parser.print_help()
        return 2
    except DorkLensError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
