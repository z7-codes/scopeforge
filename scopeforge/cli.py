from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .analyzer import analyze_records, render_analysis
from .dorks import CATEGORIES, build_plan, render_plan
from .lab import render_lab
from .ledger import add_lead, list_leads, render_leads
from .report import render_report
from .scope import add_scope, get_scope, list_scopes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeforge", description="Scope-safe recon planning and evidence triage.")
    parser.add_argument("--version", action="version", version=f"scopeforge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("interactive", help="launch the interactive console")

    scope = sub.add_parser("scope", help="manage written authorization scopes")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_add = scope_sub.add_parser("add", help="add a scope")
    scope_add.add_argument("name")
    scope_add.add_argument("--domain", action="append", required=True)
    scope_add.add_argument("--exclude", action="append", default=[])
    scope_add.add_argument("--source", default="")
    scope_sub.add_parser("list", help="list saved scopes")

    plan = sub.add_parser("plan", help="generate scoped discovery queries")
    plan.add_argument("scope")
    plan.add_argument("--category", choices=CATEGORIES, default="recon")
    plan.add_argument("--limit", type=int, default=50)
    plan.add_argument("--format", choices=("text", "json", "md"), default="text")

    lead = sub.add_parser("lead", help="manage the lead ledger")
    lead_sub = lead.add_subparsers(dest="lead_command", required=True)
    lead_add = lead_sub.add_parser("add", help="add a lead")
    lead_add.add_argument("--scope", required=True)
    lead_add.add_argument("--candidate", required=True)
    lead_add.add_argument("--source", default="")
    lead_add.add_argument("--category", default="recon")
    lead_add.add_argument("--note", default="")
    lead_list = lead_sub.add_parser("list", help="list leads")
    lead_list.add_argument("--scope")
    lead_list.add_argument("--format", choices=("text", "json"), default="text")

    analyze = sub.add_parser("analyze", help="analyze recorded evidence")
    analyze.add_argument("path", help="JSON file or directory containing JSON evidence")
    analyze.add_argument("--format", choices=("text", "json", "md"), default="text")
    analyze.add_argument("--output", help="optional file path for output")

    lab = sub.add_parser("lab", help="show guided lab checks")
    lab.add_argument("scenario", choices=("localhost", "dvwa", "juice-shop", "ctf"))

    report = sub.add_parser("report", help="render a Markdown report draft")
    report.add_argument("analysis", help="JSON file from analyze --format json")
    report.add_argument("--scope", required=True)
    report.add_argument("--output")
    return parser


def load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("analyses", "records", "evidence"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [data]
    raise ValueError("unsupported evidence JSON shape: " + str(path))


def cmd_scope_add(args: argparse.Namespace) -> str:
    scope = add_scope(args.name, args.domain, args.exclude, args.source)
    return f"scope saved: {scope.name} | domains: {', '.join(scope.domains)}"


def cmd_scope_list() -> str:
    scopes = list_scopes()
    if not scopes:
        return "No scopes saved."
    lines = [f"Scopes - {len(scopes)}"]
    for scope in scopes:
        exclusions = ", ".join(scope.exclusions) or "-"
        source = scope.source or "-"
        lines.append(f"{scope.name}: domains={', '.join(scope.domains)} exclusions={exclusions} source={source}")
    return "\n".join(lines)


def cmd_plan(args: argparse.Namespace) -> str:
    scope = get_scope(args.scope)
    records = build_plan(scope, args.category, args.limit)
    return render_plan(records, args.format)


def cmd_lead_add(args: argparse.Namespace) -> str:
    lead = add_lead(args.scope, args.source, args.candidate, args.category, args.note)
    return f"lead added: {lead.id} | {lead.scope} | {lead.candidate}"


def cmd_lead_list(args: argparse.Namespace) -> str:
    return render_leads(list_leads(args.scope), args.format)


def cmd_analyze(args: argparse.Namespace) -> str:
    target = Path(args.path)
    if target.is_dir():
        paths = sorted(target.glob("*.json"))
        if not paths:
            raise ValueError("no JSON files found in " + str(target))
    else:
        paths = [target]
    records: list[dict[str, Any]] = []
    for path in paths:
        records.extend(load_records(path))
    output = render_analysis(analyze_records(records), args.format)
    if args.output:
        output_path = Path(args.output)
        if output_path.parent != Path("."):
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
        return f"analysis written: {output_path}"
    return output


def cmd_report(args: argparse.Namespace) -> str:
    analyses = load_records(Path(args.analysis))
    content = render_report(args.scope, analyses)
    if args.output:
        output = Path(args.output)
        if output.parent != Path("."):
            output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        return f"report written: {output}"
    return content


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(argv) if argv is not None else list(sys.argv[1:])
    if not raw_args:
        from .tui import run_interactive

        return run_interactive()
    args = build_parser().parse_args(raw_args)
    try:
        if args.command == "interactive":
            from .tui import run_interactive

            return run_interactive()
        if args.command == "scope":
            output = cmd_scope_add(args) if args.scope_command == "add" else cmd_scope_list()
        elif args.command == "plan":
            output = cmd_plan(args)
        elif args.command == "lead":
            output = cmd_lead_add(args) if args.lead_command == "add" else cmd_lead_list(args)
        elif args.command == "analyze":
            output = cmd_analyze(args)
        elif args.command == "lab":
            output = render_lab(args.scenario)
        elif args.command == "report":
            output = cmd_report(args)
        else:
            raise ValueError("unknown command: " + str(args.command))
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0
