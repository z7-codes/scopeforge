from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import __version__, findings, inject, probe, search, ui, verify
from .analyzer import analyze_records, render_analysis
from .budget import Budget
from .config import load_config, set_value
from .dorks import CATEGORIES, build_plan, render_plan
from .errors import NothingFound, ScopeForgeError, SearchError, UsageError
from .evidence import folder as evidence_folder
from .exposure import build_worksheet
from .exposure import render as render_scan
from .exposure import run as run_scan
from .ledger import add_lead, list_leads, render_leads
from .net import Session
from .preflight import check as check_preflight
from .report import render_report
from .scope import add_scope, get_scope, list_scopes, remove_scope
from .state import clear as clear_state
from .state import load_seen

CANONICAL_HEADERS = {
    "user-agent": "User-Agent",
    "accept": "Accept",
    "cookie": "Cookie",
    "host": "Host",
}


def _session(scope_name: str | None, lab: bool, args: argparse.Namespace) -> Session:
    config = load_config()
    budget = Budget(
        max_requests=getattr(args, "max_requests", None) or config.max_requests,
        max_per_host=getattr(args, "max_per_host", None) or config.max_per_host,
        delay=config.delay if getattr(args, "delay", None) is None else args.delay,
    )
    return Session(
        budget=budget,
        scope=get_scope(scope_name) if scope_name else None,
        lab=lab,
        timeout=config.timeout,
        max_bytes=config.max_bytes,
        headers=parse_headers(getattr(args, "header", None), getattr(args, "cookie", ""), getattr(args, "ua", "")),
        allow_redirect=bool(getattr(args, "allow_redirect", False)),
    )


def parse_headers(pairs: list[str] | None, cookie: str = "", user_agent: str = "") -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in pairs or []:
        if ":" not in raw:
            raise UsageError("header must look like 'Name: value': " + raw)
        key, _, value = raw.partition(":")
        key = key.strip()
        headers[CANONICAL_HEADERS.get(key.lower(), key)] = value.strip()
    if cookie:
        headers["Cookie"] = cookie.strip()
    if user_agent:
        headers["User-Agent"] = user_agent.strip()
    return headers


def _owned(args: argparse.Namespace) -> None:
    if not getattr(args, "i_own_this", False):
        raise UsageError("explicit --i-own-this confirmation is required")


def _resume_seen(args: argparse.Namespace) -> set[str]:
    if getattr(args, "no_resume", False) or not args.scope:
        return set()
    return load_seen(args.scope)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeforge", description="Scope-safe recon, proof, and triage.")
    parser.add_argument("--version", action="version", version=f"scopeforge {__version__}")
    parser.add_argument("--skip-preflight", action="store_true", help="skip tool checks and session banner")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("interactive", help="numbered console")

    sc = sub.add_parser("scope", help="manage written scopes")
    sc_sub = sc.add_subparsers(dest="scope_command", required=True)
    add = sc_sub.add_parser("add")
    add.add_argument("name")
    add.add_argument("--domain", action="append", required=True)
    add.add_argument("--exclude", action="append", default=[])
    add.add_argument("--source", default="")
    sc_sub.add_parser("list")
    show = sc_sub.add_parser("show")
    show.add_argument("name")
    rm = sc_sub.add_parser("remove")
    rm.add_argument("name")

    pl = sub.add_parser("plan", help="generate scoped dork queries")
    pl.add_argument("scope")
    pl.add_argument("--category", choices=CATEGORIES, default="recon")
    pl.add_argument("--limit", type=int, default=50)
    pl.add_argument("--format", choices=("text", "json", "md"), default="text")

    sr = sub.add_parser("search", help="passive dork search; exports URLs for manual review")
    sr.add_argument("scope")
    sr.add_argument("--category", choices=CATEGORIES, default="exposure")
    sr.add_argument("--provider", choices=("auto", "ddg", "google_cse", "brave", "file"), default="auto")
    sr.add_argument("--limit", type=int, default=10)
    sr.add_argument("--max-queries", type=int, default=0)
    sr.add_argument("--input", help="file of URLs for the file provider")
    sr.add_argument("--format", choices=("text", "json"), default="text")
    sr.add_argument("--output")

    ld = sub.add_parser("lead", help="manage the lead ledger")
    ld_sub = ld.add_subparsers(dest="lead_command", required=True)
    ld_add = ld_sub.add_parser("add")
    ld_add.add_argument("--scope", required=True)
    ld_add.add_argument("--candidate", required=True)
    ld_add.add_argument("--source", default="")
    ld_add.add_argument("--category", default="recon")
    ld_add.add_argument("--note", default="")
    ld_list = ld_sub.add_parser("list")
    ld_list.add_argument("--scope")
    ld_list.add_argument("--format", choices=("text", "json"), default="text")

    ex = sub.add_parser("exposure", help="manual exposure worksheet")
    ex.add_argument("domain")
    ex.add_argument("--scope", required=True)
    ex.add_argument("--source", default="")
    ex.add_argument("--output")

    sca = sub.add_parser("scan", help="probe exposure paths with structural proof")
    sca.add_argument("host")
    sca.add_argument("--scope")
    sca.add_argument("--lab", action="store_true")
    sca.add_argument("--tier", choices=("high", "medium", "low", "all"), default="high")
    sca.add_argument("--delay", type=float)
    sca.add_argument("--max-requests", type=int)
    sca.add_argument("--max-per-host", type=int)
    sca.add_argument("--include-maybe", action="store_true")
    sca.add_argument("--allow-redirect", action="store_true", help="follow at most one in-scope redirect")
    sca.add_argument("--header", action="append", default=[], help="extra request header 'Name: value'")
    sca.add_argument("--cookie", default="", help="Cookie header value")
    sca.add_argument("--ua", default="", help="override User-Agent header")
    sca.add_argument("--no-resume", action="store_true")
    sca.add_argument("--i-own-this", action="store_true")

    pb = sub.add_parser("probe", help="send benign markers to owned/lab/in-scope URL params")
    pb.add_argument("urls", nargs="+")
    pb.add_argument("--scope")
    pb.add_argument("--lab", action="store_true")
    pb.add_argument("--marker", default="")
    pb.add_argument("--max-params", type=int, default=0)
    pb.add_argument("--delay", type=float)
    pb.add_argument("--max-requests", type=int)
    pb.add_argument("--max-per-host", type=int)
    pb.add_argument("--allow-redirect", action="store_true", help="follow at most one in-scope redirect")
    pb.add_argument("--header", action="append", default=[], help="extra request header 'Name: value'")
    pb.add_argument("--cookie", default="", help="Cookie header value")
    pb.add_argument("--ua", default="", help="override User-Agent header")
    pb.add_argument("--no-resume", action="store_true")
    pb.add_argument("--i-own-this", action="store_true")

    ij = sub.add_parser("inject", help="authorized payload ladder with paired baselines")
    ij.add_argument("urls", nargs="+")
    ij.add_argument("--scope")
    ij.add_argument("--lab", action="store_true")
    ij.add_argument("--classes", default="", help="comma-separated payload classes")
    ij.add_argument("--max-classes", type=int, default=2)
    ij.add_argument("--delay", type=float)
    ij.add_argument("--max-requests", type=int)
    ij.add_argument("--max-per-host", type=int)
    ij.add_argument("--allow-redirect", action="store_true")
    ij.add_argument("--header", action="append", default=[], help="extra request header 'Name: value'")
    ij.add_argument("--cookie", default="", help="Cookie header value")
    ij.add_argument("--ua", default="", help="override User-Agent header")
    ij.add_argument("--i-own-this", action="store_true")

    fd = sub.add_parser("findings", help="inspect findings")
    fd_sub = fd.add_subparsers(dest="findings_command", required=True)
    fdl = fd_sub.add_parser("list")
    fdl.add_argument("--scope")
    fdl.add_argument("--status", choices=findings.STATUSES)
    fdl.add_argument("--min-confidence", choices=findings.CONFIDENCE, default="low")
    fdl.add_argument("--devil", action="store_true", help="sort by signal length")
    fdl.add_argument("--format", choices=("text", "json"), default="text")

    vf = sub.add_parser("verify", help="confirm or reject a finding")
    vf.add_argument("finding_id")
    vf.add_argument("--status", choices=("confirmed", "false-positive", "skipped"))
    vf.add_argument("--note", default="")

    an = sub.add_parser("analyze", help="score recorded evidence")
    an.add_argument("path")
    an.add_argument("--format", choices=("text", "json", "md"), default="text")
    an.add_argument("--output")

    rp = sub.add_parser("report", help="render markdown report")
    rp.add_argument("analysis")
    rp.add_argument("--scope", required=True)
    rp.add_argument("--scope-source", default="")
    rp.add_argument("--output")

    cf = sub.add_parser("config", help="read or set defaults")
    cf.add_argument("key", nargs="?")
    cf.add_argument("value", nargs="?")

    sub.add_parser("evidence-dir", help="print evidence folder path")

    st = sub.add_parser("state", help="manage resume state")
    st_sub = st.add_subparsers(dest="state_command", required=True)
    stc = st_sub.add_parser("clear")
    stc.add_argument("scope")

    lb = sub.add_parser("lab", help="guided lab checks or loopback lab server")
    lb.add_argument("scenario", nargs="?", choices=("localhost", "dvwa", "juice-shop", "ctf", "serve"))
    lb.add_argument("--serve", action="store_true", help="start the local lab server")
    lb.add_argument("--port", type=int, default=8099, help="lab server port")
    lb.add_argument("--bind", default="127.0.0.1", help="loopback bind address")
    return parser


def _write(content: str, output: str | None) -> str:
    if not output:
        return content
    path = Path(output)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return "written: " + str(path)


def _records(path: Path) -> list[dict[str, Any]]:
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


def run_command(args: argparse.Namespace) -> str:
    if args.command == "scope":
        if args.scope_command == "add":
            item = add_scope(args.name, args.domain, args.exclude, args.source)
            return f"scope saved: {item.name} | {', '.join(item.domains)}"
        if args.scope_command == "list":
            items = list_scopes()
            lines = [f"{i.name}: {', '.join(i.domains)} | source={i.source or '-'}" for i in items]
            return "\n".join(lines) or "No scopes saved."
        if args.scope_command == "show":
            return json.dumps(get_scope(args.name).to_dict(), indent=2)
        remove_scope(args.name)
        return f"scope removed: {args.name}"

    if args.command == "plan":
        return render_plan(build_plan(get_scope(args.scope), args.category, args.limit), args.format)

    if args.command == "search":
        scope = get_scope(args.scope)
        config = load_config()
        limit = args.max_queries or config.max_queries
        if args.provider == "file":
            urls = search.search("", "file", args.limit, args.input)
            records: list[dict[str, Any]] = []
        else:
            records = build_plan(scope, args.category, limit)
            urls = []
            failures = 0
            for index, record in enumerate(records):
                if index and config.delay:
                    time.sleep(config.delay)
                try:
                    found = search.search(record["query"], args.provider, args.limit)
                except ScopeForgeError as exc:
                    failures += 1
                    print(f"warn: {record['query']} -> {exc}", file=sys.stderr)
                    continue
                for url in found:
                    if url not in urls:
                        urls.append(url)
            if failures == len(records):
                raise SearchError(f"every query failed ({failures})")
        if args.format == "json":
            return json.dumps({"queries": [r["query"] for r in records], "urls": urls}, indent=2)
        return _write("\n".join(urls) or "no results", args.output)

    if args.command == "lead":
        if args.lead_command == "add":
            lead = add_lead(args.scope, args.source, args.candidate, args.category, args.note)
            return f"lead added: {lead.id} | {lead.scope} | {lead.candidate}"
        return render_leads(list_leads(args.scope), args.format)

    if args.command == "exposure":
        scope = get_scope(args.scope)
        return _write(build_worksheet(scope.name, args.domain, args.source), args.output)

    if args.command == "scan":
        _owned(args)
        session = _session(args.scope, args.lab, args)
        result = run_scan(
            session,
            args.scope or "lab",
            args.host,
            args.tier,
            args.include_maybe,
            True,
            resume=not args.no_resume,
            seen=_resume_seen(args),
        )
        if not result.findings:
            raise NothingFound("scan produced no findings")
        return render_scan(result)

    if args.command == "probe":
        _owned(args)
        session = _session(args.scope, args.lab, args)
        max_params = args.max_params or load_config().max_params
        probe_result = probe.run(
            session,
            args.scope or "lab",
            args.urls,
            marker=args.marker or None,
            max_params=max_params,
            resume=not args.no_resume,
            seen=_resume_seen(args),
        )
        if not probe_result.findings:
            raise NothingFound("probe produced no findings")
        return probe.render(probe_result)

    if args.command == "inject":
        _owned(args)
        session = _session(args.scope, args.lab, args)
        requested = [item.strip() for item in args.classes.split(",") if item.strip()] or None
        inject_result = inject.run(session, args.scope or "lab", args.urls, requested, args.max_classes)
        if not inject_result.findings:
            raise NothingFound("inject produced no findings")
        return inject.render(inject_result)

    if args.command == "findings":
        return findings.render(
            findings.list_all(args.scope, args.status, args.min_confidence, args.devil), args.format
        )

    if args.command == "verify":
        if args.status:
            return verify.decide(args.finding_id, args.status, args.note)
        if not sys.stdin.isatty():
            verify.get(args.finding_id)
            return verify.decide(args.finding_id, "skip")
        verify.interactive(args.finding_id)
        return ""

    if args.command == "analyze":
        target = Path(args.path)
        paths = sorted(target.glob("*.json")) if target.is_dir() else [target]
        evidence_records: list[dict[str, Any]] = []
        for path in paths:
            evidence_records.extend(_records(path))
        return _write(render_analysis(analyze_records(evidence_records), args.format), args.output)

    if args.command == "report":
        return _write(render_report(args.scope, _records(Path(args.analysis)), args.scope_source), args.output)

    if args.command == "config":
        if not args.key:
            return json.dumps(load_config().to_dict(), indent=2)
        if not args.value:
            return json.dumps({args.key: getattr(load_config(), args.key)}, indent=2)
        return json.dumps(set_value(args.key, args.value).to_dict(), indent=2)

    if args.command == "evidence-dir":
        return str(evidence_folder())

    if args.command == "state":
        clear_state(args.scope)
        return f"state cleared: {args.scope}"

    if args.command == "lab":
        if args.serve or args.scenario == "serve":
            from .lab_serve import serve

            serve(args.port, args.bind)
            return ""
        if not args.scenario:
            raise UsageError("choose a lab scenario or use 'lab serve'")
        from .lab import render_lab

        return render_lab(args.scenario)

    raise UsageError("unknown command: " + str(args.command))


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(argv) if argv is not None else list(sys.argv[1:])
    from_cli = argv is None
    informational = any(flag in raw for flag in ("--version", "-h", "--help"))
    with ExitStack() as stack:
        log = None
        if from_cli and not informational and "--skip-preflight" not in raw:
            code = check_preflight()
            if code:
                return code
            ui.banner(__version__)
            ui.trap_sigint()
            scope = raw[0]
            if "--scope" in raw and len(raw) > raw.index("--scope") + 1:
                scope = raw[raw.index("--scope") + 1]
            log = stack.enter_context(ui.session_log(scope))
        if not raw or raw[0] == "interactive":
            from .tui import run_interactive

            return run_interactive(log=log)
        args = build_parser().parse_args(raw)
        try:
            output = run_command(args)
        except ScopeForgeError as exc:
            ui.error(f"error: {exc}", log)
            return exc.exit_code
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            ui.error(f"error: {exc}", log)
            return 2
        except KeyboardInterrupt:
            ui.error("interrupted", log)
            return 130
        if output:
            ui.tee(output, log)
        return 0
