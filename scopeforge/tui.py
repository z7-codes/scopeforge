from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .analyzer import analyze_records, render_analysis
from .dorks import CATEGORIES, build_plan, render_plan
from .exposure import build_worksheet
from .lab import LABS, render_lab
from .ledger import add_lead, list_leads, render_leads
from .probe import probe_urls, render_probe
from .report import render_report
from .scope import add_scope, check_scope, get_scope, list_scopes
from .storage import read_json, write_json

STATE_FILE = "tui-state.json"

SAFETY = [
    "Own assets, written authorization, labs, or CTFs only.",
    "Discovery is not authorization.",
    "Third-party websites are intel only, never testing targets.",
    "No payload firing, exploit chains, credential attacks, or data extraction.",
    "No real user accounts or real user data.",
    "If sensitive data is found: stop, do not save it, report minimal redacted proof.",
]


@dataclass
class State:
    scope: str = ""
    devil: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "devil": self.devil}


def load_state() -> State:
    data = read_json(STATE_FILE, {})
    if not isinstance(data, dict):
        return State()
    return State(str(data.get("scope", "")), bool(data.get("devil", False)))


def save_state(state: State) -> None:
    write_json(STATE_FILE, state.to_dict())


def clear_screen() -> None:
    if os.environ.get("SCOPEFORGE_NO_CLEAR") == "1":
        return
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    if os.environ.get("SCOPEFORGE_NO_PAUSE") == "1":
        return
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def ask_int(label: str, default: int, minimum: int, maximum: int) -> int:
    raw = ask(label, str(default))
    try:
        value = int(raw)
    except ValueError:
        print("error: enter a number")
        return default
    if value < minimum or value > maximum:
        print(f"error: value must be between {minimum} and {maximum}")
        return default
    return value


def header(state: State) -> str:
    mode = "DEVIL" if state.devil else "SAFE"
    scope = state.scope or "none"
    lines = [
        "=" * 68,
        f"  SCOPEFORGE v{__version__} - SCOPE-SAFE RECON WORKFLOW",
        "=" * 68,
        f"  Active scope : {scope}",
        f"  Mode         : {mode}",
        "=" * 68,
        "",
        "  [01] Scope management",
        "  [02] Dork plan generator",
        "  [03] Lead ledger",
        "  [04] Evidence analyzer",
        "  [05] Lab mode",
        "  [06] Report generator",
        "  [07] Safety rules",
        "  [08] Toggle Devil Mode",
        "  [09] Public exposure worksheet",
        "  [10] Benign URL probe",
        "  [00] Exit",
        "",
        "=" * 68,
    ]
    return "\n".join(lines)


def load_evidence(path_text: str) -> list[dict[str, Any]]:
    target = Path(path_text).expanduser()
    if not target.exists():
        raise ValueError("path not found: " + str(target))
    paths = sorted(target.glob("*.json")) if target.is_dir() else [target]
    if not paths:
        raise ValueError("no JSON files found in " + str(target))
    records: list[dict[str, Any]] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            records.extend(item for item in data if isinstance(item, dict))
        elif isinstance(data, dict):
            for key in ("analyses", "records", "evidence"):
                value = data.get(key)
                if isinstance(value, list):
                    records.extend(item for item in value if isinstance(item, dict))
                    break
            else:
                records.append(data)
    return records


def write_output(content: str, target: str) -> None:
    if not target:
        print(content)
        return
    path = Path(target).expanduser()
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print("saved: " + str(path))


def select_menu(title: str, options: list[str]) -> int:
    print("")
    print(title)
    print("-" * len(title))
    for index, option in enumerate(options, start=1):
        print(f"  [{index:02d}] {option}")
    print("  [00] Back")
    return ask_int("Select", 0, 0, len(options))


def menu_scope(state: State) -> None:
    while True:
        choice = select_menu(
            "SCOPE MANAGEMENT",
            ["List scopes", "Add scope", "Set active scope", "Check candidate against active scope"],
        )
        if choice == 0:
            return
        try:
            if choice == 1:
                scopes = list_scopes()
                if not scopes:
                    print("No scopes saved.")
                for scope in scopes:
                    print(f"{scope.name}: domains={', '.join(scope.domains)} exclusions={', '.join(scope.exclusions) or '-'}")
            elif choice == 2:
                name = ask("Scope name")
                domains_text = ask("Domains, comma separated")
                excludes_text = ask("Exclusions, comma separated")
                source = ask("Scope source", "manual-entry")
                domains = [item.strip() for item in domains_text.split(",") if item.strip()]
                excludes = [item.strip() for item in excludes_text.split(",") if item.strip()]
                scope = add_scope(name, domains, excludes, source)
                state.scope = scope.name
                save_state(state)
                print("scope added and activated: " + scope.name)
            elif choice == 3:
                name = ask("Scope name", state.scope)
                get_scope(name)
                state.scope = name
                save_state(state)
                print("active scope: " + name)
            elif choice == 4:
                scope = get_scope(state.scope)
                candidate = ask("Candidate hostname or URL")
                decision = check_scope(scope, candidate)
                print(f"allowed={decision.allowed} reason={decision.reason}")
        except (ValueError, OSError) as exc:
            print("error: " + str(exc))
        pause()


def menu_plan(state: State) -> None:
    try:
        scope = get_scope(state.scope)
    except ValueError as exc:
        print("error: " + str(exc))
        pause()
        return
    print("")
    print("DORK PLAN GENERATOR")
    print("-" * 18)
    print("Categories: " + ", ".join(CATEGORIES))
    category = ask("Category", "recon")
    limit = ask_int("Limit", 20, 1, 500)
    fmt = ask("Format (text, json, md)", "text")
    output = ask("Output file, blank to print", "")
    try:
        records = build_plan(scope, category, limit)
        write_output(render_plan(records, fmt), output)
    except (ValueError, OSError) as exc:
        print("error: " + str(exc))
    pause()


def menu_ledger(state: State) -> None:
    while True:
        choice = select_menu("LEAD LEDGER", ["Add lead", "List leads"])
        if choice == 0:
            return
        try:
            if choice == 1:
                candidate = ask("Candidate URL or hostname")
                source = ask("Source", "manual")
                category = ask("Category", "recon")
                note = ask("Note")
                lead = add_lead(state.scope, source, candidate, category, note)
                print("lead added: " + lead.id)
            elif choice == 2:
                print(render_leads(list_leads(state.scope or None)))
        except (ValueError, OSError) as exc:
            print("error: " + str(exc))
        pause()


def menu_analyze(state: State) -> None:
    print("")
    print("EVIDENCE ANALYZER")
    print("-" * 17)
    path = ask("Evidence JSON file or directory")
    if not path:
        return
    fmt = ask("Format (text, json, md)", "text")
    output = ask("Output file, blank to print", "")
    try:
        results = analyze_records(load_evidence(path))
        if state.devil:
            results.sort(key=lambda item: item.get("score", 0), reverse=True)
        write_output(render_analysis(results, fmt), output)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc))
    pause()


def menu_lab(state: State) -> None:
    print("")
    print("LAB MODE")
    print("-" * 8)
    print("Scenarios: " + ", ".join(sorted(LABS)))
    scenario = ask("Scenario", "localhost")
    try:
        print(render_lab(scenario))
    except ValueError as exc:
        print("error: " + str(exc))
    pause()


def menu_report(state: State) -> None:
    print("")
    print("REPORT GENERATOR")
    print("-" * 17)
    path = ask("Analysis JSON file or directory")
    if not path:
        return
    scope_name = ask("Scope name", state.scope)
    output = ask("Output file", "report.md")
    try:
        analyses = load_evidence(path)
        write_output(render_report(scope_name, analyses), output)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc))
    pause()


def menu_safety(state: State) -> None:
    print("")
    print("SAFETY RULES")
    print("-" * 12)
    for index, rule in enumerate(SAFETY, start=1):
        print(f"  {index}. {rule}")
    print("")
    print("Devil Mode means deeper scoring and stricter triage, never exploitation.")
    pause()


def menu_exposure(state: State) -> None:
    print("")
    print("PUBLIC EXPOSURE WORKSHEET")
    print("-" * 25)
    print("Generates scoped searches for manual browser checks. No automatic querying.")
    scope_name = ask("Scope name", state.scope)
    domain = ask("Domain")
    source = ask("Scope source", "manual-entry")
    output = ask("Output file", "exposure.md")
    try:
        scope = get_scope(scope_name)
        decision = check_scope(scope, domain)
        if not decision.allowed:
            raise ValueError("domain blocked by scope: " + decision.reason)
        write_output(build_worksheet(scope.name, domain, source), output)
    except (ValueError, OSError) as exc:
        print("error: " + str(exc))
    pause()


def menu_probe(state: State) -> None:
    print("")
    print("BENIGN URL PROBE")
    print("-" * 16)
    print("Only owned assets, labs, or CTF targets. No exploit payloads are used.")
    urls_text = ask("URLs, comma separated")
    scope_name = ask("Scope name for non-lab hosts", state.scope)
    confirm = ask("Type OWN to confirm ownership or authorization")
    marker = ask("Benign marker", "Z7CHECK-SF")
    fmt = ask("Format (text, json, md)", "text")
    output = ask("Output file, blank to print", "")
    if confirm.strip().upper() != "OWN":
        print("blocked: ownership confirmation required")
        pause()
        return
    urls = [item.strip() for item in urls_text.split(",") if item.strip()]
    try:
        results = probe_urls(urls, marker, scope_name, True)
        write_output(render_probe(results, fmt), output)
    except (ValueError, OSError) as exc:
        print("error: " + str(exc))
    pause()


def run_interactive() -> int:
    state = load_state()
    handlers: dict[int, Callable[[State], None]] = {
        1: menu_scope,
        2: menu_plan,
        3: menu_ledger,
        4: menu_analyze,
        5: menu_lab,
        6: menu_report,
        7: menu_safety,
        9: menu_exposure,
        10: menu_probe,
    }
    while True:
        clear_screen()
        print(header(state))
        try:
            choice = ask("Select", "0")
        except (EOFError, KeyboardInterrupt):
            return 0
        if choice in ("0", "q", "Q", "exit", "Exit"):
            return 0
        try:
            number = int(choice)
        except ValueError:
            print("error: enter a menu number")
            pause()
            continue
        if number == 8:
            state.devil = not state.devil
            save_state(state)
            print("Devil Mode: " + ("ON" if state.devil else "OFF"))
            pause()
            continue
        handler = handlers.get(number)
        if handler:
            handler(state)
        else:
            print("error: unknown option")
            pause()
