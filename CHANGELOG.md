# Changelog

## 0.4.0 — 2026-11-22

- Added a single network gate in `scopeforge.net.Session.get()` with scope guard, budget spend, redirect blocking, 8-second timeout, 64 KB body cap, and a fixed user agent.
- Added typed errors and exit codes: `0` success, `2` input/scope, `3` budget, `4` nothing found, `130` interrupted.
- Added JSON-backed data catalogs for paths, dorks, and marker-only payload classes. No attack-payload ladder or `inject` command was added.
- Added `errors.py`, `config.py`, `state.py`, `budget.py`, `net.py`, `data.py`, `validators.py`, `soft404.py`, `diff.py`, `search.py`, `evidence.py`, and `verify.py`.
- Rewrote `exposure.py` around structural validators, soft-404 baselines, tier selection, resume support, and findings.
- Rewrote `probe.py` as a benign multi-parameter marker probe with normalized response diffs.
- Rewrote `findings.py` and the CLI around `findings list` and `verify`; only operator-confirmed findings write evidence.
- Added passive `search` providers: DDG, Google CSE, Brave, and local URL file. Search never auto-chains into scan or probe.
- Added global/per-host budgets, per-scope resume state, package data for JSON catalogs, and ruff/mypy configuration.
- Rewrote the Markdown report generator to be deterministic, evidence-backed, and draft-only, with a manual reproduction outline, impact template, severity placeholder, and pre-submit checklist.
- Added `report --scope-source` and updated the README for the v0.4 command surface.
- Updated the interactive menu, README, and tests for the new safe architecture.

## 0.3.0 — 2026-11-22

- Added `exposure` command that generates a manual public-exposure worksheet from scoped dork queries.
- Added `probe` command that sends only benign markers to explicitly owned, lab, or in-scope URLs.
- Added ownership confirmation, scope checks, no-redirect requests, rate limiting, and redacted output to probe mode.
- Added interactive menu options `[09] Public exposure worksheet` and `[10] Benign URL probe`.
- Added tests for worksheet generation, marker URL building, local reflection probing, and safety gates.

## 0.2.0 — 2026-11-22

- Added an airgeddon-style interactive console launched with `scopeforge` or `scopeforge interactive`.
- Added numbered menus for scopes, dork plans, leads, evidence analysis, labs, reports, and safety rules.
- Added persistent active scope and Devil Mode state.
- Devil Mode now sorts analysis results by signal score.
- Kept all existing non-interactive CLI commands unchanged.

## 0.1.2 — 2026-11-22

- Added `analyze --output` so analysis JSON can be written without shell redirection or encoding issues.
- Updated README self-check commands.

## 0.1.1 — 2026-11-22

- Replaced non-ASCII CLI separators with ASCII for consistent Windows console output.
- Added a regression test that checks text-mode CLI output stays ASCII.

## 0.1.0 — 2026-11-22

- Added scope parser with wildcard and exclusion support.
- Added scoped dork planner with recon, exposure, SQLi surface, XSS surface, and CTF categories.
- Added local lead ledger.
- Added evidence analyzer with XSS, SQLi, exposure, recon, and manual confirmation signals.
- Added redaction for URLs, parameters, emails, tokens, and long hex values.
- Added Markdown report drafting.
- Added guided lab mode for localhost, DVWA, Juice Shop, and CTF targets.
- Added cross-platform CI workflow for Windows, Ubuntu, macOS, and Arch Linux.
