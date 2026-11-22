# Changelog

## 0.4.0 — 2026-11-22

- Added a structural exposure scan for explicitly owned, lab, or in-scope hosts.
- Added a path validator catalog with soft-404 baseline comparison to reduce false positives.
- Added a local findings store with `findings list` and a `verify` confirm/false-positive/skip loop.
- Added evidence export from confirmed findings into `~/.scopeforge/evidence/<scope>.json`.
- Added rate limiting, request caps, scope checks, and mandatory `--i-own-this` confirmation to the scan workflow.
- Added tests for validators, soft-404 handling, findings decisions, and CLI wiring.

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
