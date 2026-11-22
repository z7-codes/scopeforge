# ScopeForge

[![CI](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml/badge.svg)](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml)

ScopeForge is a cross-platform command-line tool for scope-safe recon, manual proof collection, and report drafting. It is the companion tool to [Advanced Google Dorks](https://github.com/z7-codes/advanced-google-dorks).

It does **not** scan arbitrary domains, fire attack payloads, exploit findings, extract data, bypass WAFs, or declare vulnerabilities automatically. Every engine stops at a signal plus a copy-pasteable request; the operator confirms impact.

## v0.4 safety model

- One network choke point: `scopeforge.net.Session.get()` runs `guard()` -> `budget.spend()` -> `fetch()`.
- Written scope plus exclusions are mandatory for non-lab targets. Lab hosts need `--lab`.
- `--i-own-this` is mandatory for `scan` and `probe`.
- No redirects, 8-second timeout, 64 KB body cap, fixed `ScopeForge/0.4` user agent.
- Global and per-host budgets, typed exit codes, resume state, and redacted evidence.
- `search` is passive only. It never feeds `scan` or `probe` automatically.
- The payload catalog is marker-only. There is no SQLi/XSS/traversal/redirect/SSTI/CRLF ladder and no `inject` command.

## What it does

- Validates written scopes with wildcard and exclusion support.
- Generates scoped dork queries from JSON-backed templates.
- Runs passive dork searches through DDG, Google CSE, Brave, or a local URL file.
- Stores leads in a local ledger.
- Runs structural exposure checks with soft-404 suppression and validator-based proof.
- Sends benign markers to parameters on owned/lab/in-scope URLs and diffs normalized responses.
- Stores findings locally, supports confirm/false-positive/skip, and writes evidence JSON.
- Scores evidence that you record from authorized work, labs, or CTFs.
- Renders a Markdown evidence report draft.
- Provides guided lab scenarios for localhost, DVWA, Juice Shop, and CTF targets.

## Install

```bash
python -m pip install git+https://github.com/z7-codes/scopeforge.git
scopeforge --version
```

Local development:

```bash
python -m pip install -e .
```

Works on Windows, Linux, Arch, and macOS with Python 3.10 or newer. No backend, no cloud dependency. Optional search providers use `SCOPEFORGE_CSE_KEY`, `SCOPEFORGE_CSE_CX`, or `SCOPEFORGE_BRAVE_KEY`.

## Interactive console

```bash
scopeforge
scopeforge interactive
```

Current menu:

```text
[1] Scope management
[2] Dork plan
[3] Passive search
[4] Exposure worksheet
[5] Exposure scan
[6] Benign param probe
[7] Findings
[8] Verify finding
[9] Config
[0] Exit
```

## Quick start

```bash
scopeforge scope add main --domain example.com --domain "*.example.org" --exclude staging.example.org --source "program-policy-2026-11-22"
scopeforge plan main --category recon --limit 20 --format md > recon-plan.md
scopeforge search main --category exposure --provider ddg --limit 10 --output leads.txt
scopeforge exposure example.com --scope main --source "program-policy-2026-11-22" --output exposure.md
scopeforge scan https://example.com --scope main --tier high --i-own-this
scopeforge probe "https://example.com/search?q=test" --scope main --i-own-this
scopeforge findings list --scope main
scopeforge verify <finding-id>
scopeforge lab localhost
```

For local lab work:

```bash
scopeforge scan http://localhost:3000 --lab --i-own-this
scopeforge probe "http://localhost:3000/search?q=test" --lab --i-own-this
```

## Exposure scan

`scan` checks a fixed set of JSON-backed paths. A path is reported only when a structural validator matches, or when you explicitly ask for `--include-maybe`. Soft-404 bodies are baselined first. `.git/HEAD` can chain to other `.git` checks only after a non-absent result.

```bash
scopeforge scan https://example.com --scope main --tier high --i-own-this
scopeforge scan https://example.com --scope main --tier all --include-maybe --no-resume --i-own-this
```

## Benign probe

`probe` replaces one parameter at a time with a benign marker such as `z7sf7q`. It normalizes CSRF tokens, UUIDs, hex IDs, timestamps, asset versions, and base64 blobs before diffing. Reflection is a signal, not a vulnerability declaration.

```bash
scopeforge probe "http://localhost:8080/search?q=test" --lab --i-own-this
scopeforge probe "https://app.example.com/search?q=test" --scope main --marker z7sf7q --max-params 5 --i-own-this
```

## Findings and evidence

```bash
scopeforge findings list --scope main --min-confidence medium
scopeforge findings list --format json > findings.json
scopeforge verify <finding-id> --status confirmed --note "manually reviewed in scope"
scopeforge analyze ~/.scopeforge/evidence --format json --output analysis.json
scopeforge report analysis.json --scope main --scope-source "program-policy-2026-11-22" --output report.md
```

`verify` writes a redacted evidence record under `~/.scopeforge/evidence/<scope>.json`. Only operator-confirmed findings become evidence records.

The report is deterministic and draft-only. Confirmed records get a manual reproduction outline, impact template, and severity placeholder; unconfirmed records stay in a validation table. The draft always includes a pre-submit checklist for scope source, Known Issues, duplicates, redaction, impact, evidence path, and official channel.

Status values from the analyzer:

- `blocked`: authorization was not recorded.
- `needs-validation`: evidence is incomplete.
- `likely`: a meaningful signal was recorded.
- `evidence-confirmed`: manual confirmation and an evidence summary exist.

## Search providers

```bash
scopeforge search main --category exposure --provider ddg
scopeforge search main --category xss --provider google_cse
scopeforge search main --category recon --provider brave
scopeforge search main --provider file --input urls.txt
```

`file` skips blank lines and `#` comments. `auto` tries Google CSE, Brave, then DDG. Results are exported for manual review only.

## Config and state

```bash
scopeforge config
scopeforge config delay 0.4
scopeforge config max_requests 300
scopeforge evidence-dir
scopeforge state clear main
```

Defaults:

```json
{
  "delay": 0.4,
  "max_requests": 300,
  "max_per_host": 120,
  "max_urls": 25,
  "max_params": 5,
  "max_queries": 40,
  "timeout": 8.0,
  "max_bytes": 65536,
  "provider": "auto"
}
```

Exit codes:

```text
0  success
2  input/scope/usage error
3  budget exhausted
4  nothing found
130 interrupted
```

## Data location

Local data is stored under `~/.scopeforge` by default. Set `SCOPEFORGE_HOME` to use another directory. Bundled catalogs live in `scopeforge/data/`: `paths.json`, `dorks.json`, and marker-only `payloads.json`.

## Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q scopeforge tests
git diff --check
```

## Roadmap

- Local browser UI with FastAPI and static HTML.
- PyInstaller binaries for Windows and Linux.
- Arch `PKGBUILD` and AUR packaging.
- Import adapters for Burp, ZAP, and Nuclei evidence exports.
- Dedupe and Known Issues note importer.

## Related

- [Advanced Google Dorks](https://github.com/z7-codes/advanced-google-dorks) — scope-safe dork library, operator-free discovery guide, and vulnerability fundamentals.
