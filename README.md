# ScopeForge

[![CI](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml/badge.svg)](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml)

ScopeForge is a cross-platform command-line tool for scope-safe recon planning, evidence triage, and report drafting. It is the companion tool to [Advanced Google Dorks](https://github.com/z7-codes/advanced-google-dorks).

It does **not** scan arbitrary domains, fire payloads, extract data, or declare vulnerabilities automatically.

## What it does

- Validates written scopes with wildcard and exclusion support.
- Generates scoped discovery queries from a category template set.
- Stores leads in a local ledger.
- Analyzes evidence that you record from authorized work, labs, or CTFs.
- Redacts URLs, parameters, emails, tokens, and long hex values in reports.
- Renders a Markdown evidence report draft.
- Provides guided lab scenarios for localhost, DVWA, Juice Shop, and CTF targets.
- Generates a manual public-exposure worksheet from scoped dork queries.
- Probes explicitly owned, lab, or in-scope URLs with benign markers only.
- Probes known exposure paths with structural validators and a soft-404 baseline on owned/lab/in-scope hosts.
- Stores findings locally and supports confirm, false-positive, and skip decisions with evidence export.

## Devil Mode

Devil Mode is a scoring posture, not an attack mode.

It means deeper signal correlation, stricter dedupe prompts, lower tolerance for weak evidence, and sharper report structure. It never enables credential attacks, exploit chains, mass requests, WAF bypass, denial of service, or testing third-party websites.

## Install

```bash
python -m pip install git+https://github.com/z7-codes/scopeforge.git
scopeforge --version
```

Local development:

```bash
python -m pip install -e .
```

Works on Windows, Linux, Arch, and macOS with Python 3.10 or newer. No API keys, no backend, no cloud dependency.

## Interactive console

Run the tool with no arguments for an airgeddon-style numbered menu:

```bash
scopeforge
scopeforge interactive
```

Menu sections:

```text
[01] Scope management
[02] Dork plan generator
[03] Lead ledger
[04] Evidence analyzer
[05] Lab mode
[06] Report generator
  [07] Safety rules
  [08] Toggle Devil Mode
  [09] Public exposure worksheet
  [10] Benign URL probe
  [00] Exit

```

Active scope and Devil Mode are saved locally. Devil Mode sorts analysis results by signal score and keeps the same no-exploitation safety boundary.

## Public exposure worksheet

Generate scoped searches for manual browser checks. ScopeForge does not query search engines or targets.

```bash
scopeforge exposure example.com --scope main --source policy --output exposure.md
```

The worksheet includes every dork category, scope source, empty evidence columns, and decision rules. A public result is a lead, not a vulnerability declaration.

## Benign URL probe

For URLs you own, labs, or CTF targets only. This sends a benign marker such as `Z7CHECK-SF`, never an exploit payload.

```bash
scopeforge probe "http://localhost:8080/search?q=test" --i-own-this
scopeforge probe "https://app.example.com/search?q=test" --scope main --i-own-this --format md --output probe.md
```

Safety gates:

- `--i-own-this` is mandatory.
- Non-lab hosts require a saved scope.
- Redirects are blocked.
- Requests are rate limited.
- Output is redacted and always says `needs-validation`; it never declares a vulnerability.

## Structural exposure scan

For hosts you own, labs, or written in-scope assets only. The scanner sends ordinary GET requests to a small catalog of known paths, uses response validators plus a soft-404 baseline to reduce false positives, and never fires exploit payloads.

```bash
scopeforge scope add lab --domain localhost --source "juice-shop local"
scopeforge scan http://localhost:3000 --scope lab --tier all --i-own-this
scopeforge findings list --scope lab
scopeforge verify <id> --status confirmed --note "verified in browser"
scopeforge analyze ~/.scopeforge/evidence
```

Useful scan flags:

- `--tier high|medium|low|all` filters the path catalog by severity.
- `--delay` sets the pause between requests; default is `0.4` seconds.
- `--max-requests` caps the run; default is `120`.
- `--include-maybe` records protected or ambiguous responses as low-confidence findings.
- `--i-own-this` is mandatory.

Findings stay `new` until you run `verify`. Only `confirmed` findings are written to the evidence directory. Every record still needs manual validation before a report.

## Quick start

```bash
scopeforge scope add main --domain example.com --domain "*.example.org" --exclude staging.example.org --source "program-policy-2026-11-22"

scopeforge plan main --category recon --limit 20
scopeforge plan main --category xss --format md > xss-plan.md

scopeforge lead add --scope main --candidate https://example.com/search?q=test --source manual-browsing --category xss

scopeforge lab localhost
```

## Evidence analysis

Create `evidence.json`:

```json
[
  {
    "id": "EV-001",
    "scope": "main",
    "category": "xss",
    "url": "https://example.com/search?q=test",
    "parameter": "q",
    "context": "html-attribute",
    "reflection": true,
    "authorized": true,
    "excerpt": "value=Z7CHECK123 from authorized lab capture"
  },
  {
    "id": "EV-002",
    "scope": "main",
    "category": "sqli",
    "url": "https://example.com/product?id=1",
    "parameter": "id",
    "error_family": "mysql_error",
    "authorized": true,
    "excerpt": "database-family error text omitted"
  }
]
```

Run:

```bash
scopeforge analyze evidence.json
scopeforge analyze evidence.json --format json --output analysis.json
scopeforge report analysis.json --scope main --output report.md
```

Status values:

- `blocked`: authorization was not recorded.
- `needs-validation`: evidence is incomplete.
- `likely`: a meaningful signal was recorded.
- `evidence-confirmed`: the operator supplied manual confirmation and an evidence summary.

ScopeForge never replaces manual validation or program triage.

## Data location

Local data is stored under `~/.scopeforge` by default.

Set `SCOPEFORGE_HOME` to use another directory.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- Local browser UI with FastAPI and static HTML.
- PyInstaller binaries for Windows and Linux.
- Arch `PKGBUILD` and AUR packaging.
- GitHub Actions test matrix — active.
- Import adapters for Burp, ZAP, and Nuclei evidence exports.
- Dedupe and Known Issues note importer.

## Related

- [Advanced Google Dorks](https://github.com/z7-codes/advanced-google-dorks) — scope-safe dork library, operator-free discovery guide, and vulnerability fundamentals.
