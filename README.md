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
scopeforge analyze evidence.json --format json > analysis.json
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
