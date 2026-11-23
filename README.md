# DorkLens

[![CI](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml/badge.svg)](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml)

> DorkLens is the rebuilt, focused CLI for advanced dork planning and passive public exposure discovery.
> It replaces the older menu-heavy ScopeForge experience.

DorkLens takes one input — a domain such as `example.com` — and generates a professional, category-based advanced dork plan for that target. It can then run those dorks through passive search providers, collect public results, and produce a clean Markdown report.

DorkLens is passive. It does not send requests to the target domain, does not fire exploit payloads, does not scrape `google.com`, and does not declare that a target is vulnerable. It reports public exposure signals that a human must verify and triage.

## Install

```bash
python -m pip install git+https://github.com/z7-codes/scopeforge.git
dorklens --version
```

Local development:

```bash
python -m pip install -e .
python -m dorklens example.com
```

If the `dorklens` executable is not on your PATH, use `python -m dorklens` instead.

Works on Windows, Linux, and macOS with Python 3.10 or newer.

## Quick start

Generate every dork for a domain:

```bash
dorklens example.com
```

Generate a specific category:

```bash
dorklens dorks example.com --category directory-listing
```

List all categories:

```bash
dorklens categories
```

Export a dork plan:

```bash
dorklens dorks example.com --format md --output dork-plan.md
dorklens dorks example.com --format json --output dork-plan.json
```

Run passive searches and save results:

```bash
dorklens search example.com --output results.json --format json
dorklens report results.json --output exposure-report.md
```

Import URLs you collected manually:

```bash
dorklens search example.com --provider file --input urls.txt --format md
```

## Search providers

- `auto`: tries configured Google CSE, then Brave, then DuckDuckGo HTML.
- `google_cse`: uses the official Custom Search API. Set `DORKLENS_CSE_KEY` and `DORKLENS_CSE_CX`.
- `brave`: uses the Brave Search API. Set `DORKLENS_BRAVE_KEY`.
- `ddg`: passive DuckDuckGo HTML results. No key required.
- `file`: imports URLs from a local text file. No network request.

Provider names are intentionally hidden from the report unless a provider fails. DorkLens never scrapes `google.com` directly.

## Output safety language

DorkLens labels results as signals, for example:

- `High-priority exposure signal`
- `Directory exposure signal`
- `Administrative surface signal`
- `Development surface signal`
- `Parameter surface signal`
- `Public information signal`

Every result includes `Manual verification required.` DorkLens does not output automatic vulnerability verdicts.

## Example dork categories

- `directory-listing`
- `sensitive-files`
- `backups-archives`
- `config-and-secrets`
- `source-control`
- `logs-and-debug`
- `admin-panels`
- `inurl-parameters`
- `apis-and-docs`
- `cloud-storage`
- `subdomains-and-assets`
- `public-mentions`

Run `dorklens categories` for the full list.

## Example output

```text
site:example.com intitle:"Index of /admin"
site:example.com intitle:"Index of /old"
site:example.com intitle:"Index of /test"
site:example.com intitle:"Index of /dev"
site:example.com intitle:"Index of /backup"
```

## Scope of behavior

DorkLens performs passive search-provider requests only. It does not request the target domain, crawl the target domain, scan ports, submit payloads, or upload data. Reports and result files stay local.

Use it only for domains and programs you are permitted to assess. Follow the target's disclosure policy and verify every signal manually before reporting anything.
