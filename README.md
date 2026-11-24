# DorkLens

[![CI](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml/badge.svg)](https://github.com/z7-codes/scopeforge/actions/workflows/ci.yml)

> point it, and it sees

DorkLens is a focused, one-command recon workflow. It finds public signals, builds dorks, crawls and walks likely paths, collects parameterized URLs, tests them with a conservative signal engine, and writes a report you can actually read.

The catalog contains 380 advanced dorks across 33 categories. Defaults stay fast: quick/full/deep run 20/40/80 high-priority queries first; the full catalog is always available in `dorklens/data/dorks.yaml`.

No config marathon. No flag memorization. A local demo proves the whole engine in seconds without internet.

## Install

```bash
bash install.sh
. .venv/bin/activate
```

Or manually:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows, use `python -m dorklens` if the `dorklens` script is not on PATH.

## 30-second trust check

```bash
dorklens selftest
dorklens demo
dorklens demo --out dorklens-demo --port 8765
```

The demo starts a local fixture server, runs the real pipeline, and prints the findings in the terminal. You should see `sqli_error`, `sqli_bool`, `open_redirect`, `lfi`, and directory hits. No internet is used.

## Lab truth check

The real benchmark is an intentionally vulnerable lab, not a random site with zero findings.

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python -m dorklens 127.0.0.1:3000 -p lab -s 127.0.0.1 -y -o dorklens-lab
python scripts/lab_assert.py dorklens-lab
```

The gate is an expected-vs-actual matrix, not a count: `q` must fire SQLi on `/rest/products/search`, `to` must fire open redirect on `/redirect`, clean endpoints must stay silent, and total findings stay under 40. CI runs the same scan on every commit and uploads `dorklens-lab-ci/findings.json`. The `lab` profile skips internet dorks and uses a small endpoint list for fast, authorized local testing.

## One command

```bash
dorklens target.com -p quick -y
```
That means: quick profile, no wizard prompt, print all findings in the terminal.

Interactive mode:

```bash
dorklens
```

Three questions: target, profile, go.

Config-driven run:

```bash
dorklens init target.com
dorklens -c dorklens.yaml -y
```

## Commands

| Command | What it does |
|---|---|
| `dorklens` | wizard: domain, profile, confirmation |
| `dorklens target.com -p quick` | passive + dork + crawl |
| `dorklens target.com -p full` | passive + dork + crawl + dirs + payload |
| `dorklens target.com -p deep` | full + timing checks |
| `dorklens target.com -p full --post` | include POST/JSON injection specs |
| `dorklens 127.0.0.1:3000 -p lab -s 127.0.0.1` | local vulnerable-lab benchmark |
| `dorklens -c dorklens.yaml` | run from config |
| `dorklens demo` | offline end-to-end proof |
| `dorklens doctor` | dependency and network check |
| `dorklens selftest` | 11 core checks |
| `dorklens report -o dorklens-out` | reprint findings from SQLite state |
| `dorklens --version` | version |

## Safety model

- Written scope is required. Every target request is checked against it.
- GET by default; POST/JSON runs only with `--post` or the `lab` profile. Redirects are never followed, so detection stays intact.
- Per-host token bucket plus global concurrency limit.
- Crawler is BFS, depth 2, 200-page cap, same scope, and only follows `a[href]`.
- Two baselines before a probe. Unstable pages raise the confidence threshold by one.
- Soft-404 calibration is done per host before directory checks.
- Signals are not verdicts. Reports include a concrete next step and manual verification language.
- `Ctrl-C` stops safely; SQLite state is already committed and a replay resumes without duplicate requests.

Only test systems you own or have explicit written permission to test.

## Pipeline

`passive -> dork -> crawl -> dirs -> params -> payload -> report`

Every stage writes into `dorklens-out/state.db`. The next stage reads from the same SQLite store. A stage crash does not erase earlier work, and re-running the same command skips already-known URLs and findings.

## Detection model

Confidence grows with the number of independent signals:

- regex evidence
- length delta
- status change
- payload reflection, raw or URL-encoded
- POST/JSON body injection when enabled
- similarity drop
- location match

Deep profile adds timing checks. Each finding carries `signals`, `evidence`, `confidence`, and `advice`.

## Config

See `dorklens.yaml.example`. CLI flags always override config values.

```yaml
domain: "{{d}}"
profile: full
max_dork_queries: 40
post: false
post_paths: []
scope:
  allow: ["{{d}}", "*.{{d}}"]
  deny: []
out_dir: dorklens-out
```

## Reports

Each run prints severity, evidence, payload, signals, and next steps directly to the terminal.

It also writes:

- `findings.json` - structured results for lab gates and CI
- `state.db` - resumable SQLite state

No HTML or Markdown report file is generated.

## Project layout

```text
dorklens/
  cli.py  ui.py  config.py  scope.py  http.py  storage.py  report.py
  demo.py  doctor.py  selftest.py
  modules/{dork,passive,dirs,params,payloads}.py
  data/{dorks,payloads,profiles}.yaml  wordlist.txt  demo/*
```

## Roadmap

Deliberately deferred until the demo pipeline is trusted:

- `--auth` cookie/header support
- Nuclei template import
- POST and JSON body support
- multi-domain batch runs

## Credits

Built by z7-codes.
