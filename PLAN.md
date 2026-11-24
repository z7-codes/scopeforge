# DorkLens Plan

## Product idea

DorkLens replaces flag-heavy tooling with one command, sensible defaults, and a demo that proves the engine locally in ten seconds.

Name: DorkLens. Lens means focus; it finds dorks and public exposure signals.

Tagline: `point it, and it sees`.

Catalog: 380 advanced dorks across 33 categories, with priority-ranked defaults of 20/40/80 queries for quick/full/deep.

## Data flow

```text
passive -> dork -> crawl -> dirs -> params -> payload -> report
```

Each stage writes to SQLite. The next stage reads the same store. Results are deduplicated by URL and finding tuple, so resume is free and a stage crash does not destroy the run.

## Detection model

Baseline twice, then probe.

Signals:

- regex
- length delta
- status change
- reflection
- similarity drop
- location match

Confidence equals the number of matched signals. On unstable pages, the threshold increases by one. Soft-404 calibration runs per host before directory checks.

## Safety

- Written scope checked on every target URL.
- Per-host token bucket.
- GET by default; POST/JSON only with `--post` or `lab`.
- Redirects are not followed.
- `Ctrl-C` leaves SQLite state safe.

## Ease

- `quick`, `full`, and `deep` profiles.
- Interactive wizard.
- `doctor` for environment checks.
- `demo` for offline end-to-end proof.
- Per-finding `next step` advice.
- Terminal-only findings with severity, evidence, and next steps.

## Layout

```text
dorklens/
  cli.py  ui.py  config.py  scope.py  http.py  storage.py  report.py
  demo.py  doctor.py  selftest.py
  modules/{passive,dork,crawl,dirs,params,payloads}.py
  data/{dorks,payloads,profiles}.yaml  wordlist.txt  lab-wordlist.txt  demo/*
scripts/lab_assert.py
tests/{test_core,test_demo,test_dorks,test_crawl,test_lab}.py
```

## Deferred

Added only after the demo pipeline is trusted:

- `--auth` cookie/header
- Nuclei template import
- multi-domain batch
