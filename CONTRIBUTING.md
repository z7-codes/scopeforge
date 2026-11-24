# Contributing

Contributions are welcome when they keep DorkLens focused, safe, and easy.

## Setup

```bash
bash install.sh
. .venv/bin/activate
python -m dorklens selftest
python -m dorklens demo
python -m pytest -q
```

## Rules

- Scope is required. Never bypass it.
- Keep requests GET-only unless a new mode is explicitly designed and documented.
- Do not add credential attacks, exploit chains, or data extraction.
- Every finding must carry evidence and a manual next step.
- Every behavior change needs a test.
- Keep wording precise: signals are not vulnerability verdicts.

## Commit style

```text
feat: add capability
fix: correct behavior
docs: improve documentation
test: add coverage
chore: maintenance
```
