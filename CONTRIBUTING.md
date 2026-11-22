# Contributing

Contributions are welcome when they keep ScopeForge scoped, offline-first, and evidence-driven.

## Setup

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Rules

- No network calls by default.
- No payload firing, mass scanning, credential attacks, exploit chains, or data extraction.
- No storage of secrets or real user data.
- Every new signal must produce a status and a next validation step.
- Every behavior change needs a test.
- Keep wording precise: signals are not automatic vulnerability declarations.

## Commit style

```text
feat: add capability
fix: correct behavior
docs: improve documentation
test: add coverage
chore: maintenance
```
