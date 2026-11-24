# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| 0.x | no |

## Reporting

Private advisory: https://github.com/z7-codes/scopeforge/security/advisories/new

Public, non-sensitive issues: normal GitHub issue. Expect a first reply within 7 days.

## Authorized use

DorkLens sends in-scope HTTP requests and probes URL parameters or JSON body fields with known test payloads. Use it only on systems you own or have explicit written permission to test.

## Built-in limits

- Written scope is required and checked before every target request.
- GET by default; POST/JSON only with `--post` or `lab`. Redirects are not followed.
- Per-host token bucket and global concurrency limit.
- Findings are signals, not automatic vulnerability declarations.
- Reports include manual verification steps and next-step advice.

## Known limits

- No authentication flows yet.
- POST/JSON injection is opt-in and expects an explicit `{{INJECT}}` body template.
- No multi-domain batch yet.
- Timing checks are opt-in through the `deep` profile.
