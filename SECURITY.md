# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | yes |
| 0.3.x and below | no |

## Reporting

Open a private advisory: https://github.com/z7-codes/scopeforge/security/advisories/new
Public, non-sensitive: normal issue. Expect a first reply in 7 days.

## Scope of the tool

ScopeForge sends HTTP requests. It never exploits. Findings are signals, not
confirmed vulnerabilities. Redirects are blocked by default; one hop is opt-in
with a scope re-check. Every request passes one choke point (`net.py:Session.get`)
which enforces written scope, `--i-own-this`, and the request budget.

## Known limits

GET only, 64 KB body cap, no auth flows beyond `--header`/`--cookie`,
sequential with delay, no proxy, no retries.
