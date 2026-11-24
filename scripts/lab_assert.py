from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

CASES = [
    ("/rest/products/search", "q", {"sqli_error", "sqli_bool", "sqli_time"}),
    ("/redirect", "to", {"open_redirect"}),
]
CLEAN = ["/api/Products", "/rest/captcha"]
MAX_FINDINGS = 40


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dorklens-lab-ci")
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    seen: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in findings:
        path = urlsplit(str(item["url"])).path
        seen[(path, str(item["param"]))].add(str(item["category"]))

    failures: list[str] = []
    for path, param, expected in CASES:
        got = sorted(seen.get((path, param), set()))
        ok = bool(set(got) & expected)
        print(f"{'PASS' if ok else 'FAIL'} {path} ?{param} expected={sorted(expected)} got={got}")
        if not ok:
            failures.append(f"{path} ?{param}")

    for path in CLEAN:
        bad = [item for item in findings if urlsplit(str(item["url"])).path == path]
        ok = not bad
        print(f"{'PASS' if ok else 'FAIL'} clean {path} findings={len(bad)}")
        if not ok:
            failures.append(f"clean {path}")

    capped = len(findings) <= MAX_FINDINGS
    print(f"{'PASS' if capped else 'FAIL'} noise cap {len(findings)}/{MAX_FINDINGS}")
    if not capped:
        failures.append("noise cap")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
