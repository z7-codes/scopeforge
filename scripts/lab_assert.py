from __future__ import annotations

import json
import sys
from pathlib import Path

CORE = {"sqli_error", "sqli_bool", "xss_reflect", "open_redirect"}


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dorklens-lab-ci")
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    categories = sorted({str(item["category"]) for item in findings})
    matched = sorted(CORE & set(categories))
    print(f"findings {len(findings)}")
    print("categories " + (", ".join(categories) or "none"))
    print("core " + (", ".join(matched) or "none"))
    return 0 if len(findings) >= 4 and len(matched) >= 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
