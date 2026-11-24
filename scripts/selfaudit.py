#!/usr/bin/env python3
"""Read-only self audit. Kuch change nahi karta, network use nahi karta.

    python scripts/selfaudit.py .          # insaan ke liye
    python scripts/selfaudit.py . --json   # machine ke liye
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
AS_JSON = "--json" in sys.argv
results: list[dict] = []


def read(*parts: str) -> str:
    p = ROOT.joinpath(*parts)
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def check(pid: str, label: str, ok: bool, hint: str = "") -> None:
    results.append({"id": pid, "label": label, "ok": bool(ok), "hint": hint})


PAYLOADS = read("dorklens", "modules", "payloads.py")
HTTP = read("dorklens", "http.py")
DIRS = read("dorklens", "modules", "dirs.py")
CLI = read("dorklens", "cli.py")
REPORT = read("dorklens", "report.py")
STORE = read("dorklens", "storage.py")
PARAMS = read("dorklens", "modules", "params.py")
SPECS = read("dorklens", "data", "payloads.yaml")
CRAWL = read("dorklens", "modules", "crawl.py") or read("dorklens", "crawl.py")

# --- P0 -------------------------------------------------------------------
check("P0.1", "POST support (http client)",
      bool(re.search(r"\basync def post\b|\.post\(", HTTP)),
      "http.py mein post() method add karein")
check("P0.2", "POST/body support (engine)",
      bool(re.search(r"[\"']method[\"']|content_type|\bbody\b", PAYLOADS + SPECS)),
      "payloads.yaml mein method/body key aur engine mein support")
check("P0.3", "crawler maujood",
      bool(CRAWL) and bool(re.search(r"css\(\s*[\"']a|href", CRAWL)),
      "modules/crawl.py - BFS, depth 2, same scope")
check("P0.4", "crawler pipeline mein juda",
      "crawl" in CLI,
      "cli.py pipeline mein crawl stage, dork se PEHLE")

# --- P1 -------------------------------------------------------------------
check("P1.1", "redirect param vocab (to/ref)",
      bool(re.search(r"[\"'](to|ref|returnUrl|callback_url)[\"']", SPECS)),
      "open_redirect.params mein to, ref add karein")
check("P1.2", "sqli param vocab (q)",
      bool(re.search(r"(?m)^\s*params:.*\bq\b", SPECS.split("sqli_error")[1].split("sqli_bool")[0]))
      if "sqli_error" in SPECS else False,
      "sqli_error.params mein q add karein")
check("P1.3", "soft-404 multi-extension calibration",
      bool(re.search(r"\.html", DIRS)) and bool(re.search(r"zz.*?/[\"']|rpartition|with_suffix", DIRS)),
      "calibration mein extension-less sample bhi lein")
check("P1.4", "reflect: raw + encoded dono",
      bool(re.search(r"quote\(", PAYLOADS)) and bool(re.search(r"reflected raw|raw.*encoded", PAYLOADS)),
      "encoded vs raw alag classify karein")
check("P1.5", "targets sort (na ki slice)",
      bool(re.search(r"targets\.sort|sorted\(targets", PAYLOADS)),
      "SCORE ke hisab se sort, phir slice")
check("P1.6", "lab gate expected-vs-actual",
      bool(re.search(r"CASES|must_fire|expected", read("scripts", "lab_assert.py"))),
      "lab_assert.py mein per-case expected category matrix")

# --- P2 -------------------------------------------------------------------
check("P2.1", "findings dedupe",
      bool(re.search(r"UNIQUE\s*\([^)]*category", STORE, re.I)) or "dedupe" in REPORT.lower(),
      "report par (host, path, category) se dedupe")
check("P2.2", "sqli_time alag / unconfirmed",
      "unconfirmed" in (REPORT + PAYLOADS).lower(),
      "timing-based ko alag section mein")
check("P2.3", "report close se pehle likhta hai",
      (lambda: (CLI.find("write(") != -1 and CLI.find("close(") != -1
                and CLI.find("write(") < CLI.find("close(")))(),
      "finally mein write() pehle, close() try/except mein")
check("P2.4", "SSLError par retry reset",
      bool(re.search(r"SSLError[\s\S]{0,300}?attempt\s*=\s*0|SSLError[\s\S]{0,200}?break", HTTP)),
      "SSL fail par retry budget reset karein")

# --- regression -----------------------------------------------------------
check("R.1", "follow_redirects=False bacha hua",
      "follow_redirects=False" in HTTP, "wapis True mat karna")
check("R.2", "loose client maujood",
      "verify=False" in HTTP, "TLS fallback hata na dein")
check("R.3", "do baselines",
      len(re.findall(r"await client\.get\(url\)", PAYLOADS)) >= 2, "baseline 2 rakhna")
check("R.4", "per-request verify ka bug wapis nahi",
      not re.search(r"client\.get\([^)]*verify=", HTTP), "verify client-level hona chahiye")
check("R.5", "client.close() maujood",
      ".close()" in HTTP, "leak na ho")

failed = [r for r in results if not r["ok"]]
blocking = [r for r in failed if r["id"].startswith(("P0", "P1"))]

if AS_JSON:
    print(json.dumps({"root": str(ROOT), "results": results,
                      "failed": len(failed), "blocking": len(blocking)}, indent=2))
else:
    for r in results:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"  {mark} {r['id']:<5} {r['label']}")
        if not r["ok"] and r["hint"]:
            print(f"       -> {r['hint']}")
    print(f"\n{len(results) - len(failed)}/{len(results)} pass | blocking: {len(blocking)}")

sys.exit(1 if blocking else 0)
