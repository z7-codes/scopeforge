from __future__ import annotations

LABS: dict[str, list[str]] = {
    "localhost": [
        "Use only an application you own or were explicitly allowed to test.",
        "Record the scope source before starting.",
        "Use a benign marker such as Z7CHECK-<short-random>.",
        "Observe where the marker appears and record the output context.",
        "Stop if real user data, credentials, or secrets appear.",
    ],
    "dvwa": [
        "Run DVWA locally and set security level intentionally.",
        "Use the built-in DVWA forms only.",
        "Record reflection context for XSS scenarios.",
        "Record error family for SQL scenarios.",
        "Do not extract database contents.",
    ],
    "juice-shop": [
        "Run OWASP Juice Shop locally.",
        "Use the in-app challenge list as the scenario source.",
        "Record the endpoint, parameter, and output context.",
        "Keep evidence redacted and minimal.",
        "Do not use real accounts or external services.",
    ],
    "ctf": [
        "Confirm the CTF-provided domain list.",
        "Use only assets listed by the event.",
        "Record challenge name, parameter, and observation.",
        "Do not scan or test unlisted domains.",
        "Stop if the challenge rules prohibit automated interaction.",
    ],
}


def render_lab(scenario: str) -> str:
    key = str(scenario).strip().lower().replace("_", "-")
    if key not in LABS:
        available = ", ".join(sorted(LABS))
        raise ValueError("unknown lab scenario: " + str(scenario) + " | available: " + available)
    lines = [f"# ScopeForge Lab Mode — {key}", "", "Guided checks only. No requests are sent by this tool.", ""]
    lines.extend(f"{index}. {step}" for index, step in enumerate(LABS[key], start=1))
    lines.extend(["", "Devil Mode here means deeper observation and stricter scoring, never exploitation."])
    return "\n".join(lines)
