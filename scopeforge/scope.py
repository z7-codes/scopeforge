from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Scope
from .storage import read_json, write_json

SCOPES_FILE = "scopes.json"
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched: str = ""


def normalize_token(value: str) -> str:
    raw = str(value).strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        host = urlsplit(raw).hostname or ""
        return host
    if raw.startswith("*."):
        return "*." + normalize_token(raw[2:])
    host = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return host.lstrip("*.")


def valid_host(value: str) -> bool:
    host = normalize_token(value)
    if not host or len(host) > 253:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.startswith("*."):
        host = host[2:]
    if DOMAIN.match(host):
        return all(LABEL.match(part) for part in host.split("."))
    return False


def base_domain(token: str) -> str:
    normalized = normalize_token(token)
    return normalized[2:] if normalized.startswith("*.") else normalized


def host_matches(host: str, token: str) -> bool:
    host = normalize_token(host)
    token = normalize_token(token)
    if not host or not token:
        return False
    base = token[2:] if token.startswith("*.") else token
    return host == base or host.endswith("." + base)


def check_scope(scope: Scope, candidate: str) -> ScopeDecision:
    host = normalize_token(candidate)
    if not valid_host(host):
        return ScopeDecision(False, "candidate is not a valid hostname or URL")
    matched = next((token for token in scope.domains if host_matches(host, token)), "")
    if not matched:
        return ScopeDecision(False, "candidate does not match any allowed scope token")
    excluded = next((token for token in scope.exclusions if host_matches(host, token)), "")
    if excluded:
        return ScopeDecision(False, f"candidate matches exclusion: {excluded}")
    return ScopeDecision(True, "candidate matches written scope", matched)


def load_scopes() -> dict[str, dict]:
    value = read_json(SCOPES_FILE, {})
    return value if isinstance(value, dict) else {}


def get_scope(name: str) -> Scope:
    scopes = load_scopes()
    value = scopes.get(name)
    if not isinstance(value, dict):
        raise ValueError(f"scope not found: {name}")
    return Scope.from_dict(value)


def list_scopes() -> list[Scope]:
    return [Scope.from_dict(value) for value in load_scopes().values() if isinstance(value, dict)]


def add_scope(name: str, domains: list[str], exclusions: list[str] | None = None, source: str = "") -> Scope:
    clean_name = str(name).strip()
    if not clean_name:
        raise ValueError("scope name is required")
    clean_domains = [normalize_token(item) for item in domains if normalize_token(item)]
    clean_exclusions = [normalize_token(item) for item in (exclusions or []) if normalize_token(item)]
    if not clean_domains:
        raise ValueError("at least one domain is required")
    invalid = [item for item in clean_domains + clean_exclusions if not valid_host(item)]
    if invalid:
        raise ValueError("invalid domain token: " + ", ".join(invalid))
    scopes = load_scopes()
    if clean_name in scopes:
        raise ValueError(f"scope already exists: {clean_name}")
    scope = Scope(
        name=clean_name,
        domains=clean_domains,
        exclusions=clean_exclusions,
        source=str(source).strip(),
    )
    scopes[clean_name] = scope.to_dict()
    write_json(SCOPES_FILE, scopes)
    return scope
