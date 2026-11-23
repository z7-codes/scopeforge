from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import load_config
from .errors import ScopeError
from .models import Decision, Scope
from .storage import read_json, write_json

SCOPES_FILE = "scopes.json"
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
LAB_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
LAB_SUFFIXES_DEFAULT = (".localhost", ".test")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched: str = ""


def _network(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def normalize_token(value: str) -> str:
    raw = str(value).strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        return urlsplit(raw).hostname or ""
    if raw.startswith("*."):
        return "*." + normalize_token(raw[2:])
    candidate = raw.split("/")[0].split("?")[0].split("#")[0]
    if candidate.startswith("["):
        end = candidate.find("]")
        return candidate[1:end] if end != -1 else ""
    if candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    return candidate.lstrip("*.")


def normalize_scope_token(value: str) -> str:
    raw = str(value).strip()
    network = _network(raw)
    return str(network) if network else normalize_token(raw)


def safe_name(value: str) -> str:
    name = str(value).strip().lower()
    if not NAME.match(name):
        raise ValueError("scope name must match [a-z0-9._-], 1-64 chars")
    return name


def valid_host(value: str) -> bool:
    host = normalize_token(value)
    if not host or len(host) > 253:
        return False
    if "/" in str(value) and _network(str(value).strip()):
        return True
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
    network = _network(str(token).strip())
    if network is not None:
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    token = normalize_token(token)
    if not host or not token:
        return False
    base = token[2:] if token.startswith("*.") else token
    return host == base or host.endswith("." + base)


def is_lab_host(host: str, suffixes: Sequence[str] | None = None) -> bool:
    value = normalize_token(host)
    chosen = tuple(load_config().lab_suffixes) if suffixes is None else tuple(suffixes)
    return value in LAB_HOSTS or any(value.endswith(suffix) for suffix in chosen)


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


def guard(scope: Scope | None, url: str, lab: bool = False) -> Decision:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ScopeError("url must start with http:// or https://")
    host = normalize_token(url)
    if not host:
        raise ScopeError("url has no hostname")
    if scope is None:
        if lab and is_lab_host(host):
            return Decision(True, "lab host", host)
        raise ScopeError("non-lab targets require a saved scope")
    decision = check_scope(scope, url)
    if not decision.allowed:
        raise ScopeError("blocked by scope: " + decision.reason)
    return Decision(True, decision.reason, decision.matched)


def load_scopes() -> dict[str, dict]:
    value = read_json(SCOPES_FILE, {})
    return value if isinstance(value, dict) else {}


def get_scope(name: str) -> Scope:
    value = load_scopes().get(name)
    if not isinstance(value, dict):
        raise ValueError(f"scope not found: {name}")
    return Scope.from_dict(value)


def list_scopes() -> list[Scope]:
    return [Scope.from_dict(value) for value in load_scopes().values() if isinstance(value, dict)]


def add_scope(name: str, domains: list[str], exclusions: list[str] | None = None, source: str = "") -> Scope:
    clean_name = safe_name(name)
    if not clean_name:
        raise ValueError("scope name is required")
    clean_domains = [normalize_scope_token(item) for item in domains if normalize_scope_token(item)]
    clean_exclusions = [normalize_scope_token(item) for item in (exclusions or []) if normalize_scope_token(item)]
    if not clean_domains:
        raise ValueError("at least one domain is required")
    invalid = [item for item in clean_domains + clean_exclusions if not valid_host(item)]
    if invalid:
        raise ValueError("invalid domain token: " + ", ".join(invalid))
    scopes = load_scopes()
    if clean_name in scopes:
        raise ValueError(f"scope already exists: {clean_name}")
    scope = Scope(name=clean_name, domains=clean_domains, exclusions=clean_exclusions, source=str(source).strip())
    scopes[clean_name] = scope.to_dict()
    write_json(SCOPES_FILE, scopes)
    return scope


def remove_scope(name: str) -> None:
    scopes = load_scopes()
    if name not in scopes:
        raise ValueError("scope not found: " + name)
    del scopes[name]
    write_json(SCOPES_FILE, scopes)
