from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable

HIGH, MEDIUM, LOW = "high", "medium", "low"
Validator = Callable[[bytes, str], bool]


def _json(body: bytes) -> dict | None:
    try:
        value = json.loads(body[:20000].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _has(pattern: bytes, body: bytes, minimum: int = 1) -> bool:
    return len(re.findall(pattern, body[:8192], re.IGNORECASE)) >= minimum


def valid_env(body: bytes, ctype: str) -> bool:
    if b"<html" in body[:2048].lower():
        return False
    return _has(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", body, 2)


def valid_git_head(body: bytes, ctype: str) -> bool:
    return bool(re.match(rb"^(ref: refs/|[0-9a-f]{40})", body[:200]))


def valid_git_config(body: bytes, ctype: str) -> bool:
    return b"[core]" in body[:2000] or b"[remote" in body[:2000]


def valid_git_log(body: bytes, ctype: str) -> bool:
    return body[:200].count(b" ") > 2 and b"commit" in body[:2000].lower()


def valid_zip(body: bytes, ctype: str) -> bool:
    return body[:4] == b"PK\x03\x04"


def valid_sql(body: bytes, ctype: str) -> bool:
    return _has(rb"(insert into|create table|-- mysql dump|-- postgresql dump)", body)


def valid_openapi(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("openapi" in value or "swagger" in value or "paths" in value)


def valid_actuator(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("_links" in value or str(value.get("status", "")).upper() == "UP")


def valid_actuator_env(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("propertySources" in value or "activeProfiles" in value)


def valid_phpinfo(body: bytes, ctype: str) -> bool:
    return b"php version" in body[:8000].lower() and b"phpinfo" in body[:20000].lower()


def valid_server_status(body: bytes, ctype: str) -> bool:
    return b"apache server status" in body[:4000].lower()


def valid_server_info(body: bytes, ctype: str) -> bool:
    return b"apache server information" in body[:4000].lower()


def valid_ds_store(body: bytes, ctype: str) -> bool:
    return body[:8] == b"\x00\x00\x00\x01Bud1"


def valid_graphql(body: bytes, ctype: str) -> bool:
    return b"__schema" in body[:8000]


def valid_dockerfile(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^FROM\s+\S", body)


def valid_web_xml(body: bytes, ctype: str) -> bool:
    return b"<web-app" in body[:4000]


def valid_package_json(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and "name" in value and ("dependencies" in value or "require" in value)


def valid_source_map(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and "mappings" in value and "version" in value


def valid_aws(body: bytes, ctype: str) -> bool:
    return b"aws_access_key_id" in body[:4000].lower()


def valid_firebase(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("hosting" in value or "database" in value or "firestore" in value)


def valid_htaccess(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(RewriteRule|RewriteEngine|Options|AddType|Order)\b", body)


def valid_idea_workspace(body: bytes, ctype: str) -> bool:
    return b"<project version=" in body[:2000]


def valid_elmah(body: bytes, ctype: str) -> bool:
    return b"error log for" in body[:4000].lower() or b"elmah.axd" in body[:8000].lower()


def valid_svn_entries(body: bytes, ctype: str) -> bool:
    return re.match(rb"^\d+\n", body[:12]) is not None and b"\x0c" in body[:2000]


def valid_robots(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(user-agent|disallow|sitemap)\s*:", body)


def valid_sitemap(body: bytes, ctype: str) -> bool:
    return b"<urlset" in body[:2000]


def valid_security_txt(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(contact|expires)\s*:", body)


@dataclass(frozen=True)
class PathRule:
    path: str
    label: str
    tier: str
    validator: Validator | None = None


RULES: tuple[PathRule, ...] = (
    PathRule("/.env", "dotenv", HIGH, valid_env),
    PathRule("/.git/HEAD", "git-head", HIGH, valid_git_head),
    PathRule("/.git/config", "git-config", HIGH, valid_git_config),
    PathRule("/.git/logs/HEAD", "git-log", HIGH, valid_git_log),
    PathRule("/actuator/env", "spring-actuator-env", HIGH, valid_actuator_env),
    PathRule("/actuator/heapdump", "spring-heapdump", HIGH, None),
    PathRule("/backup.zip", "backup-zip", HIGH, valid_zip),
    PathRule("/db.sql", "sql-dump", HIGH, valid_sql),
    PathRule("/dump.sql", "sql-dump", HIGH, valid_sql),
    PathRule("/.aws/credentials", "aws-credentials", HIGH, valid_aws),
    PathRule("/openapi.json", "openapi", MEDIUM, valid_openapi),
    PathRule("/swagger.json", "swagger", MEDIUM, valid_openapi),
    PathRule("/swagger", "swagger-ui", MEDIUM, valid_openapi),
    PathRule("/api-docs", "api-docs", MEDIUM, valid_openapi),
    PathRule("/graphql", "graphql", MEDIUM, valid_graphql),
    PathRule("/actuator", "spring-actuator", MEDIUM, valid_actuator),
    PathRule("/phpinfo.php", "phpinfo", MEDIUM, valid_phpinfo),
    PathRule("/server-status", "apache-status", MEDIUM, valid_server_status),
    PathRule("/server-info", "apache-info", MEDIUM, valid_server_info),
    PathRule("/package.json", "npm-manifest", MEDIUM, valid_package_json),
    PathRule("/composer.json", "composer-manifest", MEDIUM, valid_package_json),
    PathRule("/firebase.json", "firebase-config", MEDIUM, valid_firebase),
    PathRule("/Dockerfile", "dockerfile", MEDIUM, valid_dockerfile),
    PathRule("/WEB-INF/web.xml", "web-xml", MEDIUM, valid_web_xml),
    PathRule("/.idea/workspace.xml", "jetbrains-workspace", MEDIUM, valid_idea_workspace),
    PathRule("/elmah.axd", "elmah", MEDIUM, valid_elmah),
    PathRule("/.htaccess", "htaccess", LOW, valid_htaccess),
    PathRule("/.svn/entries", "svn-entries", LOW, valid_svn_entries),
    PathRule("/.DS_Store", "ds-store", LOW, valid_ds_store),
    PathRule("/robots.txt", "robots", LOW, valid_robots),
    PathRule("/sitemap.xml", "sitemap", LOW, valid_sitemap),
    PathRule("/.well-known/security.txt", "security-txt", LOW, valid_security_txt),
)

BY_PATH = {rule.path: rule for rule in RULES}
TIER_ORDER = (HIGH, MEDIUM, LOW)


def get_rule(path: str) -> PathRule:
    rule = BY_PATH.get(path)
    if rule is None:
        raise ValueError("unknown path rule: " + path)
    return rule


def rules_for(tier: str = HIGH) -> list[PathRule]:
    key = str(tier).strip().lower()
    if key in ("all", "any"):
        return list(RULES)
    if key not in TIER_ORDER:
        raise ValueError("tier must be high, medium, low, or all")
    allowed = set(TIER_ORDER[: TIER_ORDER.index(key) + 1])
    return [rule for rule in RULES if rule.tier in allowed]
