from __future__ import annotations

import json
import re
from collections.abc import Callable

from .errors import DataError

Validator = Callable[[bytes, str], bool]


def _json(body: bytes) -> dict:
    try:
        value = json.loads(body[:20000].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _has(pattern: bytes, body: bytes, minimum: int = 1) -> bool:
    return len(re.findall(pattern, body[:8192], re.IGNORECASE)) >= minimum


def env(body: bytes, ctype: str) -> bool:
    if b"<html" in body[:2048].lower():
        return False
    return _has(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", body, 2)


def git_head(body: bytes, ctype: str) -> bool:
    return bool(re.match(rb"^(ref: refs/|[0-9a-f]{40})", body[:200]))


def git_config(body: bytes, ctype: str) -> bool:
    return b"[core]" in body[:2000] or b"[remote" in body[:2000]


def git_log(body: bytes, ctype: str) -> bool:
    return body[:200].count(b" ") > 2 and b"commit" in body[:2000].lower()


def zip_archive(body: bytes, ctype: str) -> bool:
    return body[:4] == b"PK\x03\x04"


def sql(body: bytes, ctype: str) -> bool:
    return _has(rb"(insert into|create table|-- mysql dump|-- postgresql dump)", body)


def openapi(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("openapi" in value or "swagger" in value or "paths" in value)


def actuator(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("_links" in value or str(value.get("status", "")).upper() == "UP")


def actuator_env(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("propertySources" in value or "activeProfiles" in value)


def phpinfo(body: bytes, ctype: str) -> bool:
    return b"php version" in body[:8000].lower() and b"phpinfo" in body[:20000].lower()


def server_status(body: bytes, ctype: str) -> bool:
    return b"apache server status" in body[:4000].lower()


def server_info(body: bytes, ctype: str) -> bool:
    return b"apache server information" in body[:4000].lower()


def ds_store(body: bytes, ctype: str) -> bool:
    return body[:8] == b"\x00\x00\x00\x01Bud1"


def graphql(body: bytes, ctype: str) -> bool:
    return b"__schema" in body[:8000]


def dockerfile(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^FROM\s+\S", body)


def web_xml(body: bytes, ctype: str) -> bool:
    return b"<web-app" in body[:4000]


def manifest(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and "name" in value and ("dependencies" in value or "require" in value)


def source_map(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and "mappings" in value and "version" in value


def aws(body: bytes, ctype: str) -> bool:
    return b"aws_access_key_id" in body[:4000].lower()


def firebase(body: bytes, ctype: str) -> bool:
    value = _json(body)
    return bool(value) and ("hosting" in value or "database" in value or "firestore" in value)


def htaccess(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(RewriteRule|RewriteEngine|Options|AddType|Order)\b", body)


def idea(body: bytes, ctype: str) -> bool:
    return b"<project version=" in body[:2000]


def elmah(body: bytes, ctype: str) -> bool:
    return b"error log for" in body[:4000].lower() or b"elmah.axd" in body[:8000].lower()


def svn(body: bytes, ctype: str) -> bool:
    return re.match(rb"^\d+\n", body[:12]) is not None and b"\x0c" in body[:2000]


def robots(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(user-agent|disallow|sitemap)\s*:", body)


def sitemap(body: bytes, ctype: str) -> bool:
    return b"<urlset" in body[:2000]


def security_txt(body: bytes, ctype: str) -> bool:
    return _has(rb"(?m)^(contact|expires)\s*:", body)


REGISTRY: dict[str, Validator] = {
    "env": env,
    "git_head": git_head,
    "git_config": git_config,
    "git_log": git_log,
    "zip": zip_archive,
    "sql": sql,
    "openapi": openapi,
    "actuator": actuator,
    "actuator_env": actuator_env,
    "phpinfo": phpinfo,
    "server_status": server_status,
    "server_info": server_info,
    "ds_store": ds_store,
    "graphql": graphql,
    "dockerfile": dockerfile,
    "web_xml": web_xml,
    "manifest": manifest,
    "source_map": source_map,
    "aws": aws,
    "firebase": firebase,
    "htaccess": htaccess,
    "idea": idea,
    "elmah": elmah,
    "svn": svn,
    "robots": robots,
    "sitemap": sitemap,
    "security_txt": security_txt,
}


def resolve(name: str | None) -> Validator | None:
    if not name:
        return None
    validator = REGISTRY.get(str(name))
    if validator is None:
        raise DataError("unknown validator: " + str(name))
    return validator
