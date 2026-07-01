# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import fnmatch
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .paths import DATA_DIR
from . import evidence


SCOPE_FILE = DATA_DIR / "scope" / "scope.json"


def load_scope() -> dict[str, Any]:
    if not SCOPE_FILE.exists():
        return {"hosts": [], "notes": "No persisted scope file yet."}
    try:
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"hosts": [], "notes": f"Invalid scope file: {SCOPE_FILE}"}


def save_scope(
    hosts: list[str],
    notes: str = "",
    organization: str = "",
    patterns: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> dict[str, Any]:
    SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
    normalized = sorted({normalize_host(host) for host in hosts if normalize_host(host)})
    normalized_patterns = sorted({pattern.strip().lower() for pattern in patterns or [] if pattern.strip()})
    normalized_cidrs = sorted({cidr.strip() for cidr in cidrs or [] if cidr.strip()})
    payload = {"hosts": normalized, "notes": notes}
    if normalized_patterns:
        payload["patterns"] = normalized_patterns
    if normalized_cidrs:
        payload["cidrs"] = normalized_cidrs
    if organization:
        payload["organization"] = organization
    SCOPE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    initialized = evidence.ensure_project(organization, normalized) if organization else None
    evidence.log_event(
        "scope.set",
        f"Updated authorized scope with {len(normalized)} hosts.",
        {
            "organization": organization,
            "hosts": normalized,
            "patterns": normalized_patterns,
            "cidrs": normalized_cidrs,
            "notes": notes,
            "path": str(SCOPE_FILE),
        },
    )
    result = {"saved": True, "path": str(SCOPE_FILE), "scope": payload}
    if initialized:
        result["evidenceProject"] = initialized
    return result


def normalize_host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    return parsed.hostname or value


def check_target(target: str) -> dict[str, Any]:
    host = normalize_host(target)
    scope = load_scope()
    return check_target_in_scope(target, scope)


def check_target_in_scope(target: str, scope: dict[str, Any]) -> dict[str, Any]:
    host = normalize_host(target)
    match = _scope_match(host, scope)
    return {"target": target, "host": host, "inScope": bool(match["allowed"]), "match": match, "scope": scope}


def _scope_match(host: str, scope: dict[str, Any]) -> dict[str, Any]:
    if not host:
        return {"allowed": False, "type": "none"}
    exact_hosts = {normalize_host(item) for item in scope.get("hosts", []) if isinstance(item, str)}
    if host in exact_hosts:
        return {"allowed": True, "type": "host", "value": host}

    for pattern in scope.get("patterns", []):
        if not isinstance(pattern, str):
            continue
        normalized_pattern = pattern.strip().lower()
        if normalized_pattern.startswith("exact:"):
            exact = normalize_host(normalized_pattern.removeprefix("exact:"))
            if host == exact:
                return {"allowed": True, "type": "exact", "value": pattern}
            continue
        if fnmatch.fnmatchcase(host, normalized_pattern):
            return {"allowed": True, "type": "pattern", "value": pattern}

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address:
        for cidr in scope.get("cidrs", []):
            if not isinstance(cidr, str):
                continue
            try:
                if address in ipaddress.ip_network(cidr.strip(), strict=False):
                    return {"allowed": True, "type": "cidr", "value": cidr}
            except ValueError:
                continue

    return {"allowed": False, "type": "none"}
