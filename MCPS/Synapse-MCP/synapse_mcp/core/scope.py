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
from .errors import McpError
from .url_hygiene import redact_url_query_values


SCOPE_FILE = DATA_DIR / "scope" / "scope.json"
DEFAULT_INVENTORY_PREVIEW = 5
DEFAULT_INVENTORY_PAGE_SIZE = 50
MAX_INVENTORY_PAGE_SIZE = 500


def _inventory_cursor(value: str | None) -> int:
    if value in (None, ""):
        return 0
    try:
        cursor = int(value)
    except (TypeError, ValueError) as exc:
        raise McpError(-32602, "cursor must be a non-negative integer offset.") from exc
    if cursor < 0:
        raise McpError(-32602, "cursor must be a non-negative integer offset.")
    return cursor


def compact_scope(
    scope_value: dict[str, Any],
    *,
    cursor: str | None = None,
    limit: int = DEFAULT_INVENTORY_PAGE_SIZE,
    include_inventory: bool = False,
) -> dict[str, Any]:
    """Return bounded scope metadata plus an optional inventory page.

    A missing cursor is the routine compact view and returns only a small
    preview. Supplying a cursor opts into pagination, while include_inventory
    deliberately returns the complete inventory for compatibility/export use.
    """
    page_limit = int(limit)
    if page_limit < 1 or page_limit > MAX_INVENTORY_PAGE_SIZE:
        raise McpError(-32602, f"limit must be between 1 and {MAX_INVENTORY_PAGE_SIZE}.")
    inventory = [
        {"type": kind, "value": str(value)}
        for kind in ("host", "pattern", "cidr")
        for value in scope_value.get({"host": "hosts", "pattern": "patterns", "cidr": "cidrs"}[kind], [])
        if isinstance(value, str)
    ]
    offset = _inventory_cursor(cursor)
    if include_inventory:
        page = inventory
        offset = 0
    else:
        effective_limit = page_limit if cursor is not None else min(DEFAULT_INVENTORY_PREVIEW, page_limit)
        page = inventory[offset : offset + effective_limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(inventory)
    result: dict[str, Any] = {
        "organization": scope_value.get("organization", ""),
        "notes": scope_value.get("notes", ""),
        "counts": {
            "hosts": len(scope_value.get("hosts", [])),
            "patterns": len(scope_value.get("patterns", [])),
            "cidrs": len(scope_value.get("cidrs", [])),
            "total": len(inventory),
        },
        "inventory": page,
        "inventoryIncluded": include_inventory,
        "pagination": {
            "cursor": str(offset),
            "limit": len(page),
            "returned": len(page),
            "total": len(inventory),
            "hasMore": has_more,
            "nextCursor": str(next_offset) if has_more else None,
        },
    }
    return result


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
    *,
    cursor: str | None = None,
    limit: int = DEFAULT_INVENTORY_PAGE_SIZE,
    include_inventory: bool = False,
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
    result = {
        "saved": True,
        "path": str(SCOPE_FILE),
        "scope": compact_scope(payload, cursor=cursor, limit=limit, include_inventory=include_inventory),
    }
    if initialized:
        initialized_hosts = initialized.get("hosts", [])
        result["evidenceProject"] = {
            "initialized": initialized.get("initialized", False),
            "organization": initialized.get("organization", organization),
            "path": initialized.get("path", ""),
            "hostCount": len(initialized_hosts) if isinstance(initialized_hosts, list) else 0,
        }
    return result


def normalize_host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    return parsed.hostname or value


def check_target(
    target: str,
    *,
    cursor: str | None = None,
    limit: int = DEFAULT_INVENTORY_PAGE_SIZE,
    include_inventory: bool = False,
) -> dict[str, Any]:
    scope_value = load_scope()
    return check_target_in_scope(
        target,
        scope_value,
        cursor=cursor,
        limit=limit,
        include_inventory=include_inventory,
    )


def check_target_in_scope(
    target: str,
    scope: dict[str, Any],
    *,
    cursor: str | None = None,
    limit: int = DEFAULT_INVENTORY_PAGE_SIZE,
    include_inventory: bool = False,
) -> dict[str, Any]:
    host = normalize_host(target)
    match = _scope_match(host, scope)
    public_target = redact_url_query_values(target) if urlsplit(str(target)).scheme in {"http", "https"} else target
    return {
        "target": public_target,
        "host": host,
        "inScope": bool(match["allowed"]),
        "match": match,
        "scope": compact_scope(scope, cursor=cursor, limit=limit, include_inventory=include_inventory),
    }


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
