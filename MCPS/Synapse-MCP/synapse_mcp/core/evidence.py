# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .paths import DATA_DIR


EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_LOG = EVIDENCE_DIR / "events.jsonl"
ORGS_DIR = EVIDENCE_DIR / "orgs"

HOST_FIELD_NAMES = ("target", "url", "hostname", "host", "domain")
ORG_FIELD_NAMES = ("organization", "org", "company", "client", "project")
SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "jwt",
    "bearer",
}
REDACTED_VALUE = "[REDACTED]"
MAX_STRING_SCRUB_BYTES = 100_000
SECRET_STRING_PATTERNS = (
    re.compile(r"(Authorization:\s*[A-Za-z][A-Za-z0-9_-]*\s+)([^\s\r\n]+)", re.IGNORECASE),
    re.compile(r"(Set-Cookie:\s*[^=;\s]+)=([^;\r\n]+)", re.IGNORECASE),
    re.compile(r"(Cookie:\s*)([^\r\n]+)", re.IGNORECASE),
    re.compile(r"\b(Bearer\s+)([A-Za-z0-9._~+/=-]{6,})", re.IGNORECASE),
    re.compile(r"\b((?:password|passwd)=)([^&\s]+)", re.IGNORECASE),
)


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return normalized or "unknown"


def normalize_host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    return (parsed.hostname or value).lower()


def _first_string(data: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _workspace_organization(workspace_id: str) -> str:
    workspace_slug = slug(workspace_id)
    if not workspace_slug:
        return ""
    meta_path = EVIDENCE_DIR.parent / "workspaces" / workspace_slug / "workspace.json"
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    organization = payload.get("organization") if isinstance(payload, dict) else ""
    return organization.strip() if isinstance(organization, str) else ""


def _extract_hosts_from_value(value: Any) -> set[str]:
    hosts: set[str] = set()
    if isinstance(value, str):
        host = normalize_host(value)
        if host:
            hosts.add(host)
    elif isinstance(value, list):
        for item in value:
            hosts.update(_extract_hosts_from_value(item))
    elif isinstance(value, dict):
        hosts.update(extract_hosts(value))
    return hosts


def extract_hosts(data: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for key in HOST_FIELD_NAMES:
        if key in data:
            hosts.update(_extract_hosts_from_value(data[key]))
    if "hosts" in data:
        hosts.update(_extract_hosts_from_value(data["hosts"]))
    return hosts


def extract_organization(data: dict[str, Any] | None = None, default: str = "unknown-org") -> str:
    if not data:
        return default
    value = _first_string(data, ORG_FIELD_NAMES)
    if value:
        return value
    workspace_id = data.get("workspaceId") or data.get("workspace_id")
    if isinstance(workspace_id, str) and workspace_id.strip():
        value = _workspace_organization(workspace_id)
        if value:
            return value
    return default


def project_path(organization: str) -> Path:
    return ORGS_DIR / slug(organization)


def host_path(organization: str, host: str) -> Path:
    return project_path(organization) / "hosts" / slug(host)


def ensure_project(organization: str, hosts: list[str] | None = None) -> dict[str, Any]:
    org = organization or "unknown-org"
    org_dir = project_path(org)
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "hosts").mkdir(parents=True, exist_ok=True)
    org_meta = {
        "organization": org,
        "slug": slug(org),
        "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (org_dir / "metadata.json").write_text(json.dumps(org_meta, indent=2, ensure_ascii=False), encoding="utf-8")

    created_hosts = []
    for raw_host in hosts or []:
        host = normalize_host(raw_host)
        if not host:
            continue
        hdir = host_path(org, host)
        hdir.mkdir(parents=True, exist_ok=True)
        meta = {
            "organization": org,
            "host": host,
            "slug": slug(host),
            "updatedAt": org_meta["updatedAt"],
        }
        (hdir / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        (hdir / "events.jsonl").touch(exist_ok=True)
        created_hosts.append({"host": host, "path": str(hdir)})

    return {"initialized": True, "organization": org, "path": str(org_dir), "hosts": created_hosts}


def _append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def _field_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _scrub_secret_strings(value: str) -> str:
    if len(value.encode("utf-8", errors="ignore")) > MAX_STRING_SCRUB_BYTES:
        return value
    scrubbed = value
    for pattern in SECRET_STRING_PATTERNS:
        scrubbed = pattern.sub(lambda match: f"{match.group(1)}{REDACTED_VALUE}", scrubbed)
    return scrubbed


def sanitize_data(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _field_marker(key_text) in SENSITIVE_FIELD_NAMES:
                sanitized[key_text] = REDACTED_VALUE
            else:
                sanitized[key_text] = sanitize_data(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_data(item) for item in value]
    if isinstance(value, str):
        return _scrub_secret_strings(value)
    return value


def _index_event(event: dict[str, Any]) -> list[str]:
    data = event.get("data", {})
    if not isinstance(data, dict):
        return []
    hosts = sorted(extract_hosts(data))
    if not hosts:
        return []
    organization = extract_organization(data)
    paths = []
    ensure_project(organization, hosts)
    for host in hosts:
        path = host_path(organization, host) / "events.jsonl"
        _append_jsonl(path, event)
        paths.append(str(path))
    return paths


def log_event(event_type: str, summary: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    event_data = data or {}
    workspace_id = event_data.get("workspaceId") or event_data.get("workspace_id")
    if isinstance(workspace_id, str) and workspace_id.strip():
        from ..state.runtime import ActivatedWorkspaceRepository
        from ..state.selector import assert_json_v1_write_allowed, selected_store_version

        workspace_root = EVIDENCE_DIR.parent / "workspaces" / slug(workspace_id)
        if selected_store_version(workspace_root) == "sqlite-v2":
            repository = ActivatedWorkspaceRepository(slug(workspace_id), workspace_root)
            result = repository.append_audit(event_type, summary, sanitize_data(event_data))
            return {
                **result,
                "path": str(repository.database_path),
                "indexedPaths": [],
                "event": {
                    "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "type": event_type,
                    "summary": summary,
                    "data": sanitize_data(event_data),
                },
            }
        assert_json_v1_write_allowed(workspace_root / "workspace.json")
    EVIDENCE_LOG.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": event_type,
        "summary": summary,
        "data": sanitize_data(event_data),
    }
    _append_jsonl(EVIDENCE_LOG, event)
    indexed_paths = _index_event(event)
    return {"logged": True, "path": str(EVIDENCE_LOG), "indexedPaths": indexed_paths, "event": event}


def tail_events(limit: int = 20) -> list[dict[str, Any]]:
    if not EVIDENCE_LOG.exists():
        return []
    return _read_jsonl_tail(EVIDENCE_LOG, limit)


def _read_jsonl_tail(path: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    limit = max(int(limit), 1)
    block_size = 8192
    data = b""
    with path.open("rb") as handle:
        handle.seek(0, 2)
        position = handle.tell()
        while position > 0 and data.count(b"\n") <= limit:
            read_size = min(block_size, position)
            position -= read_size
            handle.seek(position)
            data = handle.read(read_size) + data
    lines = [line.decode("utf-8", errors="replace") for line in data.splitlines() if line.strip()]
    events = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _event_mentions_host(event: dict[str, Any], host: str) -> bool:
    data = event.get("data", {})
    return isinstance(data, dict) and host in extract_hosts(data)


def host_context(target: str, organization: str | None = None, limit: int = 50) -> dict[str, Any]:
    host = normalize_host(target)
    if not host:
        return {"target": target, "host": "", "events": [], "paths": []}

    org = organization or ""
    paths: list[Path] = []
    if org:
        paths.append(host_path(org, host) / "events.jsonl")
    else:
        for candidate in ORGS_DIR.glob("*/hosts/*/events.jsonl"):
            try:
                meta = json.loads((candidate.parent / "metadata.json").read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                meta = {}
            if meta.get("host") == host or candidate.parent.name == slug(host):
                paths.append(candidate)

    events: list[dict[str, Any]] = []
    seen = set()
    for path in paths:
        for event in _read_jsonl_tail(path, limit):
            marker = json.dumps(event, sort_keys=True, ensure_ascii=False)
            if marker not in seen:
                events.append(event)
                seen.add(marker)

    if len(events) < limit and EVIDENCE_LOG.exists():
        for event in tail_events(1000):
            if _event_mentions_host(event, host):
                marker = json.dumps(event, sort_keys=True, ensure_ascii=False)
                if marker not in seen:
                    events.append(event)
                    seen.add(marker)

    events = sorted(events, key=lambda item: item.get("createdAt", ""))[-limit:]
    fingerprints = []
    fingerprint_paths = []
    for path in paths:
        fingerprint_path = path.parent / "fingerprint.json"
        if not fingerprint_path.exists():
            continue
        try:
            fingerprints.append(json.loads(fingerprint_path.read_text(encoding="utf-8")))
            fingerprint_paths.append(str(fingerprint_path))
        except json.JSONDecodeError:
            continue
    return {
        "target": target,
        "host": host,
        "organization": org or None,
        "fingerprints": fingerprints,
        "events": events,
        "paths": [str(path) for path in paths if path.exists()],
        "fingerprintPaths": fingerprint_paths,
    }
