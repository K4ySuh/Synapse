# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from xml.etree import ElementTree

from . import evidence, scope
from .adapters.results import surface_candidate, surface_candidate_id
from .errors import McpError
from .paths import DATA_DIR, REPORTS_DIR as _CONFIGURED_REPORTS_DIR


WORKSPACES_DIR = DATA_DIR / "workspaces"
# Top-level reports root (tests rebind this to a temp dir). Rendered reports and the
# per-workspace decision archive live here, never inside the workspace state folder.
REPORTS_DIR = _CONFIGURED_REPORTS_DIR
DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_STATE = threading.local()
ENTITY_FILES = {
    "services": "services.json",
    "endpoints": "endpoints.json",
    "parameters": "parameters.json",
    "findings": "findings.json",
    "actions": "actions.json",
    "observations": "observations.json",
}
ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".rar", ".bak", ".backup", ".sql", ".db")
INTERESTING_PATH_MARKERS = ("admin", "backup", "debug", "dump", "config", "secret", "token", "swagger", "graphql")
AUTH_FIELD_MARKERS = ("pass", "token", "otp", "mfa", "csrf", "user", "email", "login")
HIGH_VALUE_FORM_PATH_MARKERS = ("login", "auth", "session", "account", "admin", "upload", "import", "export", "reset", "password")
FINDING_STATUSES = {"candidate", "confirmed", "false_positive", "accepted_risk", "fixed"}
FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_CONFIDENCES = {"low", "medium", "high"}
DEFAULT_REPLACEABLE_EVIDENCE_SOURCES = {"sitemap", "crawler", "js_intelligence"}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return normalized or "default"


def normalize_workspace_id(value: str) -> str:
    return slug(value)


def normalize_target(value: str) -> str:
    return scope.normalize_host(value).lower()


def default_workspace_id() -> str:
    current_scope = scope.load_scope()
    organization = current_scope.get("organization")
    if isinstance(organization, str) and organization.strip():
        return normalize_workspace_id(organization)
    return "default"


def workspace_path(workspace_id: str) -> Path:
    return WORKSPACES_DIR / normalize_workspace_id(workspace_id)


@contextmanager
def workspace_lock(workspace_id: str, timeout_seconds: float | None = None):
    # Synapse supports Linux/macOS local operation; fcntl.flock gives a simple
    # per-workspace advisory lock across MCP server processes.
    wid = normalize_workspace_id(workspace_id)
    held = getattr(_LOCK_STATE, "held_workspace_locks", set())
    if wid in held:
        yield
        return
    timeout = DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS if timeout_seconds is None else float(timeout_seconds)
    root = workspace_path(wid)
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / ".lock"
    deadline = time.monotonic() + max(timeout, 0.0)
    with lock_path.open("a+", encoding="utf-8") as handle:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.add(wid)
                _LOCK_STATE.held_workspace_locks = held
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise McpError(-32000, f"Timed out waiting for workspace lock for {wid} after {timeout:.1f}s.") from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            held.discard(wid)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def target_path(workspace_id: str, target: str) -> Path:
    return workspace_path(workspace_id) / "targets" / slug(normalize_target(target))


def target_entity_dir(workspace_id: str, target: str) -> Path:
    root = target_path(workspace_id, target) / "entities"
    root.mkdir(parents=True, exist_ok=True)
    return root


def target_entity_path(workspace_id: str, target: str, entity_name: str) -> Path:
    filename = ENTITY_FILES.get(entity_name)
    if not filename:
        raise McpError(-32602, f"Unknown target entity: {entity_name}")
    return target_entity_dir(workspace_id, target) / filename


def timestamped_filename(suffix: str) -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"{timestamp}-{suffix}"


def workspace_output_path(workspace_id: str, tool: str, suffix: str) -> Path:
    root = workspace_path(workspace_id) / "outputs" / slug(tool)
    root.mkdir(parents=True, exist_ok=True)
    return root / timestamped_filename(suffix)


def target_output_dir(workspace_id: str, target: str, tool: str) -> Path:
    root = target_path(workspace_id, target) / "outputs" / slug(tool)
    root.mkdir(parents=True, exist_ok=True)
    return root


def target_output_path(workspace_id: str, target: str, tool: str, suffix: str) -> Path:
    return target_output_dir(workspace_id, target, tool) / timestamped_filename(suffix)


def retain_latest_artifacts(
    directory: Path,
    suffix: str,
    *,
    keep: int = 1,
    sibling_suffixes: tuple[str, ...] = (),
) -> list[str]:
    if keep < 1 or not directory.exists():
        return []
    matches = sorted(directory.glob(f"*-{suffix}"), key=lambda path: path.name)
    removed: list[str] = []
    for path in matches[: max(len(matches) - keep, 0)]:
        for candidate in (path, *(path.with_name(f"{path.stem}{sibling}") for sibling in sibling_suffixes)):
            try:
                if candidate.exists() and candidate.is_file():
                    candidate.unlink()
                    removed.append(str(candidate))
            except OSError:
                continue
    return removed


def target_model_dir(workspace_id: str, target: str, model: str = "") -> Path:
    root = target_path(workspace_id, target) / "models"
    if model:
        root = root / slug(model)
    root.mkdir(parents=True, exist_ok=True)
    return root


def target_model_path(workspace_id: str, target: str, filename: str) -> Path:
    root = target_model_dir(workspace_id, target)
    return root / filename


def scope_status_for_target(target: str) -> dict[str, Any]:
    host = normalize_target(target)
    current_scope = scope.load_scope()
    has_scope = any(current_scope.get(name) for name in ("hosts", "patterns", "cidrs"))
    if not has_scope:
        return {
            "scopeStatus": "scope_unset",
            "scopeReason": "No persisted scope hosts, patterns, or CIDRs are configured.",
            "scope": current_scope,
        }
    checked = scope.check_target(host)
    match = checked.get("match", {})
    if checked.get("inScope"):
        match_type = match.get("type", "unknown")
        value = match.get("value", host)
        return {
            "scopeStatus": "in_scope",
            "scopeReason": f"Matched {match_type} scope entry {value}.",
            "scope": checked,
        }
    return {
        "scopeStatus": "out_of_scope",
        "scopeReason": f"No scope entry matched target host {host}.",
        "scope": checked,
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def list_workspaces() -> dict[str, Any]:
    workspaces = []
    if WORKSPACES_DIR.exists():
        for candidate in sorted(WORKSPACES_DIR.iterdir()):
            if not candidate.is_dir():
                continue
            meta = _read_json(candidate / "workspace.json", {})
            if meta:
                workspaces.append(meta)
    return {"workspaces": workspaces}


def _normalize_scope_snapshot(
    hosts: list[str] | None = None,
    patterns: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    normalized_hosts = sorted({normalize_target(host) for host in hosts or [] if normalize_target(host)})
    normalized_patterns = sorted({pattern.strip().lower() for pattern in patterns or [] if isinstance(pattern, str) and pattern.strip()})
    normalized_cidrs = sorted({cidr.strip() for cidr in cidrs or [] if isinstance(cidr, str) and cidr.strip()})
    if normalized_hosts:
        payload["hosts"] = normalized_hosts
    if normalized_patterns:
        payload["patterns"] = normalized_patterns
    if normalized_cidrs:
        payload["cidrs"] = normalized_cidrs
    return payload


def workspace_scope(workspace_id: str) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    if not wid:
        return {}
    payload = _read_json(workspace_path(wid) / "scope.json", {})
    return payload if isinstance(payload, dict) else {}


def create_workspace(
    workspace_id: str,
    organization: str = "",
    notes: str = "",
    hosts: list[str] | None = None,
    patterns: list[str] | None = None,
    cidrs: list[str] | None = None,
) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    if not wid:
        raise McpError(-32602, "workspaceId is required.")
    path = workspace_path(wid)
    existing = _read_json(path / "workspace.json", {})
    created = not bool(existing)
    created_at = existing.get("createdAt") or now_utc()
    scope_snapshot = _normalize_scope_snapshot(hosts, patterns, cidrs)
    normalized_hosts = scope_snapshot.get("hosts", [])
    payload = {
        "workspaceId": wid,
        "organization": organization or existing.get("organization", ""),
        "notes": notes or existing.get("notes", ""),
        "createdAt": created_at,
        "updatedAt": now_utc(),
    }
    _write_json(path / "workspace.json", payload)
    (path / "targets").mkdir(parents=True, exist_ok=True)
    if scope_snapshot:
        _write_json(path / "scope.json", {**scope_snapshot, "updatedAt": payload["updatedAt"]})
        for host in normalized_hosts:
            add_target(wid, host)
    evidence.log_event(
        "workspace.create",
        f"{'Created' if created else 'Updated'} workspace {wid}.",
        {
            "workspaceId": wid,
            "organization": payload["organization"],
            "hosts": normalized_hosts,
            "notes": payload["notes"],
            "path": str(path),
            "created": created,
        },
    )
    return {"created": created, "workspaceId": wid, "workspace": payload, "path": str(path)}


def ensure_workspace(workspace_id: str | None = None, organization: str = "", notes: str = "") -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id or default_workspace_id())
    existing = _read_json(workspace_path(wid) / "workspace.json", {})
    if existing:
        return {"workspaceId": wid, "workspace": existing, "path": str(workspace_path(wid))}
    return create_workspace(wid, organization=organization, notes=notes)


def add_target(workspace_id: str, target: str, kind: str = "host", notes: str = "") -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    if not host:
        raise McpError(-32602, "target must include a hostname or IP.")
    path = target_path(wid, host)
    existing = _read_json(path / "target.json", {})
    created = not bool(existing)
    created_at = existing.get("createdAt") or now_utc()
    payload = {
        "workspaceId": wid,
        "target": host,
        "kind": kind or existing.get("kind", "host"),
        "notes": notes or existing.get("notes", ""),
        "createdAt": created_at,
        "updatedAt": now_utc(),
    }
    _write_json(path / "target.json", payload)
    (path / "evidence").mkdir(parents=True, exist_ok=True)
    for entity_name in ENTITY_FILES:
        entity_path = target_entity_path(wid, host, entity_name)
        if not entity_path.exists():
            _write_json(entity_path, [])
    if not (path / "evidence" / "findings.md").exists():
        write_findings_markdown(wid, host)
    if created:
        evidence.log_event(
            "workspace.add_target",
            f"Added target {host} to workspace {wid}.",
            {"workspaceId": wid, "target": host, "kind": payload["kind"], "notes": payload["notes"], "path": str(path)},
        )
    return {"added": created, "target": payload, "path": str(path)}


def _markdown_escape(value: Any) -> str:
    return str(value or "").replace("|", "\\|").strip()


def render_findings_markdown(workspace_id: str, target: str) -> str:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    findings = _read_json(target_entity_path(wid, host, "findings"), [])
    if not isinstance(findings, list):
        findings = []

    lines = [
        f"# Vulnerability Findings for {host}",
        "",
        f"- Workspace: `{wid}`",
        f"- Updated: `{now_utc()}`",
        f"- Finding count: `{len(findings)}`",
        "",
    ]
    if not findings:
        lines.extend(["No findings have been recorded for this target yet.", ""])
        return "\n".join(lines)

    lines.extend(["| Status | Severity | Confidence | Title | Evidence |", "| --- | --- | --- | --- | --- |"])
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        evidence_ids = finding.get("evidenceIds", [])
        evidence_text = (
            ", ".join(str(item) for item in evidence_ids)
            if isinstance(evidence_ids, list)
            else str(evidence_ids or "")
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_escape(finding.get("status", "confirmed")),
                    _markdown_escape(finding.get("severity", "info")),
                    _markdown_escape(finding.get("confidence", "unknown")),
                    _markdown_escape(finding.get("title", "Untitled finding")),
                    _markdown_escape(evidence_text),
                ]
            )
            + " |"
        )

    for index, finding in enumerate([item for item in findings if isinstance(item, dict)], start=1):
        title = finding.get("title", "Untitled finding")
        lines.extend(
            [
                "",
                f"## {index}. {title}",
                "",
                f"- Status: `{finding.get('status', 'confirmed')}`",
                f"- Severity: `{finding.get('severity', 'info')}`",
                f"- Confidence: `{finding.get('confidence', 'unknown')}`",
                f"- Operator reviewed: `{bool(finding.get('operatorReviewed', False))}`",
            ]
        )
        if finding.get("id"):
            lines.append(f"- Finding ID: `{finding.get('id')}`")
        evidence_ids = finding.get("evidenceIds", [])
        if evidence_ids:
            lines.append(f"- Evidence IDs: `{', '.join(str(item) for item in evidence_ids)}`")
        for label, field in (("Impact", "impact"), ("Remediation", "remediation")):
            value = str(finding.get(field, "")).strip()
            if value:
                lines.extend(["", f"### {label}", "", value])
        reproduction_steps = finding.get("reproductionSteps", [])
        if isinstance(reproduction_steps, list) and reproduction_steps:
            lines.extend(["", "### Reproduction Steps", ""])
            lines.extend([f"{step_index}. {step}" for step_index, step in enumerate(reproduction_steps, start=1)])
        description = str(finding.get("description", "")).strip()
        if description:
            lines.extend(["", "### Description", "", description])
    lines.append("")
    return "\n".join(lines)


def write_findings_markdown(workspace_id: str, target: str) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    path = target_path(wid, host) / "evidence" / "findings.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_findings_markdown(wid, host)
    path.write_text(content, encoding="utf-8")
    return {"path": str(path), "bytes": len(content.encode("utf-8"))}


def _stable_hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:16]


def _entity_key(entity: dict[str, Any]) -> str:
    # Keys must be derived from stable content fields only. Mutable fields such
    # as evidenceIds change between ingests of the same data and would break
    # deduplication.
    if entity.get("key"):
        return str(entity["key"])
    entity_type = entity.get("type", "")
    if entity_type == "service":
        return f"service:{entity.get('host', '')}|{entity.get('address', '')}|{entity.get('port', '')}|{entity.get('protocol', '')}"
    if entity_type == "endpoint":
        if entity.get("graphqlOperation"):
            return f"endpoint:{entity.get('method', '')}|{entity.get('url', '')}|graphql:{entity.get('graphqlOperationType', '')}:{entity.get('graphqlOperation', '')}"
        return f"endpoint:{entity.get('method', '')}|{entity.get('url', '')}"
    if entity_type == "parameter":
        if entity.get("graphqlOperation"):
            return f"parameter:{entity.get('method', '')}|{entity.get('url', '')}|graphql:{entity.get('graphqlOperationType', '')}:{entity.get('graphqlOperation', '')}|{entity.get('name', '')}"
        return f"parameter:{entity.get('method', '')}|{entity.get('url', '')}|{entity.get('location', '')}|{entity.get('name', '')}"
    if entity_type == "finding":
        if entity.get("id"):
            return f"finding:{entity['id']}"
        return f"finding:title:{entity.get('title', '')}"
    if entity.get("actionId"):
        return f"action:{entity['actionId']}"
    for id_field in ("id", "candidateId"):
        if entity.get(id_field):
            return f"{entity_type}:{entity[id_field]}"
    if entity_type and entity.get("value") not in ("", None):
        discriminator = "|".join(str(entity.get(field, "")) for field in ("value", "url", "parameter", "method"))
        return f"{entity_type}:{discriminator}"
    if entity.get("title"):
        return f"{entity_type}:title:{entity['title']}"
    return json.dumps(entity, sort_keys=True, ensure_ascii=False)


_MERGE_UNION_FIELDS = {
    "evidenceIds",
    "missingEvidenceIds",
    "statusCodes",
    "cookieNames",
    "responseCookieNames",
    "responseCookieFlags",
    "contentTypes",
    "requestContentTypes",
    "authorizationSchemes",
    "redirectLocations",
    "queryParameters",
    "bodyParameters",
    "jsonParameters",
    "errorSignals",
    "tags",
    "reasons",
    "affectedUrls",
    "candidateFor",
}
_MERGE_REPLACE_FIELDS = {"updatedAt", "lastSeenAt"}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _merge_entity_fields(merged: dict[str, Any], item: dict[str, Any]) -> None:
    for name, value in item.items():
        if name in _MERGE_UNION_FIELDS:
            current = merged.get(name)
            current_list = current if isinstance(current, list) else ([] if current in ("", None) else [current])
            merged[name] = current_list + [entry for entry in (value if isinstance(value, list) else [value]) if entry not in current_list]
        elif name in _MERGE_REPLACE_FIELDS:
            if value not in ("", None):
                merged[name] = value
        elif name == "severity":
            # Severity only escalates automatically; operator-reviewed records
            # keep whatever the operator decided.
            current_rank = _SEVERITY_RANK.get(str(merged.get("severity", "") or ""), -1)
            incoming_rank = _SEVERITY_RANK.get(str(value or ""), -1)
            if incoming_rank > current_rank and not merged.get("operatorReviewed"):
                merged[name] = value
        elif name == "isReportable":
            # Reportability is an operator/agent disposition, not adapter data. Every
            # re-ingest carries the default True; it must never override a stored
            # decision (especially a False that suppressed a reviewed false positive).
            # Preserve whatever is already stored; only seed legacy records missing it.
            if "isReportable" not in merged:
                merged[name] = value
        elif name == "candidateDetails" and isinstance(value, dict):
            # One consolidated test_candidate accumulates per-vuln-class detail as each
            # injection adapter contributes its class; keep the first detail per class.
            current = merged.get("candidateDetails")
            current = current if isinstance(current, dict) else {}
            for vuln_class, detail in value.items():
                current.setdefault(vuln_class, detail)
            merged["candidateDetails"] = current
        elif name == "priorityScore" and merged.get("type") == "test_candidate":
            merged[name] = max(int(merged.get(name, 0) or 0), int(value or 0))
        elif name == "priority" and merged.get("type") == "test_candidate":
            current_rank = _SEVERITY_RANK.get(str(merged.get("priority", "") or ""), -1)
            incoming_rank = _SEVERITY_RANK.get(str(value or ""), -1)
            if incoming_rank > current_rank:
                merged[name] = value
        elif value not in ("", None, [], {}) and not merged.get(name):
            merged[name] = value
    # A class refuted by the validation lifecycle must not be resurrected by a later
    # re-scan: keep candidateFor free of classes marked refuted in candidateDetails.
    if merged.get("type") == "test_candidate" and isinstance(merged.get("candidateFor"), list):
        details = merged.get("candidateDetails") if isinstance(merged.get("candidateDetails"), dict) else {}
        refuted = {cls for cls, detail in details.items() if isinstance(detail, dict) and detail.get("validationStatus") == "refuted"}
        if refuted:
            merged["candidateFor"] = [cls for cls in merged["candidateFor"] if cls not in refuted]


def _merge_entities(path: Path, new_entities: list[dict[str, Any]], evidence_id: str) -> tuple[list[dict[str, Any]], int]:
    existing = _read_json(path, [])
    if not isinstance(existing, list):
        existing = []
    by_key = {_entity_key(item): item for item in existing if isinstance(item, dict)}
    created = 0
    for entity in new_entities:
        if not isinstance(entity, dict):
            continue
        item = dict(entity)
        item.setdefault("firstSeenAt", now_utc())
        item["lastSeenAt"] = now_utc()
        item.setdefault("evidenceIds", [])
        # Every persisted entity is reportable by default. Operators/agents flip this
        # to False (via set_entity_reportable) to keep a reviewed record out of the
        # generated reports without deleting it or weakening workspace state.
        item.setdefault("isReportable", True)
        if evidence_id and evidence_id not in item["evidenceIds"]:
            item["evidenceIds"].append(evidence_id)
        key = _entity_key(item)
        if key in by_key:
            merged = by_key[key]
            _merge_entity_fields(merged, item)
        else:
            by_key[key] = item
            created += 1
    merged_items = sorted(by_key.values(), key=lambda item: _entity_key(item))
    _write_json(path, merged_items)
    return merged_items, created


# Entity normalization happens in two phases. Phase 1 is context-free
# structural normalization at the adapter/parser boundary: canonical type,
# list-shaped list fields, and id/key mirroring. Phase 2 is workspace-aware
# normalization during ingestion, where workspace_id and target are available:
# timestamps, default affected assets, evidence validation, and enum
# enforcement. Merge/deduplication stays a pure merge and never invents
# authoritative fields.

_ENTITY_TYPE_DEFAULTS = {
    "services": "service",
    "endpoints": "endpoint",
    "parameters": "parameter",
    "findings": "finding",
    "actions": "action",
    "observations": "observation",
}
_ENTITY_LIST_FIELDS = (
    "evidenceIds",
    "missingEvidenceIds",
    "tags",
    "reasons",
    "affectedAssets",
    "affectedUrls",
    "candidateFor",
    "reproductionSteps",
    "statusCodes",
    "cookieNames",
    "responseCookieNames",
    "responseCookieFlags",
    "contentTypes",
    "requestContentTypes",
    "authorizationSchemes",
    "redirectLocations",
    "queryParameters",
    "bodyParameters",
    "jsonParameters",
    "errorSignals",
)
OBSERVATION_PRIORITIES = {"info", "low", "medium", "high", "critical"}
# Common candidate validation lifecycle, shared by every layer of the DATA model.
# A candidate observation (consolidated web test_candidate or any single-class
# *_candidate) moves through these states as tests/decisions accumulate.
CANDIDATE_VALIDATION_OUTCOMES = {"proposed", "testing", "confirmed", "refuted", "inconclusive"}


def _normalize_entity_structure(entity: dict[str, Any], entity_name: str) -> dict[str, Any]:
    item = dict(entity)
    if not str(item.get("type", "") or "") and entity_name in _ENTITY_TYPE_DEFAULTS:
        item["type"] = _ENTITY_TYPE_DEFAULTS[entity_name]
    for field in _ENTITY_LIST_FIELDS:
        if field in item and not isinstance(item[field], list):
            item[field] = [] if item[field] in ("", None) else [item[field]]
    if entity_name == "findings" and item.get("id") and not item.get("key"):
        item["key"] = f"finding:{item['id']}"
    if entity_name == "actions" and item.get("actionId") and not item.get("key"):
        item["key"] = str(item["actionId"])
    return item


def _normalize_entities_for_workspace(
    workspace_id: str,
    target: str,
    entity_name: str,
    entities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        _normalize_entity_for_workspace(workspace_id, target, entity_name, item)
        for item in entities
        if isinstance(item, dict)
    ]


def _normalize_entity_for_workspace(workspace_id: str, target: str, entity_name: str, entity: dict[str, Any]) -> dict[str, Any]:
    item = _normalize_entity_structure(entity, entity_name)
    if entity_name == "findings":
        return _normalize_finding_for_workspace(workspace_id, target, item)
    if entity_name == "actions":
        return _normalize_action_for_workspace(item)
    if entity_name == "observations":
        return _normalize_observation_for_workspace(item)
    if entity_name == "endpoints":
        return _normalize_endpoint_for_workspace(item)
    return item


def _normalize_finding_for_workspace(workspace_id: str, target: str, finding: dict[str, Any]) -> dict[str, Any]:
    item = dict(finding)
    title = str(item.get("title", "") or "Untitled finding")
    item["title"] = title
    if item.get("severity") not in FINDING_SEVERITIES:
        item["severity"] = "info"
    if item.get("status") not in FINDING_STATUSES:
        item["status"] = "candidate"
    if item.get("confidence") not in FINDING_CONFIDENCES:
        item["confidence"] = "low"
    if not item.get("key"):
        item["key"] = f"finding:{item['id']}" if item.get("id") else f"finding:title:{title}"
    if not item.get("id"):
        item["id"] = _generate_finding_id(title)
    item.setdefault("operatorReviewed", False)
    if not item.get("affectedAssets"):
        item["affectedAssets"] = [normalize_target(target)]
    else:
        item["affectedAssets"] = sorted({_normalize_affected_asset(item) for item in item.get("affectedAssets", []) if _normalize_affected_asset(item)})
    evidence_ids = [str(entry) for entry in item.get("evidenceIds", []) if entry]
    item["evidenceIds"] = evidence_ids
    item["missingEvidenceIds"] = _missing_evidence_ids(workspace_id, target, evidence_ids)
    item.setdefault("createdAt", now_utc())
    item["updatedAt"] = now_utc()
    return item


def _normalize_affected_asset(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return normalize_target(text)


def _normalize_action_for_workspace(action: dict[str, Any]) -> dict[str, Any]:
    item = dict(action)
    if not item.get("actionId"):
        # A content-derived id keeps re-ingested transcripts deduplicable.
        item["actionId"] = "act_" + _stable_hash(
            item.get("tool", ""),
            item.get("target", ""),
            item.get("summary", ""),
            item.get("type", ""),
            item.get("startedAt") or item.get("createdAt") or "",
        )
    item.setdefault("key", str(item["actionId"]))
    item.setdefault("createdAt", now_utc())
    return item


def _normalize_observation_for_workspace(observation: dict[str, Any]) -> dict[str, Any]:
    item = dict(observation)
    if not str(item.get("type", "") or ""):
        item["type"] = "observation"
    if item.get("confidence") not in FINDING_CONFIDENCES:
        item["confidence"] = "low"
    if item.get("priority") not in OBSERVATION_PRIORITIES:
        item["priority"] = "low"
    try:
        item["priorityScore"] = int(item.get("priorityScore", 0) or 0)
    except (TypeError, ValueError):
        item["priorityScore"] = 0
    reason = str(item.get("reason", "") or "")
    reasons = [str(entry) for entry in item.get("reasons", []) if str(entry)] if isinstance(item.get("reasons"), list) else []
    if reason and reason not in reasons:
        reasons.append(reason)
    item["reasons"] = reasons
    return item


def _normalize_endpoint_for_workspace(endpoint: dict[str, Any]) -> dict[str, Any]:
    item = dict(endpoint)
    item["method"] = str(item.get("method", "GET") or "GET").upper()
    url = str(item.get("url", "") or "")
    if url:
        parsed = urlsplit(url)
        if not item.get("host"):
            item["host"] = parsed.hostname or ""
        if not item.get("path"):
            item["path"] = parsed.path or "/"
    return item


def _extension_for_format(format_name: str, source: str) -> str:
    fmt = (format_name or "").lower()
    if fmt in {"json", "jsonl", "xml", "txt", "text"}:
        return "txt" if fmt == "text" else fmt
    if source.lower() == "nmap":
        return "xml"
    return "txt"


def store_raw_evidence(
    workspace_id: str,
    target: str,
    source: str,
    data_type: str,
    format_name: str,
    raw_data: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_dir = target_path(workspace_id, target) / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    evidence_id = f"ev_{stamp}_{time.time_ns() % 1_000_000:06d}_{slug(source)[:32]}"
    extension = _extension_for_format(format_name, source)
    raw_path = evidence_dir / f"{evidence_id}_raw.{extension}"
    meta_path = evidence_dir / f"{evidence_id}.json"
    raw_path.write_text(raw_data, encoding="utf-8", errors="replace")
    payload = {
        "evidenceId": evidence_id,
        "workspaceId": workspace_id,
        "target": normalize_target(target),
        "source": source,
        "dataType": data_type,
        "format": format_name,
        "rawPath": str(raw_path),
        "metadata": evidence.sanitize_data(metadata or {}),
        "createdAt": now_utc(),
    }
    _write_json(meta_path, payload)
    return payload


def prune_generated_evidence(
    workspace_id: str,
    target: str,
    *,
    source: str,
    data_type: str,
    keep: int = 1,
    preserve_evidence_id: str = "",
) -> dict[str, Any]:
    if keep < 1:
        keep = 1
    evidence_dir = target_path(workspace_id, target) / "evidence"
    records = []
    for meta_path in sorted(evidence_dir.glob("ev_*.json")):
        payload = _read_json(meta_path, {})
        if not isinstance(payload, dict):
            continue
        if payload.get("source") != source or payload.get("dataType") != data_type:
            continue
        records.append((str(payload.get("createdAt", "")), str(payload.get("evidenceId", "")), meta_path, payload))
    records.sort(key=lambda item: (item[0], item[1]))
    protected = {preserve_evidence_id} if preserve_evidence_id else set()
    removable = [item for item in records if item[1] not in protected]
    retain_count = max(keep - len(protected), 0)
    to_remove = removable[: max(len(removable) - retain_count, 0)]
    removed_ids: list[str] = []
    removed_paths: list[str] = []
    for _created_at, evidence_id, meta_path, payload in to_remove:
        raw_path = Path(str(payload.get("rawPath", "")))
        for path in (raw_path, meta_path):
            try:
                if path.exists() and path.is_file():
                    path.unlink()
                    removed_paths.append(str(path))
            except OSError:
                continue
        if evidence_id:
            removed_ids.append(evidence_id)
    if removed_ids:
        _remove_evidence_ids_from_entities(workspace_id, target, set(removed_ids))
    return {"removedEvidenceIds": removed_ids, "removedPaths": removed_paths, "kept": max(len(records) - len(removed_ids), 0)}


def _remove_evidence_ids_from_entities(workspace_id: str, target: str, evidence_ids: set[str]) -> None:
    for entity_name in ENTITY_FILES:
        path = target_entity_path(workspace_id, target, entity_name)
        items = _read_json(path, [])
        if not isinstance(items, list):
            continue
        changed = False
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("evidenceIds"), list):
                continue
            kept = [ev_id for ev_id in item["evidenceIds"] if ev_id not in evidence_ids]
            if kept != item["evidenceIds"]:
                item["evidenceIds"] = kept
                changed = True
        if changed:
            _write_json(path, items)


def _parse_json(raw_data: str) -> Any:
    try:
        return json.loads(raw_data)
    except json.JSONDecodeError:
        return None


def _endpoint_from_url(url: str, method: str = "GET", extra: dict[str, Any] | None = None) -> dict[str, Any]:
    parsed = urlsplit(url)
    query_parameters = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return {
        "type": "endpoint",
        "url": url,
        "method": method or "GET",
        "host": (parsed.hostname or "").lower(),
        "path": parsed.path or "/",
        "queryParameters": query_parameters,
        **(extra or {}),
    }


def _parameters_from_url(url: str, method: str = "GET") -> list[dict[str, Any]]:
    parsed = urlsplit(url)
    params = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not name:
            continue
        param = {
            "type": "parameter",
            "name": name,
            "location": "query",
            "method": method or "GET",
            "url": url,
            "path": parsed.path or "/",
        }
        # The query value is already present verbatim in the stored url, so
        # surfacing a bounded preview adds no new exposure but lets value-aware
        # candidate scoring (SSRF/open-redirect/LFI/SSTI, access-control value
        # shape) actually fire instead of always seeing an empty value.
        if value:
            param["valuePreview"] = value[:120]
        params.append(param)
    return params


def _interesting_observations_for_endpoint(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    path = str(endpoint.get("path", "")).lower()
    status = endpoint.get("status")
    observations = []
    is_success = isinstance(status, int) and 200 <= status < 300
    if is_success and path.endswith(ARCHIVE_EXTENSIONS):
        observations.append(
            {
                "type": "sensitive_file_candidate",
                "value": endpoint.get("url", endpoint.get("path", "")),
                "confidence": "medium",
                "priority": "high",
                "priorityScore": 90,
                "reason": "Successful response for archive or backup-like extension.",
            }
        )
        observations.append(
            _sitemap_candidate(
                endpoint.get("url", endpoint.get("path", "")),
                "sensitive_file",
                "high",
                90,
                "Successful response for archive or backup-like extension.",
                {"method": endpoint.get("method", "GET"), "path": endpoint.get("path", "")},
            )
        )
    if is_success and any(marker in path for marker in INTERESTING_PATH_MARKERS):
        observations.append(
            {
                "type": "interesting_endpoint",
                "value": endpoint.get("url", endpoint.get("path", "")),
                "confidence": "low",
                "priority": "medium",
                "priorityScore": 60,
                "reason": "Path contains an admin, debug, backup, API documentation, or secret-related marker.",
            }
        )
        observations.append(
            _sitemap_candidate(
                endpoint.get("url", endpoint.get("path", "")),
                "interesting_endpoint",
                "medium",
                60,
                "Path contains an admin, debug, backup, API documentation, or secret-related marker.",
                {"method": endpoint.get("method", "GET"), "path": endpoint.get("path", "")},
            )
        )
    return observations


def _sitemap_candidate(
    value: Any,
    category: str,
    priority: str,
    priority_score: int,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "type": "sitemap_finding_candidate",
        "category": category,
        "value": value,
        "priority": priority,
        "priorityScore": priority_score,
        "confidence": "low",
        "reason": reason,
        **(extra or {}),
    }


def _form_candidate_observations(form: dict[str, Any], action: str, method: str, input_names: list[str]) -> list[dict[str, Any]]:
    lowered_action = action.lower()
    lowered_inputs = [name.lower() for name in input_names]
    candidates = [
        {
            "type": "form_endpoint",
            "value": action,
            "method": method,
            "pageUrl": form.get("pageUrl", ""),
            "inputNames": input_names,
            "confidence": "medium",
            "priority": "low",
            "priorityScore": 30,
            "reason": "Form was discovered in HTML and recorded without necessarily submitting it.",
        }
    ]
    if method == "POST":
        candidates.append(
            {
                "type": "post_form_candidate",
                "value": action,
                "pageUrl": form.get("pageUrl", ""),
                "inputNames": input_names,
                "confidence": "medium",
                "priority": "medium",
                "priorityScore": 65,
                "reason": "POST form was identified but not submitted to avoid mutating application state.",
            }
        )
    if any(marker in lowered_action for marker in HIGH_VALUE_FORM_PATH_MARKERS) or any(
        any(marker in name for marker in AUTH_FIELD_MARKERS) for name in lowered_inputs
    ):
        candidates.append(
            _sitemap_candidate(
                action,
                "high_value_form",
                "high" if method == "POST" else "medium",
                80 if method == "POST" else 55,
                "Form action or input names indicate authentication, account, upload, import/export, or admin workflow.",
                {"method": method, "pageUrl": form.get("pageUrl", ""), "inputNames": input_names},
            )
        )
    return candidates


def _burp_metadata_observations(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    url = str(endpoint.get("url", ""))
    observations: list[dict[str, Any]] = []
    if endpoint.get("stateChanging"):
        observations.append(
            {
                "type": "state_changing_method",
                "value": url,
                "method": endpoint.get("method", ""),
                "confidence": "medium",
                "priority": "medium",
                "priorityScore": 60,
                "reason": "Burp traffic observed a method commonly associated with state-changing workflows.",
            }
        )
    if endpoint.get("hasAuthorization"):
        observations.append(
            {
                "type": "authorization_header_observed",
                "value": url,
                "authorizationSchemes": endpoint.get("authorizationSchemes", []),
                "confidence": "medium",
                "priority": "medium",
                "priorityScore": 55,
                "reason": "Burp request included an Authorization header; values are not stored.",
            }
        )
    if endpoint.get("cookieNames"):
        observations.append(
            {
                "type": "cookie_names_observed",
                "value": url,
                "cookieNames": endpoint.get("cookieNames", []),
                "confidence": "medium",
                "priority": "low",
                "priorityScore": 35,
                "reason": "Burp request included cookies; only cookie names are stored.",
            }
        )
    if endpoint.get("authBoundary"):
        observations.append(
            {
                "type": "auth_boundary",
                "value": url,
                "statusCodes": endpoint.get("statusCodes", []),
                "redirectLocations": endpoint.get("redirectLocations", []),
                "confidence": "medium",
                "priority": "high",
                "priorityScore": 80,
                "reason": "Burp response indicated authentication or authorization boundary behavior.",
            }
        )
    for kind, priority, score, reason in (
        ("apiRoute", "medium", 55, "Burp traffic observed an API-like route."),
        ("jsonEndpoint", "medium", 55, "Burp traffic observed JSON request or response behavior."),
        ("graphqlEndpoint", "high", 75, "Burp traffic observed GraphQL-like path or request body fields."),
    ):
        if endpoint.get(kind):
            observations.append(
                {
                    "type": kind[0].lower() + re.sub(r"([A-Z])", r"_\1", kind[1:]).lower(),
                    "value": url,
                    "confidence": "medium",
                    "priority": priority,
                    "priorityScore": score,
                    "reason": reason,
                }
            )
    for location in endpoint.get("redirectLocations", []) if isinstance(endpoint.get("redirectLocations"), list) else []:
        observations.append(
            {
                "type": "redirect_observed",
                "value": url,
                "redirectLocation": location,
                "confidence": "medium",
                "priority": "low",
                "priorityScore": 40,
                "reason": "Burp response included a redirect Location header.",
            }
        )
    for item in endpoint.get("interestingErrors", []) if isinstance(endpoint.get("interestingErrors"), list) else []:
        if not isinstance(item, dict):
            continue
        observations.append(
            {
                "type": "interesting_error",
                "value": url,
                "status": item.get("status"),
                "signals": item.get("signals", []),
                "confidence": "medium",
                "priority": "high",
                "priorityScore": 85,
                "reason": "Burp response contained error status or error-message indicators.",
            }
        )
    return observations


def parse_ffuf(raw_data: str) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    results = payload.get("results", []) if isinstance(payload, dict) else []
    entities = {"endpoints": [], "parameters": [], "observations": []}
    for result in results:
        if not isinstance(result, dict):
            continue
        url = str(result.get("url") or "")
        if not url:
            continue
        endpoint = _endpoint_from_url(
            url,
            "GET",
            {
                "source": "ffuf",
                "status": result.get("status"),
                "length": result.get("length"),
                "words": result.get("words"),
                "lines": result.get("lines"),
                "contentType": result.get("content-type") or result.get("contentType", ""),
                "redirectLocation": result.get("redirectlocation", ""),
            },
        )
        entities["endpoints"].append(endpoint)
        entities["parameters"].extend(_parameters_from_url(url))
        entities["observations"].extend(_interesting_observations_for_endpoint(endpoint))
    return entities


def parse_sitemap(raw_data: str) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"endpoints": [], "parameters": [], "observations": []}
    if not isinstance(payload, dict):
        return entities
    for host in payload.get("hosts", []):
        if not isinstance(host, dict):
            continue
        for item in host.get("urls", []):
            if not isinstance(item, dict):
                continue
            methods = item.get("methods") or ["GET"]
            method = methods[0] if isinstance(methods, list) and methods else "GET"
            endpoint = _endpoint_from_url(
                str(item.get("url", "")),
                method,
                {
                    "source": "sitemap",
                    "statusCodes": item.get("statusCodes", []),
                    "contentTypes": item.get("contentTypes", []),
                    "title": item.get("title", ""),
                    "fetched": item.get("fetched", False),
                    "bodyParameters": item.get("bodyParameters", []),
                    "jsonParameters": item.get("jsonParameters", []),
                    "cookieNames": item.get("cookieNames", []),
                    "responseCookieNames": item.get("responseCookieNames", []),
                    "responseCookieFlags": item.get("responseCookieFlags", []),
                    "authorizationSchemes": item.get("authorizationSchemes", []),
                    "requestContentTypes": item.get("requestContentTypes", []),
                    "responseHeaders": item.get("responseHeaders", {}),
                    "technologySignals": item.get("technologySignals", []),
                    "redirectLocations": item.get("redirectLocations", []),
                    "interestingErrors": item.get("interestingErrors", []),
                    "errorSignals": item.get("errorSignals", []),
                    "observedRequests": item.get("observedRequests", []),
                    "hasAuthorization": bool(item.get("hasAuthorization")),
                    "apiRoute": bool(item.get("apiRoute")),
                    "jsonEndpoint": bool(item.get("jsonEndpoint")),
                    "graphqlEndpoint": bool(item.get("graphqlEndpoint")),
                    "stateChanging": bool(item.get("stateChanging")),
                    "authBoundary": bool(item.get("authBoundary")),
                },
            )
            entities["endpoints"].append(endpoint)
            entities["parameters"].extend(_parameters_from_url(endpoint["url"], method))
            for name in item.get("bodyParameters", []) if isinstance(item.get("bodyParameters"), list) else []:
                entities["parameters"].append(
                    {
                        "type": "parameter",
                        "name": str(name),
                        "location": "body",
                        "method": method,
                        "url": endpoint["url"],
                        "path": endpoint.get("path", ""),
                    }
                )
            for name in item.get("jsonParameters", []) if isinstance(item.get("jsonParameters"), list) else []:
                entities["parameters"].append(
                    {
                        "type": "parameter",
                        "name": str(name),
                        "location": "json",
                        "method": method,
                        "url": endpoint["url"],
                        "path": endpoint.get("path", ""),
                    }
                )
            for name in item.get("cookieNames", []) if isinstance(item.get("cookieNames"), list) else []:
                entities["parameters"].append(
                    {
                        "type": "parameter",
                        "name": str(name),
                        "location": "cookie",
                        "method": method,
                        "url": endpoint["url"],
                        "path": endpoint.get("path", ""),
                    }
                )
            if item.get("statusCodes"):
                endpoint_for_observation = dict(endpoint)
                endpoint_for_observation["status"] = item["statusCodes"][0]
                entities["observations"].extend(_interesting_observations_for_endpoint(endpoint_for_observation))
            entities["observations"].extend(_burp_metadata_observations(endpoint))
        for form in host.get("forms", []):
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", ""))
            method = str(form.get("method", "GET")).upper()
            inputs = [item for item in form.get("inputs", []) if isinstance(item, dict)]
            input_names = [str(item.get("name", "")) for item in inputs if item.get("name")]
            if action:
                entities["endpoints"].append(
                    _endpoint_from_url(
                        action,
                        method,
                        {
                            "source": "sitemap_form",
                            "pageUrl": form.get("pageUrl", ""),
                            "formId": form.get("id", ""),
                            "formName": form.get("name", ""),
                            "inputNames": input_names,
                            "fetched": False,
                        },
                    )
                )
            entities["observations"].extend(_form_candidate_observations(form, action, method, input_names))
            for input_item in form.get("inputs", []):
                if isinstance(input_item, dict) and input_item.get("name"):
                    parameter = {
                        "type": "parameter",
                        "name": input_item["name"],
                        "location": "form",
                        "method": method,
                        "url": action,
                        "inputType": input_item.get("type", ""),
                    }
                    preview = str(input_item.get("valuePreview", ""))[:120]
                    if preview:
                        parameter["valuePreview"] = preview
                    entities["parameters"].append(parameter)
    return entities


def parse_nmap(raw_data: str) -> dict[str, list[dict[str, Any]]]:
    entities = {"services": [], "observations": []}
    try:
        root = ElementTree.fromstring(raw_data)
    except ElementTree.ParseError:
        return entities
    for host_node in root.findall("host"):
        address = ""
        address_node = host_node.find("address")
        if address_node is not None:
            address = address_node.attrib.get("addr", "")
        hostnames = [
            hostname.attrib.get("name", "")
            for hostname in host_node.findall("./hostnames/hostname")
            if hostname.attrib.get("name")
        ]
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is not None and state_node.attrib.get("state") != "open":
                continue
            service_node = port_node.find("service")
            service = service_node.attrib if service_node is not None else {}
            entities["services"].append(
                {
                    "type": "service",
                    "host": hostnames[0] if hostnames else address,
                    "address": address,
                    "port": int(port_node.attrib.get("portid", "0") or 0),
                    "protocol": port_node.attrib.get("protocol", "tcp"),
                    "name": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                }
            )
    return entities


def parse_nuclei(raw_data: str) -> dict[str, list[dict[str, Any]]]:
    entities = {"endpoints": [], "observations": [], "findings": []}
    for line in raw_data.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        matched = str(item.get("matched-at") or item.get("matched") or item.get("host") or "")
        if matched:
            entities["endpoints"].append(
                _endpoint_from_url(
                    matched,
                    str(item.get("type") or "GET").upper() if str(item.get("type") or "").upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "GET",
                    {
                        "source": "nuclei",
                        "templateId": item.get("template-id", ""),
                        "matcherName": item.get("matcher-name", ""),
                    },
                )
            )
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(info.get("severity") or item.get("severity") or "info").lower()
        name = str(info.get("name") or item.get("template-id") or "Nuclei result")
        template_id = str(item.get("template-id") or "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        elif not isinstance(tags, list):
            tags = []
        observation = {
            "type": "nuclei_result",
            "value": matched or template_id,
            "templateId": template_id,
            "templatePath": item.get("template-path", ""),
            "name": name,
            "severity": severity,
            "confidence": "medium" if severity in {"critical", "high", "medium"} else "low",
            "priority": severity if severity in {"critical", "high", "medium", "low"} else "info",
            "priorityScore": {"critical": 95, "high": 85, "medium": 70, "low": 45, "info": 20}.get(severity, 20),
            "matchedAt": matched,
            "matcherName": item.get("matcher-name", ""),
            "extractedResults": item.get("extracted-results", []),
            "tags": tags,
            "reason": "Nuclei template matched this target; validate before treating as confirmed.",
        }
        entities["observations"].append(observation)
        # The id and key must stay stable across re-ingests of the same result
        # so deduplication merges instead of duplicating the finding.
        matched_target = normalize_target(matched) if matched else ""
        finding_fingerprint = _stable_hash("nuclei", template_id or name, matched)
        entities["findings"].append(
            {
                "type": "finding",
                "id": f"finding-nuclei-{finding_fingerprint}",
                "key": f"finding:nuclei:{template_id or slug(name)}|{matched_target or finding_fingerprint}",
                "title": f"Nuclei candidate: {name}",
                "status": "candidate",
                "severity": severity if severity in FINDING_SEVERITIES else "info",
                "confidence": observation["confidence"],
                "affectedAssets": [matched_target] if matched_target else [],
                "evidenceIds": [],
                "reproductionSteps": [
                    f"Review Nuclei template {template_id or name}.",
                    f"Validate the match against {matched or 'the scanned target'}.",
                ],
                "impact": str(info.get("description", "")),
                "remediation": str(info.get("remediation", "")),
                "description": str(info.get("description", "")),
                "operatorReviewed": False,
                "templateId": template_id,
                "matchedAt": matched,
                "tags": tags,
            }
        )
    return entities


def _service_from_shodan(
    host: str,
    port: Any,
    *,
    address: str = "",
    protocol: str = "tcp",
    name: str = "",
    product: str = "",
    version: str = "",
    source: str = "shodan",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return None
    return {
        "type": "service",
        "host": host,
        "address": address,
        "port": port_number,
        "protocol": protocol or "tcp",
        "name": name,
        "product": product,
        "version": version,
        "source": source,
        **(extra or {}),
    }


def _http_endpoint_for_service(host: str, port: int, http: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not host:
        return None
    http = http or {}
    scheme = "https" if port in {443, 8443} else "http"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if default_port else f"{host}:{port}"
    return _endpoint_from_url(
        f"{scheme}://{netloc}/",
        "GET",
        {
            "source": "shodan",
            "status": http.get("status"),
            "title": http.get("title"),
            "server": http.get("server"),
        },
    )


def parse_shodan(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"services": [], "endpoints": [], "observations": []}
    if not isinstance(payload, dict):
        return entities
    metadata = metadata or {}
    source_kind = str(metadata.get("sourceKind") or metadata.get("tool") or "shodan")
    _parse_shodan_domain(payload, entities)
    _parse_shodan_host_like(payload, entities, source_kind)
    _parse_shodan_search(payload, entities)
    _parse_shodan_target_summary(payload, entities)
    return entities


def parse_ssrf_analysis(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict):
        return entities
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        reasons = candidate.get("reasons", []) if isinstance(candidate.get("reasons"), list) else []
        entities["observations"].append(
            surface_candidate(
                vuln_class="ssrf",
                url=str(candidate.get("url", "")),
                method=str(candidate.get("method", "GET")),
                parameter=str(candidate.get("parameter", "")),
                location=str(candidate.get("location", "query")),
                reason=str(reasons[0]) if reasons else "SSRF candidate identified.",
                priority=str(candidate.get("priority", "low")),
                priority_score=int(candidate.get("priorityScore", 0) or 0),
                confidence=str(candidate.get("confidence", "low")),
                test_plan_summary=str(candidate.get("testPlanSummary", "")),
            )
        )
    return entities


def parse_open_redirect_analysis(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict):
        return entities
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        entities["observations"].append(
            {
                "type": "open_redirect_candidate",
                "value": candidate.get("url", ""),
                "candidateId": candidate.get("candidateId", ""),
                "parameter": candidate.get("parameter", ""),
                "method": candidate.get("method", ""),
                "location": candidate.get("location", ""),
                "priority": candidate.get("priority", "low"),
                "priorityScore": candidate.get("priorityScore", 0),
                "confidence": candidate.get("confidence", "low"),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            }
        )
    return entities


def parse_command_injection_analysis(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict):
        return entities
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        entities["observations"].append(
            {
                "type": "command_injection_candidate",
                "value": candidate.get("url", ""),
                "candidateId": candidate.get("candidateId", ""),
                "parameter": candidate.get("parameter", ""),
                "method": candidate.get("method", ""),
                "location": candidate.get("location", ""),
                "priority": candidate.get("priority", "low"),
                "priorityScore": candidate.get("priorityScore", 0),
                "confidence": candidate.get("confidence", "low"),
                "osFamily": candidate.get("osFamily", "unknown"),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            }
        )
    test = payload.get("test") if isinstance(payload.get("test"), dict) else payload
    if isinstance(test, dict) and test.get("assessment") == "possible_command_injection":
        candidate = test.get("candidate", {}) if isinstance(test.get("candidate"), dict) else {}
        metadata = metadata or {}
        entities["observations"].append(
            {
                "type": "possible_command_injection",
                "value": candidate.get("url", metadata.get("target", "")),
                "parameter": candidate.get("parameter", ""),
                "confidence": "medium",
                "priority": "high",
                "priorityScore": 85,
                "osFamily": test.get("osFamily", "unknown"),
                "reason": "Benign marker payload was observed in the response.",
            }
        )
    return entities


def parse_adapter_result(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {name: [] for name in ENTITY_FILES}
    if not isinstance(payload, dict):
        return entities
    source_entities = payload.get("entities")
    if not isinstance(source_entities, dict):
        return entities
    for entity_name in ENTITY_FILES:
        values = source_entities.get(entity_name, [])
        if not isinstance(values, list):
            continue
        entities[entity_name] = [_normalize_entity_structure(item, entity_name) for item in values if isinstance(item, dict)]
    return entities


def parse_ssti_test(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict) or payload.get("assessment") != "possible_ssti":
        return entities
    candidate = payload.get("candidate", {}) if isinstance(payload.get("candidate"), dict) else {}
    entities["observations"].append(
        {
            "type": "possible_ssti",
            "value": candidate.get("url", (metadata or {}).get("target", "")),
            "parameter": candidate.get("parameter", (metadata or {}).get("parameter", "")),
            "method": candidate.get("method", ""),
            "location": candidate.get("location", ""),
            "confidence": "medium",
            "priority": "high",
            "priorityScore": 80,
            "reason": "Approved benign SSTI probe indicated arithmetic evaluation or template-engine error behavior.",
        }
    )
    return entities


def parse_lfi_test(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict) or payload.get("assessment") != "file_handling_behavior_observed":
        return entities
    candidate = payload.get("candidate", {}) if isinstance(payload.get("candidate"), dict) else {}
    entities["observations"].append(
        {
            "type": "file_handling_behavior_observed",
            "value": candidate.get("url", (metadata or {}).get("target", "")),
            "parameter": candidate.get("parameter", (metadata or {}).get("parameter", "")),
            "method": candidate.get("method", ""),
            "location": candidate.get("location", ""),
            "confidence": "low",
            "priority": "medium",
            "priorityScore": 65,
            "reason": "Approved benign file-handling probes produced differing response behavior.",
        }
    )
    return entities


def parse_ssi_test(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict) or payload.get("assessment") not in {"possible_ssi", "html_sink_observed"}:
        return entities
    candidate = payload.get("candidate", {}) if isinstance(payload.get("candidate"), dict) else {}
    possible = payload.get("assessment") == "possible_ssi"
    entities["observations"].append(
        {
            "type": "possible_ssi" if possible else "html_sink_observed",
            "value": candidate.get("url", (metadata or {}).get("target", "")),
            "parameter": candidate.get("parameter", (metadata or {}).get("parameter", "")),
            "method": candidate.get("method", ""),
            "location": candidate.get("location", ""),
            "confidence": "medium" if possible else "low",
            "priority": "high" if possible else "low",
            "priorityScore": 75 if possible else 35,
            "reason": "Approved benign SSI probe indicated server-side parsing behavior." if possible else "Approved marker probe showed user-controlled input reaches an HTML sink.",
        }
    )
    return entities


def parse_cors_test(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"observations": []}
    if not isinstance(payload, dict) or payload.get("assessment") != "possible_cors_misconfiguration":
        return entities
    candidate = payload.get("candidate", {}) if isinstance(payload.get("candidate"), dict) else {}
    response = payload.get("response", {}) if isinstance(payload.get("response"), dict) else {}
    creds = bool(response.get("accessControlAllowCredentials"))
    entities["observations"].append(
        {
            "type": "possible_cors_misconfiguration",
            "value": candidate.get("url", (metadata or {}).get("target", "")),
            "method": candidate.get("method", ""),
            "confidence": "medium",
            "priority": "high" if creds else "medium",
            "priorityScore": 80 if creds else 60,
            "reason": "Approved CORS probe origin was reflected"
            + (" with credentials enabled." if creds else " in the response."),
        }
    )
    return entities


def parse_graphql_test(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    payload = _parse_json(raw_data)
    entities = {"endpoints": [], "parameters": [], "observations": []}
    if not isinstance(payload, dict) or payload.get("assessment") != "introspection_enabled":
        return entities
    source_entities = payload.get("entities")
    if isinstance(source_entities, dict):
        for entity_name in entities:
            values = source_entities.get(entity_name, [])
            if not isinstance(values, list):
                continue
            entities[entity_name] = [_normalize_entity_structure(item, entity_name) for item in values if isinstance(item, dict)]
    if not any(item.get("type") == "graphql_introspection_enabled" for item in entities["observations"] if isinstance(item, dict)):
        candidate = payload.get("candidate", {}) if isinstance(payload.get("candidate"), dict) else {}
        entities["observations"].append(
            {
                "type": "graphql_introspection_enabled",
                "value": candidate.get("url", (metadata or {}).get("target", "")),
                "method": "POST",
                "confidence": "high",
                "priority": "high",
                "priorityScore": 85,
                "reason": "Approved GraphQL introspection probe returned data.__schema.",
            }
        )
    return entities


def _parse_shodan_domain(payload: dict[str, Any], entities: dict[str, list[dict[str, Any]]]) -> None:
    domain = str(payload.get("domain") or "")
    records = payload.get("records", [])
    if not isinstance(records, list):
        return
    for record in records[:1000]:
        if not isinstance(record, dict):
            continue
        subdomain = record.get("subdomain")
        record_type = record.get("type")
        value = record.get("value")
        hostname = f"{subdomain}.{domain}".strip(".") if subdomain else domain
        if hostname and record_type in {"A", "AAAA"} and value:
            entities["observations"].append(
                {
                    "type": "ip_leakage_candidate",
                    "value": str(value),
                    "host": hostname,
                    "confidence": "medium",
                    "reason": "Shodan DNS data maps this hostname to an IP address.",
                }
            )
        if hostname:
            entities["observations"].append(
                {
                    "type": "dns_record",
                    "value": hostname,
                    "recordType": record_type,
                    "recordValue": value,
                    "confidence": "medium",
                    "reason": "Observed in Shodan DNS domain data.",
                }
            )


def _parse_shodan_host_like(payload: dict[str, Any], entities: dict[str, list[dict[str, Any]]], source_kind: str) -> None:
    ip = str(payload.get("ip") or payload.get("ip_str") or "")
    hostnames = [str(item) for item in payload.get("hostnames", []) if item] if isinstance(payload.get("hostnames"), list) else []
    ports = payload.get("ports", [])
    services = payload.get("services", [])
    if isinstance(ports, list):
        for port in ports[:1000]:
            service = _service_from_shodan(hostnames[0] if hostnames else ip, port, address=ip, source=source_kind)
            if service:
                entities["services"].append(service)
    if isinstance(services, list):
        for banner in services[:1000]:
            if not isinstance(banner, dict):
                continue
            service_hostnames = [str(item) for item in banner.get("hostnames", []) if item] if isinstance(banner.get("hostnames"), list) else []
            host = service_hostnames[0] if service_hostnames else (hostnames[0] if hostnames else ip)
            port = banner.get("port")
            service = _service_from_shodan(
                host,
                port,
                address=ip,
                protocol=str(banner.get("transport") or "tcp"),
                product=str(banner.get("product") or ""),
                version=str(banner.get("version") or ""),
                source=source_kind,
                extra={"domains": banner.get("domains", []), "timestamp": banner.get("timestamp")},
            )
            if service:
                entities["services"].append(service)
                entities["observations"].append(
                    {
                        "type": "exposed_service",
                        "value": f"{host}:{service['port']}",
                        "confidence": "medium",
                        "reason": "Observed in Shodan service banner data.",
                    }
                )
                endpoint = _http_endpoint_for_service(host, service["port"], banner.get("http") if isinstance(banner.get("http"), dict) else None)
                if endpoint:
                    entities["endpoints"].append(endpoint)
    _append_cve_observations(payload.get("vulns", []), entities, ip or ",".join(hostnames))
    _append_cpe_observations(payload.get("cpes", []), entities, ip or ",".join(hostnames))


def _parse_shodan_search(payload: dict[str, Any], entities: dict[str, list[dict[str, Any]]]) -> None:
    matches = payload.get("matches", [])
    if not isinstance(matches, list):
        return
    for match in matches[:1000]:
        if not isinstance(match, dict):
            continue
        ip = str(match.get("ip") or match.get("ip_str") or "")
        hostnames = [str(item) for item in match.get("hostnames", []) if item] if isinstance(match.get("hostnames"), list) else []
        host = hostnames[0] if hostnames else ip
        service = _service_from_shodan(
            host,
            match.get("port"),
            address=ip,
            protocol=str(match.get("transport") or "tcp"),
            product=str(match.get("product") or ""),
            version=str(match.get("version") or ""),
            source="shodan_search",
            extra={"org": match.get("org"), "asn": match.get("asn"), "domains": match.get("domains", []), "timestamp": match.get("timestamp")},
        )
        if not service:
            continue
        entities["services"].append(service)
        entities["observations"].append(
            {
                "type": "exposed_service",
                "value": f"{host}:{service['port']}",
                "confidence": "medium",
                "reason": "Observed in Shodan search results.",
            }
        )
        endpoint = _http_endpoint_for_service(host, service["port"], {"title": match.get("httpTitle")})
        if endpoint:
            entities["endpoints"].append(endpoint)


def _parse_shodan_target_summary(payload: dict[str, Any], entities: dict[str, list[dict[str, Any]]]) -> None:
    for ip in payload.get("ipLeakageCandidates", []) if isinstance(payload.get("ipLeakageCandidates"), list) else []:
        entities["observations"].append(
            {
                "type": "ip_leakage_candidate",
                "value": str(ip),
                "confidence": "medium",
                "reason": "Collected during Shodan target summary.",
            }
        )
    _append_cve_observations(payload.get("possibleCves", []), entities, str(payload.get("target") or ""))
    host = payload.get("host")
    if isinstance(host, dict):
        _parse_shodan_host_like(host, entities, "shodan_host")
    internetdb = payload.get("internetdb")
    if isinstance(internetdb, dict):
        for nested in internetdb.values():
            if isinstance(nested, dict):
                _parse_shodan_host_like(nested, entities, "shodan_internetdb")
    search = payload.get("search")
    if isinstance(search, dict):
        _parse_shodan_search(search, entities)
    domain = payload.get("domain")
    if isinstance(domain, dict):
        _parse_shodan_domain(domain, entities)


def _append_cve_observations(vulns: Any, entities: dict[str, list[dict[str, Any]]], target: str) -> None:
    values = vulns.keys() if isinstance(vulns, dict) else vulns
    if isinstance(values, str) or (not isinstance(values, list) and not hasattr(values, "__iter__")):
        return
    for cve in list(values)[:1000]:
        cve_text = str(cve)
        if not cve_text.startswith("CVE-"):
            continue
        entities["observations"].append(
            {
                "type": "possible_cve",
                "value": cve_text,
                "target": target,
                "confidence": "low",
                "reason": "Reported by Shodan/InternetDB and requires validation before being treated as a finding.",
            }
        )


def _append_cpe_observations(cpes: Any, entities: dict[str, list[dict[str, Any]]], target: str) -> None:
    if not isinstance(cpes, list):
        return
    for cpe in cpes[:1000]:
        entities["observations"].append(
            {
                "type": "cpe_observed",
                "value": str(cpe),
                "target": target,
                "confidence": "medium",
                "reason": "Observed in Shodan/InternetDB service metadata.",
            }
        )


def parse_operator_note(raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    metadata = metadata or {}
    return {
        "actions": [
            {
                "type": "operator_note",
                "summary": raw_data[:500],
                "category": metadata.get("category", "note"),
            }
        ]
    }


def parse_by_source(source: str, format_name: str, raw_data: str, metadata: dict[str, Any] | None = None) -> dict[str, list[dict[str, Any]]]:
    normalized = source.lower().replace("-", "_")
    if normalized in {"adapter_result", "synapse_adapter_result"}:
        return parse_adapter_result(raw_data, metadata)
    if normalized in {"ssti_test", "ssti.execute_test"}:
        return parse_ssti_test(raw_data, metadata)
    if normalized in {"lfi_test", "lfi.execute_test"}:
        return parse_lfi_test(raw_data, metadata)
    if normalized in {"ssi_test", "ssi.execute_test"}:
        return parse_ssi_test(raw_data, metadata)
    if normalized in {"cors_test", "cors.execute_test"}:
        return parse_cors_test(raw_data, metadata)
    if normalized in {"graphql_test", "graphql.execute_test"}:
        return parse_graphql_test(raw_data, metadata)
    if normalized == "ffuf":
        return parse_ffuf(raw_data)
    if normalized in {"sitemap", "crawler", "crawler_crawl", "sitemap_from_dump"}:
        return parse_sitemap(raw_data)
    if normalized == "nmap":
        return parse_nmap(raw_data)
    if normalized == "nuclei":
        return parse_nuclei(raw_data)
    if normalized.startswith("shodan"):
        return parse_shodan(raw_data, metadata)
    if normalized in {"ssrf", "ssrf_analysis", "ssrf.analyze_workspace"}:
        return parse_ssrf_analysis(raw_data, metadata)
    if normalized in {"open_redirect", "open_redirect_analysis", "redirect_analysis", "redirect.analyze_workspace"}:
        return parse_open_redirect_analysis(raw_data, metadata)
    if normalized in {"command_injection", "command_injection_analysis", "command_injection_test", "command_injection.analyze_workspace"}:
        return parse_command_injection_analysis(raw_data, metadata)
    if normalized in {"operator_note", "note"}:
        return parse_operator_note(raw_data, metadata)
    if format_name.lower() == "json":
        payload = _parse_json(raw_data)
        if isinstance(payload, dict) and isinstance(payload.get("entities"), dict):
            return parse_adapter_result(raw_data, metadata)
        if isinstance(payload, dict) and "hosts" in payload and "summary" in payload:
            return parse_sitemap(raw_data)
    return {}


def _compact_summary(target: str, counts: dict[str, int], observations: list[dict[str, Any]], source: str) -> str:
    pieces = [f"Ingested {source} data for {target}."]
    created = [f"{count} {name}" for name, count in counts.items() if count]
    if created:
        pieces.append("New entities: " + ", ".join(created) + ".")
    else:
        pieces.append("No new normalized entities were created.")
    if observations:
        first = observations[0]
        pieces.append(f"Most notable observation: {first.get('type')} on {first.get('value')} ({first.get('confidence', 'unknown')} confidence).")
    return " ".join(pieces)


def ingest_data(
    workspace_id: str | None,
    target: str,
    source: str,
    data_type: str,
    format_name: str,
    raw_data: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workspace = ensure_workspace(workspace_id)
    wid = workspace["workspaceId"]
    scope_context = scope_status_for_target(target)
    warnings: list[str] = []
    if scope_context["scopeStatus"] != "in_scope":
        warnings.append(f"Target scope status is {scope_context['scopeStatus']}: {scope_context['scopeReason']}")
    add_target(wid, target)
    evidence_record = store_raw_evidence(wid, target, source, data_type, format_name, raw_data, metadata)
    parsed_entities = parse_by_source(source, format_name, raw_data, metadata)
    counts = {name: 0 for name in ENTITY_FILES}
    stored: dict[str, list[dict[str, Any]]] = {}
    observations = parsed_entities.get("observations", [])
    retention: dict[str, Any] | None = None
    with workspace_lock(wid):
        for entity_name in ENTITY_FILES:
            path = target_entity_path(wid, target, entity_name)
            entities = parsed_entities.get(entity_name, [])
            if not entities:
                stored[entity_name] = _read_json(path, [])
                continue
            normalized_entities = _normalize_entities_for_workspace(wid, target, entity_name, entities)
            stored_entities, created = _merge_entities(path, normalized_entities, evidence_record["evidenceId"])
            counts[entity_name] = created
            stored[entity_name] = stored_entities

        findings_document = write_findings_markdown(wid, target) if counts.get("findings") else None
        retention_mode = str((metadata or {}).get("retentionMode") or "").lower()
        if retention_mode in {"latest", "replace", "replace_previous"} or (
            retention_mode != "keep_all" and source in DEFAULT_REPLACEABLE_EVIDENCE_SOURCES and data_type in {"tool_output", "js_static_analysis"}
        ):
            retention = prune_generated_evidence(
                wid,
                target,
                source=source,
                data_type=data_type,
                keep=int((metadata or {}).get("retentionKeep", 1) or 1),
                preserve_evidence_id=evidence_record["evidenceId"],
            )
    summary = _compact_summary(normalize_target(target), counts, observations, source)
    evidence.log_event(
        "workspace.ingest",
        summary,
        {
            "workspaceId": wid,
            "target": normalize_target(target),
            "source": source,
            **(metadata or {}),
            "scopeStatus": scope_context["scopeStatus"],
            "scopeReason": scope_context["scopeReason"],
            "evidenceId": evidence_record["evidenceId"],
            "rawPath": evidence_record["rawPath"],
            "entitiesCreated": counts,
            "retention": retention or {},
            "warnings": warnings,
        },
    )
    return {
        "ingestId": evidence_record["evidenceId"].replace("ev_", "ing_", 1),
        "workspaceId": wid,
        "target": normalize_target(target),
        "scopeStatus": scope_context["scopeStatus"],
        "scopeReason": scope_context["scopeReason"],
        "evidenceId": evidence_record["evidenceId"],
        "rawPath": evidence_record["rawPath"],
        "entitiesCreated": counts,
        "retention": retention or {},
        "warnings": warnings,
        "interestingObservations": observations[:10],
        "recommendedNextActions": recommended_next_actions(stored, observations),
        "llmSummary": summary,
        **({"findingsDocument": findings_document} if findings_document else {}),
    }


def recommended_next_actions(stored: dict[str, list[dict[str, Any]]], observations: list[dict[str, Any]]) -> list[dict[str, str]]:
    actions = []
    prioritized_observations = sorted(observations, key=lambda item: int(item.get("priorityScore", 0) or 0), reverse=True)
    for observation in prioritized_observations[:5]:
        if observation.get("type") == "sensitive_file_candidate":
            actions.append(
                {
                    "action": "request_operator_review",
                    "reason": f"Manually review potential sensitive file {observation.get('value')}.",
                    "risk": "medium",
                }
            )
        elif observation.get("type") == "interesting_endpoint":
            actions.append(
                {
                    "action": "manual_review",
                    "reason": f"Review interesting endpoint {observation.get('value')}.",
                    "risk": "low",
                }
            )
        elif observation.get("type") == "sitemap_finding_candidate":
            actions.append(
                {
                    "action": "manual_review",
                    "reason": f"Review {observation.get('category', 'candidate')} candidate {observation.get('value')}.",
                    "risk": observation.get("priority", "low"),
                }
            )
        elif observation.get("type") == "post_form_candidate":
            actions.append(
                {
                    "action": "workflow_mapping",
                    "reason": f"Map POST form {observation.get('value')} from {observation.get('pageUrl')} without submitting it.",
                    "risk": "low",
                }
            )
    if not actions and stored.get("parameters"):
        actions.append(
            {
                "action": "triage_parameters",
                "reason": "Review newly observed parameters for injection, authorization, and workflow relevance.",
                "risk": "low",
            }
        )
    return actions


def record_action(
    workspace_id: str,
    target: str,
    action: dict[str, Any],
    evidence_id: str = "",
) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    add_target(wid, host)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    action_id = action.get("actionId") or f"act_{stamp}_{time.time_ns() % 1_000_000:06d}"
    item = {
        "type": action.get("type", "action"),
        "key": action_id,
        "actionId": action_id,
        "createdAt": now_utc(),
        **action,
    }
    with workspace_lock(wid):
        _, created = _merge_entities(target_entity_path(wid, host, "actions"), [item], evidence_id)
    return {"created": bool(created), "workspaceId": wid, "target": host, "action": item}


def _load_target_entities(workspace_id: str, target: str) -> dict[str, list[dict[str, Any]]]:
    return {name: _read_json(target_entity_path(workspace_id, target, name), []) for name in ENTITY_FILES}


def is_reportable(entity: Any) -> bool:
    """Return False only when a record was explicitly dispositioned as non-reportable.

    Absent or True -> reportable (the default). Backward compatible: entities stored
    before the isReportable field existed have no flag and stay reportable.
    """
    return not (isinstance(entity, dict) and entity.get("isReportable") is False)


def load_reportable_target_entities(workspace_id: str, target: str) -> dict[str, list[dict[str, Any]]]:
    """Report-boundary view of a target's entities: full workspace state minus records
    explicitly marked isReportable=False.

    Only report/render/coverage code should call this. Agent- and operator-facing paths
    (prepare_target_context, workspace_summary, resource reads) must keep using
    _load_target_entities so workspace state stays rich and complete — reportability
    filtering belongs only at the report boundary.
    """
    return {
        name: [item for item in items if is_reportable(item)]
        for name, items in _load_target_entities(workspace_id, target).items()
    }


def prepare_target_context(workspace_id: str, target: str, purpose: str = "next_step_planning", max_tokens: int = 1500) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    entities = _load_target_entities(wid, host)
    scope_context = scope_status_for_target(host)
    endpoints = entities["endpoints"]
    services = entities["services"]
    observations = entities["observations"]
    prioritized_observations = sorted(observations, key=lambda item: int(item.get("priorityScore", 0) or 0), reverse=True)
    findings = entities["findings"]
    recent_actions = entities["actions"][-10:]
    interesting_endpoints = [
        endpoint
        for endpoint in endpoints
        if any(marker in str(endpoint.get("path", "")).lower() for marker in INTERESTING_PATH_MARKERS)
        or endpoint.get("queryParameters")
    ][:20]
    auth_surface = [
        item
        for item in endpoints
        if any(marker in str(item.get("path", "")).lower() for marker in HIGH_VALUE_FORM_PATH_MARKERS)
        or any(any(marker in str(name).lower() for marker in AUTH_FIELD_MARKERS) for name in item.get("inputNames", []))
    ][:20]
    state_changing_candidates = [
        item
        for item in endpoints
        if str(item.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}
    ][:20]
    candidate_findings = [
        item
        for item in findings
        if item.get("status") == "candidate" or item.get("operatorReviewed") is False
    ][:20]
    candidate_findings.extend([item for item in prioritized_observations if str(item.get("type", "")).endswith("_candidate")][:20])
    confirmed_findings = [
        item
        for item in findings
        if item.get("status", "confirmed") == "confirmed" and item.get("operatorReviewed", True) is not False
    ][:20]
    recommended = recommended_next_actions(entities, prioritized_observations)
    missing_information = []
    if scope_context["scopeStatus"] == "scope_unset":
        missing_information.append("Authorized scope has not been configured.")
    if not endpoints:
        missing_information.append("No endpoints are recorded for this target.")
    if not recent_actions:
        missing_information.append("No prior actions are recorded for this target.")
    summary = {
        "workspaceId": wid,
        "target": host,
        "purpose": purpose,
        "maxTokens": max_tokens,
        "scopeStatus": scope_context["scopeStatus"],
        "scopeReason": scope_context["scopeReason"],
        "knownServices": [
            {
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "name": item.get("name"),
                "product": item.get("product"),
                "version": item.get("version"),
            }
            for item in services[:30]
        ],
        "knownEndpoints": {
            "total": len(endpoints),
            "interesting": [
                {
                    "method": item.get("method"),
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "statusCodes": item.get("statusCodes"),
                    "queryParameters": item.get("queryParameters", []),
                }
                for item in interesting_endpoints
            ],
        },
        "interestingEndpoints": [
            {
                "method": item.get("method"),
                "url": item.get("url"),
                "status": item.get("status"),
                "statusCodes": item.get("statusCodes"),
                "queryParameters": item.get("queryParameters", []),
            }
            for item in interesting_endpoints
        ],
        "authSurface": auth_surface,
        "stateChangingCandidates": state_changing_candidates,
        "inputParameters": entities["parameters"][:50],
        "candidateFindings": candidate_findings[:30],
        "confirmedFindings": confirmed_findings,
        "parameters": {"total": len(entities["parameters"]), "sample": entities["parameters"][:30]},
        "potentialFindings": findings[:20],
        "observations": prioritized_observations[:20],
        "interestingCandidates": [item for item in prioritized_observations if item.get("type") == "sitemap_finding_candidate"][:10],
        "recentActions": recent_actions,
        "recommendedNextSteps": recommended,
        "recommendedNextActions": recommended,
        "missingInformation": missing_information,
    }
    return summary


def workspace_summary(workspace_id: str) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    path = workspace_path(wid)
    workspace = _read_json(path / "workspace.json", {})
    targets = []
    for target_dir in sorted((path / "targets").glob("*")) if (path / "targets").exists() else []:
        target_meta = _read_json(target_dir / "target.json", {})
        if not target_meta:
            continue
        entities_dir = target_dir / "entities"
        entities = {name: _read_json(entities_dir / filename, []) for name, filename in ENTITY_FILES.items()}
        targets.append(
            {
                "target": target_meta.get("target"),
                "serviceCount": len(entities["services"]),
                "endpointCount": len(entities["endpoints"]),
                "parameterCount": len(entities["parameters"]),
                "findingCount": len(entities["findings"]),
                "observationCount": len(entities["observations"]),
            }
        )
    return {"workspace": workspace, "targetCount": len(targets), "targets": targets}


def _directory_stats(path: Path) -> dict[str, int]:
    file_count = 0
    directory_count = 0
    total_bytes = 0
    if not path.exists():
        return {"fileCount": 0, "directoryCount": 0, "bytes": 0}
    for item in path.rglob("*"):
        if item.is_dir():
            directory_count += 1
        elif item.is_file():
            file_count += 1
            try:
                total_bytes += item.stat().st_size
            except OSError:
                continue
    return {"fileCount": file_count, "directoryCount": directory_count, "bytes": total_bytes}


def delete_workspace(workspace_id: str, confirm: bool = False) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    if not wid:
        raise McpError(-32602, "workspaceId is required.")
    path = workspace_path(wid)
    root = WORKSPACES_DIR.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise McpError(-32602, f"Workspace path is outside the workspaces directory: {resolved}") from exc
    if resolved == root:
        raise McpError(-32602, "Refusing to delete the workspaces root.")

    workspace_meta = _read_json(path / "workspace.json", {})
    target_count = len([item for item in (path / "targets").glob("*") if item.is_dir()]) if (path / "targets").exists() else 0
    stats = _directory_stats(path)
    plan = {
        "workspaceId": wid,
        "path": str(path),
        "exists": path.exists(),
        "workspace": workspace_meta,
        "targetCount": target_count,
        **stats,
    }
    if not confirm:
        return {
            "deleted": False,
            "requiresConfirmation": True,
            "message": "Review the workspace deletion plan, then call workspace.delete with confirm=true to permanently erase it.",
            **plan,
        }
    if not path.exists():
        return {"deleted": False, "requiresConfirmation": False, **plan}

    with workspace_lock(wid):
        evidence.log_event(
            "workspace.delete",
            f"Deleted workspace {wid}.",
            {
                "workspaceId": wid,
                "path": str(path),
                "workspace": workspace_meta,
                "targetCount": target_count,
                "fileCount": stats["fileCount"],
                "directoryCount": stats["directoryCount"],
                "bytes": stats["bytes"],
            },
        )
        shutil.rmtree(path)
    return {"deleted": True, "requiresConfirmation": False, **plan}


def _normalize_choice(value: str, allowed: set[str], default: str, field_name: str) -> str:
    normalized = str(value or default).strip().lower()
    if normalized not in allowed:
        raise McpError(-32602, f"{field_name} must be one of: {', '.join(sorted(allowed))}.")
    return normalized


def _generate_finding_id(title: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"finding-{stamp}-{time.time_ns() % 1_000_000:06d}-{slug(title)[:32]}"


def _load_findings(workspace_id: str, target: str) -> list[dict[str, Any]]:
    findings = _read_json(target_entity_path(workspace_id, target, "findings"), [])
    return findings if isinstance(findings, list) else []


def _write_findings(workspace_id: str, target: str, findings: list[dict[str, Any]]) -> None:
    _write_json(target_entity_path(workspace_id, target, "findings"), findings)


def _find_finding_index(findings: list[dict[str, Any]], finding_id: str) -> int:
    for index, finding in enumerate(findings):
        if isinstance(finding, dict) and (finding.get("id") == finding_id or finding.get("key") == finding_id):
            return index
    raise McpError(-32602, f"Finding not found: {finding_id}")


def _evidence_id_exists(workspace_id: str, target: str, evidence_id: str) -> bool:
    evidence_dir = target_path(workspace_id, target) / "evidence"
    return (evidence_dir / f"{evidence_id}.json").exists() or bool(list(evidence_dir.glob(f"{evidence_id}_raw.*")))


def _missing_evidence_ids(workspace_id: str, target: str, evidence_ids: list[str]) -> list[str]:
    return [item for item in evidence_ids if item and not _evidence_id_exists(workspace_id, target, item)]


def create_finding(
    workspace_id: str,
    target: str,
    title: str,
    severity: str = "info",
    confidence: str = "low",
    description: str = "",
    evidence_ids: list[str] | None = None,
    status: str = "confirmed",
    affected_assets: list[str] | None = None,
    reproduction_steps: list[str] | None = None,
    impact: str = "",
    remediation: str = "",
    operator_reviewed: bool = True,
) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    add_target(wid, host)
    normalized_evidence_ids = sorted({str(item) for item in evidence_ids or [] if str(item).strip()})
    missing_evidence_ids = _missing_evidence_ids(wid, host, normalized_evidence_ids)
    finding = {
        "type": "finding",
        "id": _generate_finding_id(title),
        "title": title,
        "status": _normalize_choice(status, FINDING_STATUSES, "confirmed", "status"),
        "severity": _normalize_choice(severity, FINDING_SEVERITIES, "info", "severity"),
        "confidence": _normalize_choice(confidence, FINDING_CONFIDENCES, "low", "confidence"),
        "affectedAssets": sorted({_normalize_affected_asset(item) for item in affected_assets or [host] if _normalize_affected_asset(item)}),
        "evidenceIds": normalized_evidence_ids,
        "missingEvidenceIds": missing_evidence_ids,
        "reproductionSteps": reproduction_steps or [],
        "impact": impact,
        "remediation": remediation,
        "description": description,
        "operatorReviewed": operator_reviewed,
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
    }
    finding["key"] = finding["id"]
    with workspace_lock(wid):
        _, created = _merge_entities(target_entity_path(wid, host, "findings"), [finding], "")
        findings_document = write_findings_markdown(wid, host)
    evidence.log_event(
        "workspace.finding",
        f"Recorded finding for {host}: {title}",
        {
            "workspaceId": wid,
            "target": host,
            "findingId": finding["id"],
            "title": title,
            "status": finding["status"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "missingEvidenceIds": missing_evidence_ids,
            "operatorReviewed": operator_reviewed,
        },
    )
    return {"created": bool(created), "workspaceId": wid, "target": host, "finding": finding, "findingsDocument": findings_document}


def update_finding(workspace_id: str, target: str, finding_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    allowed_fields = {
        "title",
        "status",
        "severity",
        "confidence",
        "description",
        "affectedAssets",
        "evidenceIds",
        "reproductionSteps",
        "impact",
        "remediation",
        "operatorReviewed",
    }
    with workspace_lock(wid):
        findings = _load_findings(wid, host)
        index = _find_finding_index(findings, finding_id)
        finding = dict(findings[index])
        for key, value in updates.items():
            if key not in allowed_fields:
                continue
            if key == "status":
                finding[key] = _normalize_choice(str(value), FINDING_STATUSES, "confirmed", "status")
            elif key == "severity":
                finding[key] = _normalize_choice(str(value), FINDING_SEVERITIES, "info", "severity")
            elif key == "confidence":
                finding[key] = _normalize_choice(str(value), FINDING_CONFIDENCES, "low", "confidence")
            elif key == "affectedAssets":
                finding[key] = sorted({_normalize_affected_asset(item) for item in value or [] if _normalize_affected_asset(item)})
            elif key in {"evidenceIds", "reproductionSteps"}:
                finding[key] = [str(item) for item in value or [] if str(item).strip()]
            elif key == "operatorReviewed":
                finding[key] = bool(value)
            else:
                finding[key] = value
        finding["updatedAt"] = now_utc()
        finding["missingEvidenceIds"] = _missing_evidence_ids(wid, host, [str(item) for item in finding.get("evidenceIds", [])])
        findings[index] = finding
        _write_findings(wid, host, findings)
        findings_document = write_findings_markdown(wid, host)
    evidence.log_event(
        "workspace.finding.update",
        f"Updated finding {finding_id} for {host}.",
        {"workspaceId": wid, "target": host, "findingId": finding_id, "updatedFields": sorted(set(updates) & allowed_fields)},
    )
    return {"updated": True, "workspaceId": wid, "target": host, "finding": finding, "findingsDocument": findings_document}


def _match_observation(observation: dict[str, Any], selector: dict[str, Any]) -> bool:
    if selector.get("observationId") and selector["observationId"] in {observation.get("id"), observation.get("key"), _entity_key(observation)}:
        return True
    if selector.get("observationKey") and selector["observationKey"] in {observation.get("key"), _entity_key(observation)}:
        return True
    if selector.get("type") and str(observation.get("type", "")) != str(selector["type"]):
        return False
    if selector.get("value") and str(observation.get("value", "")) != str(selector["value"]):
        return False
    return bool(selector.get("type") or selector.get("value"))


def promote_observation_to_finding(
    workspace_id: str,
    target: str,
    selector: dict[str, Any],
    title: str = "",
    severity: str = "info",
    confidence: str = "low",
    status: str = "candidate",
) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    observations = _read_json(target_entity_path(wid, host, "observations"), [])
    if not isinstance(observations, list):
        observations = []
    matched = next((item for item in observations if isinstance(item, dict) and _match_observation(item, selector)), None)
    if not matched:
        raise McpError(-32602, "Observation not found for the provided selector.")
    finding_title = title or f"Candidate: {matched.get('category') or matched.get('type', 'observation')} on {matched.get('value', host)}"
    result = create_finding(
        wid,
        host,
        finding_title,
        severity=severity,
        confidence=confidence,
        description=str(matched.get("reason", "")),
        evidence_ids=[str(item) for item in matched.get("evidenceIds", [])],
        status=status,
        affected_assets=[host],
        operator_reviewed=False,
    )
    result["observation"] = matched
    evidence.log_event(
        "workspace.finding.promote_observation",
        f"Promoted observation to finding for {host}: {finding_title}",
        {"workspaceId": wid, "target": host, "findingId": result["finding"]["id"], "observationKey": _entity_key(matched)},
    )
    return result


def link_evidence_to_finding(workspace_id: str, target: str, finding_id: str, evidence_ids: list[str]) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    with workspace_lock(wid):
        findings = _load_findings(wid, host)
        index = _find_finding_index(findings, finding_id)
        finding = dict(findings[index])
        linked = list(finding.get("evidenceIds", []))
        for evidence_id in evidence_ids:
            value = str(evidence_id).strip()
            if value and value not in linked:
                linked.append(value)
        finding["evidenceIds"] = linked
        finding["missingEvidenceIds"] = _missing_evidence_ids(wid, host, linked)
        finding["updatedAt"] = now_utc()
        findings[index] = finding
        _write_findings(wid, host, findings)
        findings_document = write_findings_markdown(wid, host)
    evidence.log_event(
        "workspace.finding.link_evidence",
        f"Linked {len(evidence_ids)} evidence id(s) to finding {finding_id}.",
        {"workspaceId": wid, "target": host, "findingId": finding_id, "evidenceIds": evidence_ids, "missingEvidenceIds": finding["missingEvidenceIds"]},
    )
    return {"linked": True, "workspaceId": wid, "target": host, "finding": finding, "findingsDocument": findings_document}


def mark_finding_reviewed(
    workspace_id: str,
    target: str,
    finding_id: str,
    status: str = "confirmed",
    reviewer: str = "operator",
    notes: str = "",
) -> dict[str, Any]:
    result = update_finding(
        workspace_id,
        target,
        finding_id,
        {"status": status, "operatorReviewed": True},
    )
    result["finding"]["reviewedAt"] = now_utc()
    result["finding"]["reviewedBy"] = reviewer
    result["finding"]["reviewNotes"] = notes
    with workspace_lock(result["workspaceId"]):
        findings = _load_findings(result["workspaceId"], result["target"])
        index = _find_finding_index(findings, finding_id)
        findings[index] = result["finding"]
        _write_findings(result["workspaceId"], result["target"], findings)
        result["findingsDocument"] = write_findings_markdown(result["workspaceId"], result["target"])
    evidence.log_event(
        "workspace.finding.reviewed",
        f"Marked finding {finding_id} as reviewed.",
        {"workspaceId": result["workspaceId"], "target": result["target"], "findingId": finding_id, "status": status, "reviewer": reviewer},
    )
    return result


def report_decisions_path(workspace_id: str) -> Path:
    # Lives in the top-level reports root (not the workspace folder), so a workspace's
    # review decisions sit next to the reports they shape and are not duplicated.
    return REPORTS_DIR / f"{normalize_workspace_id(workspace_id)}.report-decisions.json"


def resolve_report_output_path(
    workspace_id: str,
    output_path: str,
    *,
    extension: str,
    default_name: str,
    allow_external: bool = False,
    artifact: str = "report",
) -> Path:
    """Resolve where a rendered report/export is written.

    All reports land in the top-level reports root (REPORTS_DIR), never inside the
    workspace state folder. An explicit outputPath is interpreted relative to that
    root; a redundant leading ``reports/`` segment is dropped. Escaping the root
    requires allow_external=true. Returns a path whose parent directory exists.
    """
    reports_root = REPORTS_DIR
    if output_path:
        path = Path(str(output_path)).expanduser()
        if not path.is_absolute():
            _reject_workspace_relative_output(path)
            parts = path.parts
            if parts and parts[0] == "reports":
                path = Path(*parts[1:]) if len(parts) > 1 else Path(default_name)
            path = reports_root / path
        resolved = path.resolve()
        if not _is_within(resolved, reports_root.resolve()) and allow_external is not True:
            raise McpError(-32602, f"External {artifact} output paths require allowExternalOutput=true.")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved
    if not default_name.endswith(f".{extension}"):
        default_name = f"{default_name}.{extension}"
    resolved = reports_root / default_name
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _reject_workspace_relative_output(path: Path) -> None:
    parts = path.parts
    if parts and parts[0] == "DATA":
        raise McpError(-32602, "outputPath is workspace-relative; use reports/<file> or an absolute path with allowExternalOutput=true.")
    if parts[:1] == ("workspaces",):
        raise McpError(-32602, "outputPath is workspace-relative; do not include DATA/workspaces. Use reports/<file>.")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def read_report_decisions(workspace_id: str) -> list[dict[str, Any]]:
    decisions = _read_json(report_decisions_path(workspace_id), [])
    return decisions if isinstance(decisions, list) else []


def append_report_decision(workspace_id: str, record: dict[str, Any]) -> None:
    """Append one disposition record to the workspace's small report-decisions archive.

    The archive records *what was decided* (selector, count, reason, affected keys) — not
    full copies of the discarded records — so it stays a compact, auditable log of the
    reportability calls taken in the workspace.
    """
    path = report_decisions_path(workspace_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    decisions = read_report_decisions(workspace_id)
    decisions.append(record)
    _write_json(path, decisions)


_SELECTOR_IDENTITY_FIELDS = {
    "key": ("key",),
    "id": ("id",),
    "findingId": ("id", "key"),
    "observationId": ("id", "candidateId"),
    "observationKey": ("key",),
    "candidateId": ("candidateId",),
    "actionId": ("actionId",),
}


def _entity_matches_selector(entity: dict[str, Any], selector: dict[str, Any]) -> bool:
    """Match an entity against a disposition selector.

    Identity fields (key/id/findingId/observationId/observationKey/candidateId/actionId)
    match if any one resolves to this entity. Otherwise an attribute selector is required
    and every provided attribute constraint must hold: type (exact), value (exact),
    valueContains (substring of value), urlContains (substring of url/request/path/value).
    The attribute form enables bulk disposition (e.g. one call to suppress every
    open_redirect candidate whose URL contains "oembed").
    """
    if not isinstance(entity, dict) or not isinstance(selector, dict) or not selector:
        return False
    entity_key = _entity_key(entity)
    for selector_field, entity_fields in _SELECTOR_IDENTITY_FIELDS.items():
        wanted = str(selector.get(selector_field) or "").strip()
        if not wanted:
            continue
        candidates = {str(entity.get(field) or "") for field in entity_fields}
        candidates.add(entity_key)
        if wanted in candidates:
            return True
    sel_type = str(selector.get("type") or "").strip()
    sel_value = str(selector.get("value") or "").strip()
    value_contains = str(selector.get("valueContains") or "").strip()
    url_contains = str(selector.get("urlContains") or "").strip()
    if not any((sel_type, sel_value, value_contains, url_contains)):
        return False
    if sel_type and sel_type != str(entity.get("type") or ""):
        return False
    if sel_value and sel_value != str(entity.get("value") or ""):
        return False
    if value_contains and value_contains.lower() not in str(entity.get("value") or "").lower():
        return False
    if url_contains:
        haystack = " ".join(str(entity.get(field) or "") for field in ("url", "request", "path", "value")).lower()
        if url_contains.lower() not in haystack:
            return False
    return True


def set_entity_reportable(
    workspace_id: str,
    target: str,
    entity_type: str,
    selector: dict[str, Any],
    is_reportable_value: bool,
    reason: str = "",
    reviewer: str = "operator",
) -> dict[str, Any]:
    """Set isReportable on every entity of entity_type matching selector, and archive the decision.

    Works across all six entity layers (services, endpoints, parameters, findings, actions,
    observations). Marking a record non-reportable keeps it in workspace state for later
    granular analysis while excluding it from generated reports.
    """
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    if entity_type not in ENTITY_FILES:
        raise McpError(-32602, f"entityType must be one of: {', '.join(sorted(ENTITY_FILES))}.")
    if not isinstance(selector, dict) or not any(str(value or "").strip() for value in selector.values()):
        raise McpError(-32602, "selector must be a non-empty object with at least one identity or attribute field.")
    flag = bool(is_reportable_value)
    decided_at = now_utc()
    matched_keys: list[str] = []
    add_target(wid, host)
    with workspace_lock(wid):
        path = target_entity_path(wid, host, entity_type)
        items = _read_json(path, [])
        if not isinstance(items, list):
            items = []
        for item in items:
            if not isinstance(item, dict) or not _entity_matches_selector(item, selector):
                continue
            item["isReportable"] = flag
            decision = {"isReportable": flag, "decidedAt": decided_at, "reviewer": reviewer}
            if reason:
                decision["reason"] = reason
            item["reportableDecision"] = decision
            item["updatedAt"] = decided_at
            matched_keys.append(_entity_key(item))
        decision_record = {
            "decidedAt": decided_at,
            "reviewer": reviewer,
            "workspaceId": wid,
            "target": host,
            "entityType": entity_type,
            "isReportable": flag,
            "reason": reason,
            "selector": {key: value for key, value in selector.items() if str(value or "").strip()},
            "matched": len(matched_keys),
            "entityKeys": matched_keys[:200],
        }
        if matched_keys:
            _write_json(path, items)
            append_report_decision(wid, decision_record)
    if matched_keys:
        evidence.log_event(
            "workspace.reportability",
            f"Set isReportable={flag} on {len(matched_keys)} {entity_type} record(s) for {host}.",
            {
                "workspaceId": wid,
                "target": host,
                "entityType": entity_type,
                "isReportable": flag,
                "reason": reason,
                "reviewer": reviewer,
                "matched": len(matched_keys),
            },
        )
    return {
        "workspaceId": wid,
        "target": host,
        "entityType": entity_type,
        "isReportable": flag,
        "matched": len(matched_keys),
        "entityKeys": matched_keys,
        "decision": decision_record if matched_keys else None,
    }


def _priority_to_severity(priority: str) -> str:
    value = str(priority or "").strip().lower()
    return value if value in _SEVERITY_RANK else "info"


def _candidate_finding_draft(observation: dict[str, Any], vuln_class: str, host: str) -> dict[str, Any]:
    """Suggest — never create — a finding for a confirmed candidate.

    Keeps the operator/agent in the loop: promotion still goes through
    promote_observation_to_finding with the returned selector.
    """
    obs_type = str(observation.get("type", "") or "")
    if obs_type == "test_candidate" and vuln_class:
        detail = observation.get("candidateDetails", {}).get(vuln_class, {}) if isinstance(observation.get("candidateDetails"), dict) else {}
        priority = str(detail.get("priority") or observation.get("priority") or "info")
        reasons = detail.get("reasons") if isinstance(detail.get("reasons"), list) else []
        title = f"Confirmed {vuln_class.upper()} on {observation.get('parameter') or observation.get('url') or host}"
    else:
        priority = str(observation.get("priority") or observation.get("severity") or "info")
        reasons = observation.get("reasons") if isinstance(observation.get("reasons"), list) else []
        title = f"Confirmed {obs_type.replace('_', ' ')} on {observation.get('value') or host}".strip()
    return {
        "suggestedTitle": title,
        "suggestedSeverity": _priority_to_severity(priority),
        "confidence": "high",
        "vulnClass": vuln_class,
        "reasons": [str(item) for item in reasons if str(item).strip()],
        "evidenceIds": [str(item) for item in observation.get("evidenceIds", []) if str(item).strip()],
        "promoteSelector": {"observationKey": _entity_key(observation)},
    }


def record_candidate_validation(
    workspace_id: str,
    target: str,
    selector: dict[str, Any],
    outcome: str,
    vuln_class: str = "",
    evidence_ids: list[str] | None = None,
    notes: str = "",
    reviewer: str = "operator",
) -> dict[str, Any]:
    """Record a validation outcome on a candidate observation (any DATA-model layer).

    Common to every layer: works on the consolidated web ``test_candidate`` (per
    ``vuln_class`` inside ``candidateDetails``) and on any single-class ``*_candidate``
    observation (top-level ``validationStatus``), including access-control candidates.
    Per operator decision, a refuted candidate is retained and marked, never deleted:
    when nothing reportable remains it is flagged ``isReportable=False`` + ``retired``.
    A confirmed candidate stays reportable and yields a finding draft (not auto-created).
    """
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    status = str(outcome or "").strip().lower()
    if status not in CANDIDATE_VALIDATION_OUTCOMES:
        raise McpError(-32602, f"outcome must be one of: {', '.join(sorted(CANDIDATE_VALIDATION_OUTCOMES))}.")
    if not isinstance(selector, dict) or not any(str(value or "").strip() for value in selector.values()):
        raise McpError(-32602, "selector must be a non-empty object with at least one identity or attribute field.")
    decided_at = now_utc()
    new_evidence = [str(item) for item in (evidence_ids or []) if str(item).strip()]
    draft: dict[str, Any] | None = None
    with workspace_lock(wid):
        path = target_entity_path(wid, host, "observations")
        observations = _read_json(path, [])
        if not isinstance(observations, list):
            observations = []
        matched = next((item for item in observations if isinstance(item, dict) and _entity_matches_selector(item, selector)), None)
        if matched is None:
            raise McpError(-32602, "No candidate observation matched the provided selector.")
        obs_type = str(matched.get("type", "") or "")
        classes_updated: list[str] = []
        if obs_type == "test_candidate":
            details = matched.get("candidateDetails") if isinstance(matched.get("candidateDetails"), dict) else {}
            targets = [vuln_class] if vuln_class else list(details.keys())
            targets = [cls for cls in targets if cls in details] or ([vuln_class] if vuln_class else [])
            if not targets:
                raise McpError(-32602, "vuln_class does not match any candidateFor class on this surface candidate.")
            for cls in targets:
                detail = details.setdefault(cls, {})
                detail["validationStatus"] = status
                detail["decidedAt"] = decided_at
                if notes:
                    detail["validationNotes"] = notes
                classes_updated.append(cls)
            matched["candidateDetails"] = details
            if status == "refuted":
                remaining = [cls for cls in matched.get("candidateFor", []) if cls not in classes_updated]
                matched["candidateFor"] = remaining
                if not remaining:
                    matched["isReportable"] = False
                    matched["retired"] = True
        else:
            matched["validationStatus"] = status
            matched["validationDecidedAt"] = decided_at
            if notes:
                matched["validationNotes"] = notes
            if status == "refuted":
                matched["isReportable"] = False
                matched["retired"] = True
        if new_evidence:
            existing_ev = matched.get("evidenceIds") if isinstance(matched.get("evidenceIds"), list) else []
            matched["evidenceIds"] = existing_ev + [eid for eid in new_evidence if eid not in existing_ev]
        matched["updatedAt"] = decided_at
        if status == "confirmed":
            draft = _candidate_finding_draft(matched, vuln_class, host)
        entity_key = _entity_key(matched)
        _write_json(path, observations)
        decision_record = {
            "decidedAt": decided_at,
            "reviewer": reviewer,
            "workspaceId": wid,
            "target": host,
            "entityType": "observations",
            "action": "candidate_validation",
            "outcome": status,
            "vulnClass": vuln_class,
            "classesUpdated": classes_updated,
            "notes": notes,
            "selector": {key: value for key, value in selector.items() if str(value or "").strip()},
            "entityKey": entity_key,
            "retired": bool(matched.get("retired")),
        }
        append_report_decision(wid, decision_record)
    evidence.log_event(
        "workspace.candidate.validation",
        f"Recorded {status} validation on candidate {entity_key} for {host}.",
        {"workspaceId": wid, "target": host, "outcome": status, "vulnClass": vuln_class, "retired": bool(matched.get("retired"))},
    )
    return {
        "workspaceId": wid,
        "target": host,
        "outcome": status,
        "vulnClass": vuln_class,
        "classesUpdated": classes_updated,
        "observation": matched,
        "retired": bool(matched.get("retired")),
        "findingDraft": draft,
    }


def curate_candidate(
    workspace_id: str,
    target: str,
    surface_selector: dict[str, Any],
    add: list[str] | None = None,
    remove: list[str] | None = None,
    reason: str = "",
    reviewer: str = "agent",
) -> dict[str, Any]:
    """Agent curation of a surface ``test_candidate``: add/remove vuln classes precisely.

    Lets the agent build accurate candidates from normal observations instead of adapters
    blanketing every parameter. ``surface_selector`` identifies the surface by
    ``candidateId`` or by ``url``/``method``/``parameter``/``location`` (the latter also
    lets a not-yet-existing candidate be created for ``add``). Removing a class marks it
    refuted and drops it from ``candidateFor`` (retain + mark, consistent with the
    validation lifecycle); when nothing reportable remains the surface is retired.
    """
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    add_classes = [str(cls).strip() for cls in (add or []) if str(cls).strip()]
    remove_classes = [str(cls).strip() for cls in (remove or []) if str(cls).strip()]
    if not add_classes and not remove_classes:
        raise McpError(-32602, "Provide at least one class to add or remove.")
    if not isinstance(surface_selector, dict):
        raise McpError(-32602, "surface_selector must be an object.")
    url = str(surface_selector.get("url", "") or "")
    method = str(surface_selector.get("method", "GET") or "GET").upper()
    parameter = str(surface_selector.get("parameter", "") or "")
    location = str(surface_selector.get("location", "query") or "query")
    candidate_id = str(surface_selector.get("candidateId", "") or "")
    if not candidate_id and url:
        candidate_id = surface_candidate_id(method, url, location, parameter)
    if not candidate_id:
        raise McpError(-32602, "surface_selector needs a candidateId or a url (with optional method/parameter/location).")
    decided_at = now_utc()
    created = False
    with workspace_lock(wid):
        path = target_entity_path(wid, host, "observations")
        observations = _read_json(path, [])
        if not isinstance(observations, list):
            observations = []
        matched = next(
            (item for item in observations if isinstance(item, dict) and _entity_matches_selector(item, {"candidateId": candidate_id})),
            None,
        )
        if matched is None:
            if not add_classes:
                raise McpError(-32602, "No matching surface candidate to remove classes from.")
            if not url:
                raise McpError(-32602, "Creating a candidate requires url in surface_selector.")
            matched = surface_candidate(
                vuln_class=add_classes[0],
                url=url,
                method=method,
                parameter=parameter,
                location=location,
                reason=reason or "Agent-curated candidate.",
                confidence="medium",
                tags=["agent-curated"],
            )
            matched.setdefault("firstSeenAt", decided_at)
            matched["lastSeenAt"] = decided_at
            matched.setdefault("evidenceIds", [])
            matched["isReportable"] = True
            observations.append(matched)
            created = True
        details = matched.get("candidateDetails") if isinstance(matched.get("candidateDetails"), dict) else {}
        candidate_for = [str(cls) for cls in matched.get("candidateFor", []) if str(cls)]
        for cls in add_classes:
            if cls not in candidate_for:
                candidate_for.append(cls)
            detail = details.setdefault(cls, {"reasons": [], "priority": matched.get("priority", "low"), "priorityScore": int(matched.get("priorityScore", 0) or 0), "confidence": "medium"})
            detail["validationStatus"] = detail.get("validationStatus", "proposed")
            detail["curatedBy"] = reviewer
            if reason:
                detail["curationReason"] = reason
        for cls in remove_classes:
            candidate_for = [existing for existing in candidate_for if existing != cls]
            detail = details.setdefault(cls, {})
            detail["validationStatus"] = "refuted"
            detail["decidedAt"] = decided_at
            detail["curatedBy"] = reviewer
            if reason:
                detail["curationReason"] = reason
        matched["candidateDetails"] = details
        matched["candidateFor"] = candidate_for
        matched["updatedAt"] = decided_at
        if not candidate_for:
            matched["isReportable"] = False
            matched["retired"] = True
        entity_key = _entity_key(matched)
        _write_json(path, observations)
        add_target(wid, host)
        append_report_decision(
            wid,
            {
                "decidedAt": decided_at,
                "reviewer": reviewer,
                "workspaceId": wid,
                "target": host,
                "entityType": "observations",
                "action": "curate_candidate",
                "added": add_classes,
                "removed": remove_classes,
                "reason": reason,
                "created": created,
                "entityKey": entity_key,
                "candidateId": candidate_id,
            },
        )
    evidence.log_event(
        "workspace.candidate.curate",
        f"Curated candidate {candidate_id} for {host}: +{add_classes} -{remove_classes}.",
        {"workspaceId": wid, "target": host, "added": add_classes, "removed": remove_classes, "created": created},
    )
    return {
        "workspaceId": wid,
        "target": host,
        "candidateId": candidate_id,
        "created": created,
        "added": add_classes,
        "removed": remove_classes,
        "retired": bool(matched.get("retired")),
        "observation": matched,
    }


def export_finding_context(workspace_id: str, target: str, finding_id: str) -> dict[str, Any]:
    wid = normalize_workspace_id(workspace_id)
    host = normalize_target(target)
    findings = _load_findings(wid, host)
    finding = findings[_find_finding_index(findings, finding_id)]
    evidence_items = []
    for evidence_id in finding.get("evidenceIds", []):
        meta_path = target_path(wid, host) / "evidence" / f"{evidence_id}.json"
        if meta_path.exists():
            evidence_items.append(_read_json(meta_path, {}))
    return {
        "workspaceId": wid,
        "target": host,
        "finding": finding,
        "evidence": evidence_items,
        "findingsDocument": write_findings_markdown(wid, host),
    }


def read_workspace_resource(uri: str) -> tuple[str, str] | None:
    if uri == "synapse://workspaces":
        return "application/json", json.dumps(list_workspaces(), indent=2)
    prefix = "synapse://workspace/"
    if not uri.startswith(prefix):
        return None
    rest = uri[len(prefix) :]
    parts = [part for part in rest.split("/") if part]
    if not parts:
        return None
    workspace_id = parts[0]
    if len(parts) == 1:
        return "application/json", json.dumps(workspace_summary(workspace_id), indent=2)
    if len(parts) == 2 and parts[1] == "targets":
        return "application/json", json.dumps(workspace_summary(workspace_id)["targets"], indent=2)
    if len(parts) >= 4 and parts[1] == "target":
        target = parts[2]
        view = parts[3]
        if view == "summary":
            return "application/json", json.dumps(prepare_target_context(workspace_id, target), indent=2)
        if view in ENTITY_FILES:
            return "application/json", json.dumps(_load_target_entities(workspace_id, target).get(view, []), indent=2)
    return None
