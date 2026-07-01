# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from . import dumps, evidence, scope, workspace


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _hosts_from_history_jsonl(path: Path) -> set[str]:
    hosts: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hosts
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = scope.normalize_host(str(entry.get("host", "")))
        if host:
            hosts.add(host)
    return hosts


def _classify_artifact(path: Path, artifact_type: str, hosts: set[str], scoped_hosts: set[str]) -> dict[str, Any]:
    in_scope_hosts = sorted(hosts & scoped_hosts)
    out_of_scope_hosts = sorted(hosts - scoped_hosts)
    if not hosts:
        status = "unknown-hosts"
    elif in_scope_hosts and out_of_scope_hosts:
        status = "mixed-scope-prune-candidate"
    elif out_of_scope_hosts:
        status = "out-of-scope-delete-candidate"
    else:
        status = "in-scope-kept"
    return {
        "path": str(path),
        "type": artifact_type,
        "hosts": sorted(hosts),
        "inScopeHosts": in_scope_hosts,
        "outOfScopeHosts": out_of_scope_hosts,
        "status": status,
        "deletable": status == "out-of-scope-delete-candidate",
        "prunable": status == "mixed-scope-prune-candidate"
        and artifact_type == "burp-dump-directory",
    }


def inspect_scope_data() -> dict[str, Any]:
    scoped_hosts = {scope.normalize_host(host) for host in scope.load_scope().get("hosts", [])}
    scoped_hosts = {host for host in scoped_hosts if host}
    artifacts: list[dict[str, Any]] = []

    for dump_dir in dumps.iter_dump_directories():
        hosts = _hosts_from_history_jsonl(dump_dir / "history.jsonl")
        artifacts.append(_classify_artifact(dump_dir, "burp-dump-directory", hosts, scoped_hosts))

    return {
        "scopeHosts": sorted(scoped_hosts),
        "artifacts": artifacts,
        "deleteCandidates": [item for item in artifacts if item["deletable"]],
        "pruneCandidates": [item for item in artifacts if item["prunable"]],
        "mixedScopeKept": [item for item in artifacts if item["status"] == "mixed-scope-prune-candidate" and not item["prunable"]],
        "unknownHostsKept": [item for item in artifacts if item["status"] == "unknown-hosts"],
    }


def _prune_burp_dump_directory(path: Path, scoped_hosts: set[str]) -> dict[str, Any]:
    history_path = path / "history.jsonl"
    try:
        lines = history_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"path": str(path), "error": str(exc)}

    kept_lines: list[str] = []
    removed_files: list[str] = []
    entries_before = 0
    entries_after = 0
    for line in lines:
        if not line.strip():
            continue
        entries_before += 1
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            kept_lines.append(line)
            entries_after += 1
            continue
        host = scope.normalize_host(str(entry.get("host", "")))
        if not host or host in scoped_hosts:
            kept_lines.append(line)
            entries_after += 1
            continue
        for key in ("requestFile", "responseFile"):
            if not entry.get(key):
                continue
            file_path = Path(entry[key])
            if not file_path.is_absolute():
                file_path = path / file_path
            try:
                if file_path.resolve().is_relative_to(path.resolve()) and file_path.exists():
                    file_path.unlink()
                    removed_files.append(str(file_path))
            except OSError:
                continue

    history_path.write_text("\n".join(kept_lines) + ("\n" if kept_lines else ""), encoding="utf-8")
    manifest_path = path / "manifest.json"
    manifest = _read_json(manifest_path)
    if isinstance(manifest, dict):
        manifest["exportedCount"] = entries_after
        manifest.setdefault("warnings", [])
        if isinstance(manifest["warnings"], list):
            manifest["warnings"].append("Out-of-scope entries were pruned by cache.clean_out_of_scope.")
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "path": str(path),
        "type": "burp-dump-directory",
        "entriesBefore": entries_before,
        "entriesAfter": entries_after,
        "removedFiles": removed_files,
    }


def clean_out_of_scope(confirm: bool = False) -> dict[str, Any]:
    plan = inspect_scope_data()
    if not confirm:
        return {
            "cleaned": False,
            "requiresConfirmation": True,
            "message": (
                "Review deleteCandidates and pruneCandidates, then call cache.clean_out_of_scope with confirm=true "
                "to remove or prune dump artifacts."
            ),
            **plan,
        }

    removed: list[dict[str, Any]] = []
    pruned: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    scoped_hosts = set(plan["scopeHosts"])
    for item in plan["deleteCandidates"]:
        path = Path(item["path"])
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(item)
        except OSError as exc:
            failed.append({**item, "error": str(exc)})
    for item in plan["pruneCandidates"]:
        path = Path(item["path"])
        try:
            if item["type"] == "burp-dump-directory":
                pruned.append({**item, "pruneResult": _prune_burp_dump_directory(path, scoped_hosts)})
        except OSError as exc:
            failed.append({**item, "error": str(exc)})

    result = {
        "cleaned": True,
        "removed": removed,
        "pruned": pruned,
        "failed": failed,
        "mixedScopeKept": plan["mixedScopeKept"],
        "unknownHostsKept": plan["unknownHostsKept"],
        "scopeHosts": plan["scopeHosts"],
    }
    evidence.log_event(
        "cache_cleanup",
        f"Cleaned {len(removed)} out-of-scope dump artifacts and pruned {len(pruned)} mixed artifacts; {len(failed)} failed.",
        {
            "removed": removed,
            "pruned": pruned,
            "failed": failed,
            "scopeHosts": plan["scopeHosts"],
            "mixedScopeKept": plan["mixedScopeKept"],
            "unknownHostsKept": plan["unknownHostsKept"],
        },
    )
    return result


TIMESTAMPED_RE = re.compile(r"^\d{8}-\d{6}-(.+)$")
REPLACEABLE_EVIDENCE_SOURCES = {"sitemap", "crawler", "js_intelligence"}


def _target_dirs() -> list[Path]:
    return sorted(workspace.WORKSPACES_DIR.glob("*/targets/*"))


def _timestamped_output_candidates(keep: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for target_dir in _target_dirs():
        outputs_dir = target_dir / "outputs"
        if not outputs_dir.exists():
            continue
        workspace_id = target_dir.parents[1].name
        target = target_dir.name
        for tool_dir in sorted(path for path in outputs_dir.rglob("*") if path.is_dir()):
            groups: dict[str, list[Path]] = {}
            for path in sorted(item for item in tool_dir.iterdir() if item.is_file()):
                match = TIMESTAMPED_RE.match(path.name)
                if not match:
                    continue
                groups.setdefault(match.group(1), []).append(path)
            for suffix, paths in groups.items():
                if len(paths) <= keep:
                    continue
                removable = paths[: len(paths) - keep]
                candidates.append(
                    {
                        "workspaceId": workspace_id,
                        "target": target,
                        "tool": str(tool_dir.relative_to(outputs_dir)),
                        "suffix": suffix,
                        "keep": keep,
                        "existingCount": len(paths),
                        "removeCount": len(removable),
                        "removePaths": [str(path) for path in removable],
                    }
                )
    return candidates


def _replaceable_evidence_candidates(keep: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for target_dir in _target_dirs():
        evidence_dir = target_dir / "evidence"
        if not evidence_dir.exists():
            continue
        workspace_id = target_dir.parents[1].name
        target = target_dir.name
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for meta_path in sorted(evidence_dir.glob("ev_*.json")):
            payload = _read_json(meta_path)
            if not isinstance(payload, dict):
                continue
            source = str(payload.get("source", ""))
            data_type = str(payload.get("dataType", ""))
            if source not in REPLACEABLE_EVIDENCE_SOURCES or data_type not in {"tool_output", "js_static_analysis"}:
                continue
            groups.setdefault((source, data_type), []).append(
                {
                    "createdAt": str(payload.get("createdAt", "")),
                    "evidenceId": str(payload.get("evidenceId", "")),
                    "metaPath": str(meta_path),
                    "rawPath": str(payload.get("rawPath", "")),
                }
            )
        for (source, data_type), records in groups.items():
            records.sort(key=lambda item: (item["createdAt"], item["evidenceId"]))
            if len(records) <= keep:
                continue
            removable = records[: len(records) - keep]
            candidates.append(
                {
                    "workspaceId": workspace_id,
                    "target": target,
                    "source": source,
                    "dataType": data_type,
                    "keep": keep,
                    "existingCount": len(records),
                    "removeCount": len(removable),
                    "removeEvidenceIds": [item["evidenceId"] for item in removable],
                    "removePaths": [path for item in removable for path in (item["rawPath"], item["metaPath"]) if path],
                }
            )
    return candidates


def inspect_generated_artifacts(keep: int = 1) -> dict[str, Any]:
    keep = max(int(keep or 1), 1)
    output_candidates = _timestamped_output_candidates(keep)
    evidence_candidates = _replaceable_evidence_candidates(keep)
    return {
        "keep": keep,
        "outputCandidates": output_candidates,
        "evidenceCandidates": evidence_candidates,
        "outputRemoveCount": sum(int(item["removeCount"]) for item in output_candidates),
        "evidenceRemoveCount": sum(int(item["removeCount"]) for item in evidence_candidates),
    }


def clean_generated_artifacts(confirm: bool = False, keep: int = 1) -> dict[str, Any]:
    plan = inspect_generated_artifacts(keep)
    if not confirm:
        return {
            "cleaned": False,
            "requiresConfirmation": True,
            "message": "Review outputCandidates and evidenceCandidates, then call cache.clean_generated_artifacts with confirm=true.",
            **plan,
        }
    removed_paths: list[str] = []
    failed: list[dict[str, Any]] = []
    for item in plan["outputCandidates"]:
        for raw_path in item["removePaths"]:
            path = Path(raw_path)
            try:
                if path.exists() and path.is_file():
                    path.unlink()
                    removed_paths.append(str(path))
            except OSError as exc:
                failed.append({"path": str(path), "error": str(exc)})
    pruned_evidence: list[dict[str, Any]] = []
    for item in plan["evidenceCandidates"]:
        result = workspace.prune_generated_evidence(
            item["workspaceId"],
            item["target"],
            source=item["source"],
            data_type=item["dataType"],
            keep=plan["keep"],
        )
        pruned_evidence.append({**item, "result": result})
        removed_paths.extend(result.get("removedPaths", []))
    result = {
        "cleaned": True,
        "keep": plan["keep"],
        "removedPathCount": len(set(removed_paths)),
        "removedPaths": sorted(set(removed_paths)),
        "prunedEvidence": pruned_evidence,
        "failed": failed,
    }
    evidence.log_event(
        "cache.generated_cleanup",
        f"Cleaned {result['removedPathCount']} generated artifact path(s); {len(failed)} failed.",
        {"keep": plan["keep"], "removedPathCount": result["removedPathCount"], "failed": failed},
    )
    return result
