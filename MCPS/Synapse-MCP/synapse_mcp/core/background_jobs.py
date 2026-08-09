# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from . import evidence, workspace
from .errors import McpError
from .execution import (
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    EffectEnvelope,
    ExecutionPlan,
    ExecutionPlanError,
    LocalOutputDestination,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
    write_planned_text,
)


Finalizer = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any] | None]

_LOCK = threading.Lock()
_PROCESSES: dict[str, subprocess.Popen[str]] = {}
_WATCHDOGS: dict[str, threading.Thread] = {}
_FINALIZERS: dict[str, Finalizer] = {}
MIN_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 86400


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _workspace_jobs_dir(workspace_id: str) -> Path:
    root = workspace.workspace_path(workspace.normalize_workspace_id(workspace_id)) / "jobs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _job_root_for_record(record: dict[str, Any]) -> Path:
    workspace_id = str(record.get("workspaceId", "")).strip() or workspace.default_workspace_id()
    return _workspace_jobs_dir(workspace_id)


def _job_dir_for_record(record: dict[str, Any]) -> Path:
    return _job_root_for_record(record) / str(record["jobId"])


def _record_path(job_id: str) -> Path:
    return _find_record_path(job_id) or (_workspace_jobs_dir(workspace.default_workspace_id()) / job_id / "job.json")


def _find_record_path(job_id: str, workspace_id: str = "") -> Path | None:
    if workspace_id:
        candidate = _workspace_jobs_dir(workspace_id) / job_id / "job.json"
        if candidate.exists():
            return candidate
    candidates = []
    for workspace_dir in workspace.WORKSPACES_DIR.glob("*/jobs"):
        candidates.append(workspace_dir / job_id / "job.json")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _clamp_timeout_seconds(timeout_seconds: int) -> int:
    return min(max(int(timeout_seconds), MIN_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS)


def _worker_result_error(result_path: Path, problem: str) -> dict[str, Any]:
    return {"isError": True, "error": f"Worker result file is {problem}: {result_path}"}


def read_worker_result_file(result_path: Path) -> dict[str, Any]:
    if not result_path.exists():
        return _worker_result_error(result_path, "missing")
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _worker_result_error(result_path, "corrupt")
    if not isinstance(payload, dict):
        return _worker_result_error(result_path, "corrupt")
    return payload


def _cleanup_finalizer_paths(data: dict[str, Any]) -> list[str]:
    removed: list[str] = []
    for key in ("cleanupArgsPath", "cleanupStatePath", "cleanupPlanPath"):
        raw_path = str(data.get(key, "") or "")
        if not raw_path:
            continue
        path = Path(raw_path)
        if path.exists():
            try:
                path.unlink()
                removed.append(str(path))
            except OSError:
                continue
    return removed


def _continuation_material(record: dict[str, Any]) -> dict[str, Any]:
    """Creation-time job fields whose mutation could redirect a continuation."""

    return {
        key: record.get(key)
        for key in (
            "jobId",
            "tool",
            "workspaceId",
            "target",
            "timeoutSeconds",
            "eventType",
            "summary",
            "command",
            "shellCommand",
            "eventData",
            "approval",
            "outputPath",
            "continuationPaths",
            "finalizerName",
            "finalizerData",
            "finalizerEffects",
            "correlationId",
        )
    }


def _validate_finalizer_paths(record: dict[str, Any], plan: ExecutionPlan) -> None:
    data = record.get("finalizerData")
    if not isinstance(data, dict):
        raise ExecutionPlanError("finalizer_data_invalid", "Job finalizer data must be an object.")
    for key in ("resultPath", "cleanupArgsPath", "cleanupStatePath", "cleanupPlanPath"):
        raw_path = str(data.get(key) or "")
        if not raw_path:
            continue
        destination = plan.output_for_path(raw_path)
        if key.startswith("cleanup") and not destination.may_prune:
            raise ExecutionPlanError(
                "cleanup_outside_execution_plan",
                f"The execution plan does not authorize cleanup of {destination.path}.",
            )


def _validate_runtime_record_paths(record: dict[str, Any]) -> None:
    bound = record.get("continuationPaths")
    if not isinstance(bound, dict):
        raise ExecutionPlanError("continuation_paths_missing", "Job sidecar paths were not fixed at creation.")
    for key in ("stdoutPath", "stderrPath", "returnCodePath"):
        expected = str(bound.get(key) or "")
        current = str(record.get(key) or "")
        if current == expected:
            continue
        if record.get("finalized") and not current:
            continue
        raise ExecutionPlanError(
            "continuation_path_diverged",
            f"Persisted job path {key} differs from its creation-time value.",
        )


def _write_record(record: dict[str, Any]) -> None:
    job_id = str(record["jobId"])
    root = _job_dir_for_record(record)
    root.mkdir(parents=True, exist_ok=True)
    record_path = root / "job.json"
    tmp = record_path.with_name(f".{record_path.name}.{uuid4().hex}.tmp")
    try:
        tmp.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(record_path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_record(job_id: str) -> dict[str, Any]:
    record_path = _find_record_path(job_id)
    record = _read_json(record_path, None) if record_path else None
    if not isinstance(record, dict):
        raise McpError(-32602, f"Unknown background job: {job_id}")
    return record


def snapshot_record(job_id: str) -> dict[str, Any]:
    """Return persisted job state without refresh, finalization, or writes."""

    return json.loads(json.dumps(_read_record(job_id)))


def snapshot(job_id: str, include_result: bool = False) -> dict[str, Any]:
    """Return the observational job response without hidden progression."""

    return _job_response(snapshot_record(job_id), include_result=include_result)


def _tail(path: str, limit: int = 12000) -> str:
    target = Path(path)
    if not target.exists():
        return ""
    text = target.read_text(encoding="utf-8", errors="replace")
    return text[-limit:]


def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _return_code(record: dict[str, Any]) -> int | None:
    raw_path = str(record.get("returnCodePath", "") or "")
    if not raw_path:
        return None
    rc_path = Path(raw_path)
    if not rc_path.is_file():
        return None
    try:
        return int(rc_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _forget_process(job_id: str) -> None:
    with _LOCK:
        _PROCESSES.pop(job_id, None)
        _WATCHDOGS.pop(job_id, None)


def register_finalizer(name: str, finalizer: Finalizer) -> None:
    _FINALIZERS[name] = finalizer


def _worker_result_finalizer(_record: dict[str, Any], _result: dict[str, Any], data: dict[str, Any]) -> dict[str, Any] | None:
    result_path = Path(str(data.get("resultPath", "")))
    payload = read_worker_result_file(result_path)
    removed = _cleanup_finalizer_paths(data)
    if removed:
        payload["workerCleanup"] = {"removed": removed}
    if payload.get("isError"):
        return payload
    if "crawl" in payload:
        workflow_refresh = []
        for ingestion in payload.get("ingestions", []) if isinstance(payload.get("ingestions"), list) else []:
            if not isinstance(ingestion, dict):
                continue
            workspace_id = str(ingestion.get("workspaceId", ""))
            target = str(ingestion.get("target", ""))
            if not workspace_id or not target:
                continue
            from . import fingerprint

            workflow_refresh.append(fingerprint.refresh_workspace_target(workspace_id, target))
        flow_graph = payload.get("flowGraph", {})
        compact_flow = {}
        if isinstance(flow_graph, dict):
            compact_flow = {
                key: flow_graph.get(key)
                for key in ("summary", "mermaidPath", "svgPath")
                if flow_graph.get(key) is not None
            }
        return {
            "summary": {
                **(payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}),
                **(payload.get("resultSummary", {}) if isinstance(payload.get("resultSummary"), dict) else {}),
            },
            "crawl": payload.get("crawl", {}),
            "outputPath": payload.get("outputPath", ""),
            "flowGraph": compact_flow,
            "ingestions": payload.get("ingestions", []),
            "actions": payload.get("actions", []),
            "ingestion": payload.get("ingestion", {}),
            "workflowRefresh": workflow_refresh,
            "resultPath": str(result_path),
        }
    return payload


register_finalizer("worker.result", _worker_result_finalizer)


def start_command(
    cmd: list[str],
    *,
    timeout_seconds: int,
    event_type: str,
    summary: str,
    display_cmd: list[str] | None = None,
    event_data: dict[str, Any] | None = None,
    tool: str = "",
    workspace_id: str = "",
    target: str = "",
    output_path: str = "",
    finalizer_name: str = "",
    finalizer_data: dict[str, Any] | None = None,
    execution_plan: ExecutionPlan | None = None,
    finalizer_effects: EffectEnvelope | None = None,
) -> dict[str, Any]:
    timeout_seconds = _clamp_timeout_seconds(timeout_seconds)
    visible_cmd = display_cmd or cmd
    workspace_id = workspace.normalize_workspace_id(workspace_id) if workspace_id else workspace.default_workspace_id()
    job_id = _new_job_id(tool or event_type, target)
    if execution_plan is None:
        execution_plan = _legacy_job_execution_plan(
            action_id=tool or event_type,
            workspace_id=workspace_id,
            target=target,
            correlation_id=uuid4().hex,
            output_path=output_path,
            finalizer_name=finalizer_name,
            finalizer_data=finalizer_data or {},
        )
    execution_plan.verify()
    if execution_plan.intent.workspace_id and execution_plan.intent.workspace_id != workspace_id:
        raise ExecutionPlanError("job_workspace_diverged", "Background job workspace differs from its execution plan.")
    if target and execution_plan.intent.target_envelope.exact_targets:
        execution_plan.intent.target_envelope.require(target)
    required_finalizer_effects = finalizer_effects or execution_plan.effects
    root = _job_root_for_record({"jobId": job_id, "workspaceId": workspace_id}) / job_id
    root.mkdir(parents=True, exist_ok=True)
    stdout_path = root / "stdout.txt"
    stderr_path = root / "stderr.txt"
    return_code_path = root / "returncode.txt"
    shell_script = ' "$@"; code=$?; printf "%s" "$code" > "$SYNAPSE_JOB_RC"; exit "$code"'
    launcher_cmd = ["/bin/sh", "-c", shell_script, "synapse-job", *cmd]
    record = {
        "jobId": job_id,
        "tool": tool or event_type,
        "workspaceId": workspace_id,
        "target": target,
        "status": "queued",
        "pid": None,
        "createdAt": _utc_now(),
        "startedAt": "",
        "completedAt": "",
        "timeoutSeconds": timeout_seconds,
        "eventType": event_type,
        "summary": summary,
        "command": visible_cmd,
        "shellCommand": _stringify(visible_cmd),
        "eventData": event_data or {},
        "approval": (event_data or {}).get("approval", {}),
        "outputPath": output_path,
        "stdoutPath": str(stdout_path),
        "stderrPath": str(stderr_path),
        "returnCodePath": str(return_code_path),
        "continuationPaths": {
            "stdoutPath": str(stdout_path),
            "stderrPath": str(stderr_path),
            "returnCodePath": str(return_code_path),
        },
        "returnCode": None,
        "timedOut": False,
        "finalized": False,
        "finalizerName": finalizer_name,
        "finalizerData": finalizer_data or {},
        "executionPlan": {},
        "finalizerEffects": required_finalizer_effects.to_dict(),
        "correlationId": execution_plan.correlation_id,
        "run": None,
        "result": None,
        "error": "",
    }
    execution_plan = execution_plan.bind_continuation(
        job_id=job_id,
        handler=finalizer_name,
        material=_continuation_material(record),
    )
    record["executionPlan"] = execution_plan.to_dict()
    _validate_finalizer_paths(record, execution_plan)
    cleanup_plan_path = str((finalizer_data or {}).get("cleanupPlanPath") or "")
    if cleanup_plan_path:
        destination = execution_plan.output_for_path(cleanup_plan_path)
        if not destination.may_prune:
            raise ExecutionPlanError(
                "cleanup_outside_execution_plan",
                "The worker plan sidecar is not authorized for continuation cleanup.",
            )
        write_planned_text(execution_plan, destination.purpose, json.dumps(execution_plan.to_dict(), indent=2, ensure_ascii=False))
        try:
            Path(destination.path).chmod(0o600)
        except OSError:
            pass
    _write_record(record)
    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
        proc = subprocess.Popen(
            launcher_cmd,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            start_new_session=True,
            env={**os.environ, "SYNAPSE_JOB_RC": str(return_code_path)},
        )
    record["status"] = "running"
    record["pid"] = proc.pid
    record["startedAt"] = _utc_now()
    with _LOCK:
        _PROCESSES[job_id] = proc
    _write_record(record)
    _start_watchdog(job_id, proc, timeout_seconds)
    evidence.log_event(
        event_type,
        f"Started background job {job_id}: {summary}",
        {
            **(event_data or {}),
            "jobId": job_id,
            "pid": proc.pid,
            "shellCommand": record["shellCommand"],
            "timeoutSeconds": timeout_seconds,
        },
    )
    return status(job_id)


def _legacy_job_execution_plan(
    *,
    action_id: str,
    workspace_id: str,
    target: str,
    correlation_id: str,
    output_path: str,
    finalizer_name: str,
    finalizer_data: dict[str, Any],
) -> ExecutionPlan:
    """Capture a conservative continuation envelope for unmigrated job starters."""

    snapshot_value = ScopeSnapshot.for_workspace(workspace_id)
    selectors: tuple[TargetSelector, ...] = ()
    seeds: tuple[CanonicalTarget, ...] = ()
    if target:
        try:
            canonical = CanonicalTarget.from_url(target)
            selectors = (TargetSelector(canonical, "any", "legacy_job_target"),)
            seeds = (canonical,)
        except ExecutionPlanError:
            pass
    planned_paths: list[tuple[str, str, bool]] = []
    if output_path:
        planned_paths.append((output_path, "legacy_job_output", False))
    for key in ("resultPath", "cleanupArgsPath", "cleanupStatePath", "cleanupPlanPath"):
        raw_path = str(finalizer_data.get(key) or "")
        if raw_path:
            planned_paths.append((raw_path, f"legacy_job_{key}", key.startswith("cleanup")))
    outputs_list: list[LocalOutputDestination] = []
    seen_paths: set[str] = set()
    for raw_path, purpose, may_prune in planned_paths:
        resolved = Path(raw_path).expanduser().resolve(strict=False)
        if str(resolved) in seen_paths:
            continue
        seen_paths.add(str(resolved))
        try:
            resolved.relative_to(workspace.workspace_path(workspace_id).resolve(strict=False))
            within = True
        except ValueError:
            within = False
        outputs_list.append(
            LocalOutputDestination(
                str(resolved),
                purpose,
                within,
                "overwrite" if resolved.exists() else "create",
                may_prune,
            )
        )
    outputs = tuple(outputs_list)
    intent = AuthorizationIntent(
        action_id=action_id,
        workspace_id=workspace_id,
        target_envelope=TargetEnvelope(
            workspace_id,
            snapshot_value.digest,
            snapshot_value,
            selectors,
            seeds,
            entire_workspace_scope=False,
        ),
        local_outputs=outputs,
        lineage=ContinuationLineage(
            origin_action_id=action_id,
            origin_correlation_id=correlation_id,
            handler=finalizer_name,
        ),
    )
    effects = EffectEnvelope(
        local_writes=("workspace", "evidence", "jobs", "reports_artifacts"),
        local_change=True,
        local_destruction=True,
        replay_safety="non_idempotent",
    )
    arguments = {"tool": action_id, "workspaceId": workspace_id, "target": target, "outputPath": output_path}

    class LegacyEffects:
        traffic = effects.traffic
        local_writes = effects.local_writes
        local_change = effects.local_change
        local_destruction = effects.local_destruction
        remote_state_change = effects.remote_state_change
        credential_use = effects.credential_use
        secret_use = effects.secret_use
        replay_safety = effects.replay_safety

    return ExecutionPlan.create(
        action_id=action_id,
        correlation_id=correlation_id,
        intent=intent,
        effects=LegacyEffects(),
        arguments=arguments,
    )


def _start_watchdog(job_id: str, proc: subprocess.Popen[str], timeout_seconds: int) -> None:
    thread = threading.Thread(
        target=_watch_process,
        args=(job_id, proc, timeout_seconds),
        name=f"synapse-job-watchdog-{job_id[:24]}",
        daemon=True,
    )
    with _LOCK:
        _WATCHDOGS[job_id] = thread
    thread.start()


def _watch_process(job_id: str, proc: subprocess.Popen[str], timeout_seconds: int) -> None:
    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            record = _read_record(job_id)
            if str(record.get("status", "")) in {"queued", "running"}:
                record["status"] = "timed_out"
                record["timedOut"] = True
                record["completedAt"] = _utc_now()
                record["lastObservedAt"] = record["completedAt"]
                record["error"] = record.get("error") or "Job exceeded timeout and was terminated by watchdog."
                _write_record(record)
        except Exception:
            pass
        terminate_process_group(proc.pid)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    finally:
        try:
            if timed_out or proc.poll() is not None:
                status(job_id)
        except Exception:
            pass
        if proc.poll() is not None:
            _forget_process(job_id)


def _stringify(cmd: list[str]) -> str:
    import shlex

    return shlex.join(cmd)


def _new_job_id(tool: str, target: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tool_slug = _slug(tool or "job")[:36]
    target_slug = _slug(workspace.normalize_target(target) if target else "")[:48]
    parts = ["job", timestamp]
    if tool_slug:
        parts.append(tool_slug)
    if target_slug:
        parts.append(target_slug)
    parts.append(uuid4().hex[:8])
    return "_".join(parts)


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(value).strip().lower()).strip("-")
    return slug or ""


def _run_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "command": record.get("command", []),
        "shellCommand": record.get("shellCommand", ""),
        "returnCode": record.get("returnCode"),
        "stdout": _tail(str(record.get("stdoutPath", ""))),
        "stderr": _tail(str(record.get("stderrPath", ""))),
        "timeoutSeconds": record.get("timeoutSeconds"),
        "timedOut": bool(record.get("timedOut", False)),
    }


def _cleanup_sidecar_files(record: dict[str, Any]) -> list[str]:
    removed: list[str] = []
    for key in ("stdoutPath", "stderrPath", "returnCodePath"):
        raw_path = str(record.get(key, "") or "")
        if not raw_path:
            record[key] = ""
            continue
        path = Path(raw_path)
        if path.exists() and path.name in {"stdout.txt", "stderr.txt", "returncode.txt"}:
            try:
                path.unlink()
                removed.append(path.name)
            except OSError as exc:
                record["error"] = (str(record.get("error", "")) + f" Sidecar cleanup failed for {path.name}: {exc}").strip()
        record[key] = ""
    return removed


def _finalize_record(record: dict[str, Any]) -> dict[str, Any]:
    workspace_id = str(record.get("workspaceId", "")).strip() or workspace.default_workspace_id()
    with workspace.workspace_lock(workspace_id):
        latest = _read_json(_find_record_path(str(record["jobId"]), workspace_id), None)
        return _finalize_record_locked(latest if isinstance(latest, dict) else record)


def _finalize_record_locked(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("finalized"):
        if any(str(record.get(key, "") or "") for key in ("stdoutPath", "stderrPath", "returnCodePath")):
            try:
                _validate_continuation(record)
            except ExecutionPlanError as exc:
                record["status"] = "failed"
                record["error"] = f"Continuation rejected [{exc.reason_code}]: {exc}"
                _write_record(record)
                return record
            removed_sidecars = _cleanup_sidecar_files(record)
            if removed_sidecars:
                record["sidecarCleanup"] = {"removed": sorted(removed_sidecars), "completedAt": _utc_now()}
                _write_record(record)
        return record
    run = _run_payload(record)
    record["run"] = run
    try:
        _validate_continuation(record)
    except ExecutionPlanError as exc:
        record["status"] = "failed"
        record["error"] = f"Continuation rejected [{exc.reason_code}]: {exc}"
        record["completedAt"] = record.get("completedAt") or _utc_now()
        record["result"] = {"isError": True, "error": record["error"]}
        record["finalized"] = True
        _write_record(record)
        _forget_process(str(record["jobId"]))
        return record
    finalizer_name = str(record.get("finalizerName", ""))
    if finalizer_name:
        finalizer = _FINALIZERS.get(finalizer_name)
        if not finalizer:
            record["status"] = "failed"
            record["error"] = f"Finalizer is not registered: {finalizer_name}"
            record["completedAt"] = record.get("completedAt") or _utc_now()
            record["finalized"] = True
            _write_record(record)
            _forget_process(str(record["jobId"]))
            return record
        try:
            record["result"] = finalizer(record, run, record.get("finalizerData", {})) or None
        except Exception as exc:  # pragma: no cover - defensive guard for lazy finalizers.
            record["status"] = "failed"
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["completedAt"] = record.get("completedAt") or _utc_now()
            record["result"] = {"isError": True, "error": record["error"]}
        if isinstance(record.get("result"), dict) and record["result"].get("isError"):
            record["status"] = "failed"
            record["error"] = str(record["result"].get("error") or "Background job finalization failed.")
    record["finalized"] = True
    removed_sidecars = _cleanup_sidecar_files(record)
    if removed_sidecars:
        record["sidecarCleanup"] = {"removed": sorted(removed_sidecars), "completedAt": _utc_now()}
    evidence.log_event(
        str(record.get("eventType", "jobs.run")),
        str(record.get("summary", f"Background job {record['jobId']} completed.")),
        {
            **(record.get("eventData", {}) if isinstance(record.get("eventData"), dict) else {}),
            "jobId": record["jobId"],
            "shellCommand": record.get("shellCommand", ""),
            "returnCode": run.get("returnCode"),
            "timeoutSeconds": run.get("timeoutSeconds"),
            "timedOut": run.get("timedOut", False),
            "sidecarCleanup": removed_sidecars,
        },
    )
    _write_record(record)
    _forget_process(str(record["jobId"]))
    return record


def _validate_continuation(record: dict[str, Any]) -> ExecutionPlan:
    serialized = record.get("executionPlan")
    if not isinstance(serialized, dict):
        raise ExecutionPlanError("continuation_plan_missing", "Job finalization requires its creation-time execution plan.")
    plan = ExecutionPlan.from_dict(serialized)
    workspace_id = str(record.get("workspaceId") or "")
    if plan.intent.workspace_id and plan.intent.workspace_id != workspace_id:
        raise ExecutionPlanError("continuation_workspace_diverged", "Job workspace no longer matches its execution plan.")
    target = str(record.get("target") or "")
    if target and plan.intent.target_envelope.exact_targets:
        plan.intent.target_envelope.require(target)
    required_value = record.get("finalizerEffects")
    if not isinstance(required_value, dict):
        raise ExecutionPlanError("finalizer_effects_missing", "Job finalizer effects were not fixed at creation.")
    required = EffectEnvelope.from_dict(required_value)
    if not plan.effects.permits(required):
        raise ExecutionPlanError("finalizer_effects_exceeded", "Job finalizer effects exceed the creation-time execution plan.")
    plan.assert_continuation_binding(
        job_id=str(record.get("jobId") or ""),
        handler=str(record.get("finalizerName") or ""),
        material=_continuation_material(record),
    )
    _validate_runtime_record_paths(record)
    _validate_finalizer_paths(record, plan)
    return plan


def _refresh(record: dict[str, Any]) -> dict[str, Any]:
    workspace_id = str(record.get("workspaceId", "")).strip() or workspace.default_workspace_id()
    with workspace.workspace_lock(workspace_id):
        latest = _read_json(_find_record_path(str(record["jobId"]), workspace_id), None)
        return _refresh_locked(latest if isinstance(latest, dict) else record)


def _refresh_locked(record: dict[str, Any]) -> dict[str, Any]:
    try:
        _validate_continuation(record)
    except ExecutionPlanError as exc:
        record["status"] = "failed"
        record["error"] = f"Continuation rejected [{exc.reason_code}]: {exc}"
        record["completedAt"] = record.get("completedAt") or _utc_now()
        record["result"] = {"isError": True, "error": record["error"]}
        record["finalized"] = True
        _write_record(record)
        _forget_process(str(record["jobId"]))
        return record
    status_value = str(record.get("status", ""))
    if status_value not in {"queued", "running"}:
        if status_value in {"completed", "timed_out", "canceled", "failed"}:
            return _finalize_record_locked(record)
        return record

    job_id = str(record["jobId"])
    proc = _PROCESSES.get(job_id)
    if proc is not None and proc.poll() is not None and _return_code(record) is None:
        Path(str(record["returnCodePath"])).write_text(str(proc.returncode), encoding="utf-8")

    started_at = str(record.get("startedAt") or record.get("createdAt") or "")
    timeout_seconds = int(record.get("timeoutSeconds") or 0)
    timed_out = False
    if timeout_seconds and started_at:
        try:
            started = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            timed_out = (datetime.now(timezone.utc) - started).total_seconds() > timeout_seconds
        except ValueError:
            timed_out = False

    rc = _return_code(record)
    pid = record.get("pid")
    alive = bool(isinstance(pid, int) and _is_pid_alive(pid))
    record["lastObservedAt"] = _utc_now()
    if rc is None and timed_out and alive:
        if proc is not None:
            _terminate_process_group(int(pid))
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        else:
            record["error"] = record.get("error") or "Job exceeded timeout, but process handle is unavailable after MCP restart."
        record["status"] = "timed_out"
        record["timedOut"] = True
        record["completedAt"] = _utc_now()
    elif rc is None and alive:
        record["status"] = "running"
    elif rc is None:
        record["status"] = "failed"
        record["completedAt"] = _utc_now()
        record["error"] = record.get("error") or "Process exited before writing a return code."
    else:
        record["status"] = "completed" if rc == 0 else "failed"
        record["returnCode"] = rc
        record["completedAt"] = record.get("completedAt") or _utc_now()
        if rc != 0:
            record["error"] = record.get("error") or f"Process exited with return code {rc}."
    _write_record(record)
    if record["status"] in {"completed", "timed_out", "failed", "canceled"}:
        return _finalize_record_locked(record)
    return record


def status(job_id: str, include_result: bool = False) -> dict[str, Any]:
    return _job_response(_refresh(_read_record(job_id)), include_result=include_result)


def list_jobs(limit: int = 20, active_only: bool = False, workspace_id: str = "", include_result: bool = False) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for path in _job_record_paths(workspace_id):
        record = _read_json(path, None)
        if isinstance(record, dict):
            if active_only and record.get("status") not in {"queued", "running"}:
                continue
            refreshed = _refresh(record)
            if not active_only or refreshed.get("status") in {"queued", "running"}:
                records.append(_job_response(refreshed, include_result=include_result))
    records.sort(key=lambda item: str(item.get("createdAt", "")), reverse=True)
    return {"jobs": records[: max(int(limit), 1)], "count": len(records)}


def active_jobs(limit: int = 20) -> dict[str, Any]:
    return list_jobs(limit=limit, active_only=True)


def _job_response(record: dict[str, Any], *, include_result: bool = False) -> dict[str, Any]:
    result = record.get("result") if isinstance(record.get("result"), dict) else {}
    finalizer_data = record.get("finalizerData") if isinstance(record.get("finalizerData"), dict) else {}
    response = {
        "jobId": record.get("jobId", ""),
        "tool": record.get("tool", ""),
        "workspaceId": record.get("workspaceId", ""),
        "target": record.get("target", ""),
        "status": record.get("status", ""),
        "pid": record.get("pid"),
        "createdAt": record.get("createdAt", ""),
        "startedAt": record.get("startedAt", ""),
        "lastObservedAt": record.get("lastObservedAt", ""),
        "completedAt": record.get("completedAt", ""),
        "timeoutSeconds": record.get("timeoutSeconds"),
        "eventType": record.get("eventType", ""),
        "summary": record.get("summary", ""),
        "outputPath": result.get("outputPath") or record.get("outputPath", ""),
        "resultPath": result.get("resultPath") or finalizer_data.get("resultPath", ""),
        "stdoutPath": record.get("stdoutPath", ""),
        "stderrPath": record.get("stderrPath", ""),
        "returnCodePath": record.get("returnCodePath", ""),
        "returnCode": record.get("returnCode"),
        "timedOut": bool(record.get("timedOut")),
        "finalized": bool(record.get("finalized")),
        "error": record.get("error", ""),
    }
    if isinstance(result.get("summary"), dict):
        response["resultSummary"] = result["summary"]
        if result["summary"].get("disposition"):
            response["resultDisposition"] = result["summary"]["disposition"]
    if isinstance(result.get("counts"), dict):
        response["counts"] = result["counts"]
    if include_result:
        response["run"] = record.get("run")
        response["result"] = record.get("result")
    return response


def _job_record_paths(workspace_id: str = "") -> list[Path]:
    if workspace_id:
        return sorted(_workspace_jobs_dir(workspace_id).glob("job_*/job.json"))
    paths = []
    paths.extend(workspace.WORKSPACES_DIR.glob("*/jobs/job_*/job.json"))
    return sorted(paths)


def cancel(job_id: str) -> dict[str, Any]:
    record = _read_record(job_id)
    refreshed = _refresh(record)
    if refreshed.get("status") not in {"queued", "running"}:
        return refreshed
    pid = refreshed.get("pid")
    if isinstance(pid, int):
        _terminate_process_group(pid)
        proc = _PROCESSES.get(job_id)
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    refreshed["status"] = "canceled"
    refreshed["completedAt"] = _utc_now()
    refreshed["error"] = "Canceled by operator request."
    _write_record(refreshed)
    evidence.log_event(
        str(refreshed.get("eventType", "jobs.cancel")),
        f"Canceled background job {job_id}.",
        {"jobId": job_id, "pid": pid, "shellCommand": refreshed.get("shellCommand", "")},
    )
    return _finalize_record(refreshed)


def terminate_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
        time.sleep(0.2)
        if _is_pid_alive(pid):
            os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _terminate_process_group(pid: int) -> None:
    terminate_process_group(pid)
