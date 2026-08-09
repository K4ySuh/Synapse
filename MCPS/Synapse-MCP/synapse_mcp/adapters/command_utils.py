# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
import shlex
import subprocess
from typing import Any

from ..core import background_jobs
from ..core.errors import McpError
from ..core import evidence, scope, workspace
from ..core.execution import EffectEnvelope, ExecutionPlan


def stringify_command(cmd: list[str]) -> str:
    return shlex.join(cmd)


def require_confirmed(args: dict[str, Any], message: str) -> None:
    if args.get("confirm") is not True:
        raise McpError(-32001, message)


def background_requested(args: dict[str, Any], *, default: bool = True) -> bool:
    return bool(args.get("background", default))


def require_in_scope(target: str, workspace_id: str = "") -> dict[str, Any]:
    workspace_scope = workspace.workspace_scope(workspace_id) if workspace_id else {}
    has_workspace_scope = any(workspace_scope.get(name) for name in ("hosts", "patterns", "cidrs"))
    result = scope.check_target_in_scope(target, workspace_scope) if has_workspace_scope else scope.check_target(target)
    if not result["inScope"]:
        if workspace_id and has_workspace_scope:
            raise McpError(
                -32002,
                f"Target is not in authorized scope for workspace {workspace.normalize_workspace_id(workspace_id)}: {result['host']}",
            )
        raise McpError(-32002, f"Target is not in authorized scope: {result['host']}")
    return result


def run_command(
    cmd: list[str],
    *,
    timeout_seconds: int,
    event_type: str,
    summary: str,
    display_cmd: list[str] | None = None,
    event_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    visible_cmd = display_cmd or cmd
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        payload = {
            "command": visible_cmd,
            "shellCommand": stringify_command(visible_cmd),
            "returnCode": proc.returncode,
            "stdout": stdout[-12000:],
            "stderr": stderr[-12000:],
            "timeoutSeconds": timeout_seconds,
            "timedOut": False,
        }
    except FileNotFoundError as exc:
        raise McpError(-32000, f"Executable not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        if proc is not None and proc.pid:
            background_jobs.terminate_process_group(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
        else:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
        payload = {
            "command": visible_cmd,
            "shellCommand": stringify_command(visible_cmd),
            "returnCode": None,
            "stdout": stdout[-12000:],
            "stderr": stderr[-12000:],
            "timeoutSeconds": timeout_seconds,
            "timedOut": True,
        }
    evidence.log_event(
        event_type,
        summary,
        {
            **(event_data or {}),
            "shellCommand": payload["shellCommand"],
            "returnCode": payload["returnCode"],
            "timeoutSeconds": payload["timeoutSeconds"],
            "timedOut": payload.get("timedOut", False),
        },
    )
    return payload


def start_background_command(
    cmd: list[str],
    *,
    timeout_seconds: int,
    event_type: str,
    summary: str,
    display_cmd: list[str] | None = None,
    event_data: dict[str, Any] | None = None,
    completion_callback: Any | None = None,
    tool: str = "",
    workspace_id: str = "",
    target: str = "",
    output_path: str = "",
    finalizer_name: str = "",
    finalizer_data: dict[str, Any] | None = None,
    execution_plan: ExecutionPlan | None = None,
    finalizer_effects: EffectEnvelope | None = None,
) -> dict[str, Any]:
    if completion_callback and not finalizer_name:
        if finalizer_effects is None:
            raise ValueError("Background completion callbacks require explicit finalizer_effects.")
        name = f"_callback_{id(completion_callback)}"
        background_jobs.register_finalizer(name, lambda _record, result, _data: completion_callback(result))
        finalizer_name = name
    return background_jobs.start_command(
        cmd,
        timeout_seconds=timeout_seconds,
        event_type=event_type,
        summary=summary,
        display_cmd=display_cmd,
        event_data=event_data,
        tool=tool,
        workspace_id=workspace_id,
        target=target,
        output_path=output_path,
        finalizer_name=finalizer_name,
        finalizer_data=finalizer_data,
        execution_plan=execution_plan,
        finalizer_effects=finalizer_effects,
    )


def get_background_job(job_id: str) -> dict[str, Any]:
    return background_jobs.status(job_id)


def list_background_jobs(limit: int = 20, workspace_id: str = "") -> dict[str, Any]:
    return background_jobs.list_jobs(limit, workspace_id=workspace_id)


def approval_metadata(args: dict[str, Any]) -> dict[str, Any]:
    confirmed = args.get("confirm") is True
    metadata = {"confirm": confirmed, "operatorApproved": confirmed, "approved": confirmed}
    for source, destination in (
        ("approvalId", "approvalId"),
        ("approvalReason", "approvalReason"),
        ("riskTier", "riskTier"),
    ):
        value = args.get(source)
        if isinstance(value, str) and value.strip():
                metadata[destination] = value.strip()
    return metadata


def require_external_output_allowed(args: dict[str, Any], field_name: str, allowed_root: str | Path | None = None) -> None:
    output = args.get(field_name)
    if not output:
        return
    if allowed_root is not None:
        try:
            Path(output).expanduser().resolve(strict=False).relative_to(Path(allowed_root).expanduser().resolve(strict=False))
            return
        except ValueError:
            pass
    if args.get("allowExternalOutput") is not True:
        raise McpError(
            -32001,
            f"{field_name} writes outside the workspace evidence tree; set allowExternalOutput=true after operator approval.",
        )


def store_tool_transcript(
    workspace_id: str,
    target: str,
    tool: str,
    profile: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    raw = {
        "tool": tool,
        "profile": profile,
        "returnCode": result.get("returnCode"),
        "timedOut": result.get("timedOut", False),
        "timeoutSeconds": result.get("timeoutSeconds"),
        "command": result.get("command", []),
        "shellCommand": result.get("shellCommand", ""),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
    }
    return workspace.ingest_data(
        workspace_id,
        target,
        tool,
        "tool_run_transcript",
        "json",
        json.dumps(raw, indent=2, ensure_ascii=False),
        metadata,
    )
