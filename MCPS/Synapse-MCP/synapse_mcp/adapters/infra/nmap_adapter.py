# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ...core import background_jobs, fingerprint, workspace
from ...core.errors import McpError
from ..command_utils import (
    approval_metadata,
    background_requested,
    require_confirmed,
    require_external_output_allowed,
    require_in_scope,
    run_command,
    start_background_command,
    store_tool_transcript,
    stringify_command,
)


NMAP_BIN = os.environ.get("NMAP_BIN", "nmap")

PROFILES: dict[str, dict[str, Any]] = {
    "low_noise": {
        "description": "Low-noise TCP connect scan of the top 100 ports with reasons.",
        "args": ["-sT", "-Pn", "--top-ports", "100", "-T3", "--reason"],
    },
    "medium": {
        "description": "TCP connect scan of the top 1000 ports with reasons.",
        "args": ["-sT", "-Pn", "--top-ports", "1000", "-T3", "--reason"],
    },
    "pentest_aggressive": {
        "description": "Explicitly approved TCP top-1000 scan with service/version detection and reasons.",
        "args": ["-sT", "-sV", "--version-light", "-Pn", "--top-ports", "1000", "-T4", "--reason"],
    },
}


def list_profiles() -> str:
    return json.dumps(PROFILES, indent=2)


def build_command(args: dict[str, Any]) -> dict[str, Any]:
    profile_name = args.get("profile", "medium")
    if profile_name not in PROFILES:
        raise McpError(-32602, f"Unknown nmap profile: {profile_name}")
    profile = PROFILES[profile_name]
    target = args["target"]
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target, workspace_id)
    require_external_output_allowed(
        args,
        "outputBase",
        workspace.target_output_dir(workspace_id, scope_result["host"], "nmap"),
    )
    output_base = Path(
        args.get("outputBase")
        or workspace.target_output_path(workspace_id, scope_result["host"], "nmap", profile_name)
    )
    cmd = [NMAP_BIN, *profile["args"]]
    ports = args.get("ports")
    if profile.get("requiresPorts") and not ports:
        raise McpError(-32602, f"Profile {profile_name} requires a ports value, e.g. '80,443'.")
    if ports:
        cmd.extend(["-p", str(ports)])
    cmd.extend(["-oA", str(output_base), scope_result["host"]])
    return {
        "profile": profile_name,
        "target": target,
        "workspaceId": workspace_id,
        "scope": scope_result,
        "outputBase": str(output_base),
        "command": cmd,
        "shellCommand": stringify_command(cmd),
        "rationale": profile["description"],
    }


def _event_data(built: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    return {
            "workspaceId": built["workspaceId"],
            "target": built["target"],
            "host": built["scope"]["host"],
            "profile": built["profile"],
            "approval": approval,
    }


def _finalize_run(built: dict[str, Any], result: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    ingestion = None
    metadata = {
        "profile": built["profile"],
        "target": built["target"],
        "host": built["scope"]["host"],
        "command": built["command"],
        "outputBase": built["outputBase"],
        "returnCode": result["returnCode"],
        "timeoutSeconds": result["timeoutSeconds"],
        "timedOut": result.get("timedOut", False),
        "approval": approval,
    }
    xml_path = Path(f"{built['outputBase']}.xml")
    if xml_path.exists():
        ingestion = workspace.ingest_data(
            built["workspaceId"],
            built["target"],
            "nmap",
            "tool_output",
            "xml",
            xml_path.read_text(encoding="utf-8", errors="replace"),
            metadata,
        )
    else:
        ingestion = store_tool_transcript(built["workspaceId"], built["target"], "nmap", built["profile"], result, metadata)
    action = workspace.record_action(
        built["workspaceId"],
        built["scope"]["host"],
        {
            "type": "tool_run",
            "tool": "nmap",
            "profile": built["profile"],
            "target": built["target"],
            "command": built["command"],
            "shellCommand": built["shellCommand"],
            "outputBase": built["outputBase"],
            "returnCode": result["returnCode"],
            "timeoutSeconds": result["timeoutSeconds"],
            "timedOut": result.get("timedOut", False),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId") if ingestion else "",
        },
        ingestion.get("evidenceId") if ingestion else "",
    )
    workflow_refresh = None
    if ingestion:
        workflow_refresh = fingerprint.refresh_workspace_target(built["workspaceId"], built["scope"]["host"])
    return {**built, "run": result, "action": action, **({"ingestion": ingestion} if ingestion else {}), **({"workflowRefresh": workflow_refresh} if workflow_refresh else {})}


def _finalize_background_run(_record: dict[str, Any], result: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    return _finalize_run(data["built"], result, data.get("approval", {}))


background_jobs.register_finalizer("nmap.run_profile", _finalize_background_run)


def run_profile(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running nmap requires confirm=true.")
    built = build_command(args)
    approval = approval_metadata(args)
    timeout_seconds = int(args.get("timeoutSeconds", 1800))
    event_data = _event_data(built, approval)
    if background_requested(args):
        job = start_background_command(
            built["command"],
            timeout_seconds=timeout_seconds,
            event_type="nmap.run",
            summary=f"Ran nmap profile {built['profile']} against {built['scope']['host']}",
            event_data=event_data,
            tool="nmap.run_profile",
            workspace_id=built["workspaceId"],
            target=built["target"],
            output_path=built["outputBase"],
            finalizer_name="nmap.run_profile",
            finalizer_data={"built": built, "approval": approval},
        )
        return json.dumps(
            {
                **built,
                "background": True,
                "job": job,
                "status": "started",
                "message": f"nmap is running in the background. Poll with jobs.status(jobId={job['jobId']!r}).",
            },
            indent=2,
        )
    result = run_command(
        built["command"],
        timeout_seconds=timeout_seconds,
        event_type="nmap.run",
        summary=f"Ran nmap profile {built['profile']} against {built['scope']['host']}",
        event_data=event_data,
    )
    return json.dumps(_finalize_run(built, result, approval), indent=2)
