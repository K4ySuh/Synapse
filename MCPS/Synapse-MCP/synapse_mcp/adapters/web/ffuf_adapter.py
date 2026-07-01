# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ...core import background_jobs, credentials, workspace
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


FFUF_BIN = os.environ.get("FFUF_BIN", "ffuf")

PROFILES: dict[str, dict[str, Any]] = {
    "low_noise": {
        "description": "Low-noise directory/file discovery with auto-calibration, conservative threads, and JSON output.",
        "threads": 10,
        "mode": "dir",
    },
    "medium": {
        "description": "Balanced directory/file discovery with auto-calibration, moderate threads, and JSON output.",
        "threads": 20,
        "mode": "dir",
    },
    "pentest_aggressive": {
        "description": "Explicitly approved higher-throughput directory/file discovery with auto-calibration and JSON output.",
        "threads": 40,
        "mode": "dir",
    },
}


def list_profiles() -> str:
    return json.dumps(PROFILES, indent=2)


def build_command(args: dict[str, Any]) -> dict[str, Any]:
    profile_name = args.get("profile", "medium")
    if profile_name not in PROFILES:
        raise McpError(-32602, f"Unknown ffuf profile: {profile_name}")
    profile = PROFILES[profile_name]
    target = args["target"]
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target, workspace_id)
    wordlist = Path(args["wordlist"]).expanduser()
    if not wordlist.exists():
        raise McpError(-32602, f"Wordlist not found: {wordlist}")
    threads = int(args.get("threads", profile["threads"]))
    timeout = int(args.get("requestTimeout", 10))
    require_external_output_allowed(
        args,
        "output",
        workspace.target_output_dir(workspace_id, scope_result["host"], "ffuf"),
    )
    output = Path(args.get("output") or workspace.target_output_path(workspace_id, scope_result["host"], "ffuf", f"{profile_name}.json"))

    cmd = [FFUF_BIN, "-w", str(wordlist), "-u", ffuf_url(profile["mode"], target), "-t", str(threads), "-timeout", str(timeout), "-ac"]
    display_cmd = list(cmd)
    if profile["mode"] == "vhost":
        hostname = scope_result["host"]
        cmd.extend(["-H", f"Host: FUZZ.{hostname}"])
        display_cmd.extend(["-H", f"Host: FUZZ.{hostname}"])
    credential_meta = None
    credential_id = args.get("credentialId")
    if credential_id:
        credential = credentials.credential_for_target(str(credential_id), target)
        credential_meta = credentials.redact_credential(credential)
        for name, value in credentials.headers_for_credential_target(credential, target).items():
            cmd.extend(["-H", f"{name}: {value}"])
        for name, value in credentials.redacted_headers_for_credential_target(credential, target).items():
            display_cmd.extend(["-H", f"{name}: {value}"])
    for code in args.get("matchCodes", []):
        cmd.extend(["-mc", str(code)])
        display_cmd.extend(["-mc", str(code)])
    for size in args.get("filterSizes", []):
        cmd.extend(["-fs", str(size)])
        display_cmd.extend(["-fs", str(size)])
    extensions = args.get("extensions", [])
    if extensions and profile["mode"] == "dir":
        normalized_extensions = ",".join(normalize_extension(ext) for ext in extensions)
        cmd.extend(["-e", normalized_extensions])
        display_cmd.extend(["-e", normalized_extensions])
    cmd.extend(["-of", "json", "-o", str(output)])
    display_cmd.extend(["-of", "json", "-o", str(output)])
    return {
        "profile": profile_name,
        "target": target,
        "workspaceId": workspace_id,
        "scope": scope_result,
        "output": str(output),
        "command": display_cmd,
        "_executionCommand": cmd,
        "shellCommand": stringify_command(display_cmd),
        "rationale": profile["description"],
        **({"credential": credential_meta} if credential_meta else {}),
    }


def ffuf_url(mode: str, target: str) -> str:
    if "FUZZ" in target:
        return target
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    if mode == "param":
        query = parsed.query + ("&" if parsed.query else "") + "FUZZ=1"
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, parsed.fragment))
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path + "FUZZ", parsed.query, parsed.fragment))


def normalize_extension(value: str) -> str:
    value = value.strip()
    return value if value.startswith(".") else f".{value}"


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
        "outputPath": built["output"],
        "returnCode": result["returnCode"],
        "timeoutSeconds": result["timeoutSeconds"],
        "timedOut": result.get("timedOut", False),
        "approval": approval,
    }
    output_path = Path(built["output"])
    if output_path.exists():
        ingestion = workspace.ingest_data(
            built["workspaceId"],
            built["target"],
            "ffuf",
            "tool_output",
            "json",
            output_path.read_text(encoding="utf-8", errors="replace"),
            metadata,
        )
    else:
        ingestion = store_tool_transcript(built["workspaceId"], built["target"], "ffuf", built["profile"], result, metadata)
    action = workspace.record_action(
        built["workspaceId"],
        built["scope"]["host"],
        {
            "type": "tool_run",
            "tool": "ffuf",
            "profile": built["profile"],
            "target": built["target"],
            "command": built["command"],
            "shellCommand": built["shellCommand"],
            "outputPath": built["output"],
            "returnCode": result["returnCode"],
            "timeoutSeconds": result["timeoutSeconds"],
            "timedOut": result.get("timedOut", False),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId") if ingestion else "",
        },
        ingestion.get("evidenceId") if ingestion else "",
    )
    visible_built = {key: value for key, value in built.items() if not key.startswith("_")}
    return {**visible_built, "run": result, "action": action, **({"ingestion": ingestion} if ingestion else {})}


def _finalize_background_run(_record: dict[str, Any], result: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    return _finalize_run(data["built"], result, data.get("approval", {}))


background_jobs.register_finalizer("ffuf.run_profile", _finalize_background_run)


def run_profile(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running ffuf requires confirm=true.")
    built = build_command(args)
    approval = approval_metadata(args)
    timeout_seconds = int(args.get("timeoutSeconds", 1800))
    event_data = _event_data(built, approval)
    if background_requested(args):
        visible_built = {key: value for key, value in built.items() if not key.startswith("_")}
        job = start_background_command(
            built["_executionCommand"],
            timeout_seconds=timeout_seconds,
            event_type="ffuf.run",
            summary=f"Ran ffuf profile {built['profile']} against {built['scope']['host']}",
            display_cmd=built["command"],
            event_data=event_data,
            tool="ffuf.run_profile",
            workspace_id=built["workspaceId"],
            target=built["target"],
            output_path=built["output"],
            finalizer_name="ffuf.run_profile",
            finalizer_data={"built": visible_built, "approval": approval},
        )
        return json.dumps(
            {
                **visible_built,
                "background": True,
                "job": job,
                "status": "started",
                "message": f"ffuf is running in the background. Poll with jobs.status(jobId={job['jobId']!r}).",
            },
            indent=2,
        )
    result = run_command(
        built["_executionCommand"],
        timeout_seconds=timeout_seconds,
        event_type="ffuf.run",
        summary=f"Ran ffuf profile {built['profile']} against {built['scope']['host']}",
        display_cmd=built["command"],
        event_data=event_data,
    )
    return json.dumps(_finalize_run(built, result, approval), indent=2)
