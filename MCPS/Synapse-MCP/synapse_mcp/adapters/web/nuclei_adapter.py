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
    get_background_job,
    list_background_jobs,
    require_confirmed,
    require_external_output_allowed,
    require_in_scope,
    run_command,
    start_background_command,
    store_tool_transcript,
    stringify_command,
)


NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")

PROFILES: dict[str, dict[str, Any]] = {
    "low_noise": {
        "description": "Low-noise validation using higher signal severities, conservative rate limits, and context-selected URLs.",
        "severity": ["critical", "high", "medium"],
        "tags": ["cve", "exposure", "misconfig", "default-login", "takeover"],
        "rateLimit": 5,
        "concurrency": 5,
        "bulkSize": 5,
        "retries": 1,
        "requestTimeout": 8,
        "processTimeout": {
            "minimumSeconds": 900,
            "perTargetSeconds": 90,
        },
        "maxContextUrls": 20,
        "includeStateChangingUrls": False,
    },
    "medium": {
        "description": "Balanced assessment profile using workspace context plus common web, CVE, exposure, and API templates.",
        "severity": ["critical", "high", "medium", "low"],
        "tags": ["cve", "exposure", "misconfig", "default-login", "takeover", "tech", "panel", "api", "graphql"],
        "rateLimit": 20,
        "concurrency": 15,
        "bulkSize": 10,
        "retries": 1,
        "requestTimeout": 10,
        "processTimeout": {
            "minimumSeconds": 1800,
            "perTargetSeconds": 120,
        },
        "maxContextUrls": 50,
        "includeStateChangingUrls": False,
    },
    "pentest_aggressive": {
        "description": "Broad pentest profile with higher throughput and broader template selection for explicitly approved testing.",
        "severity": ["critical", "high", "medium", "low", "info"],
        "tags": ["cve", "exposure", "misconfig", "default-login", "takeover", "tech", "panel", "api", "graphql", "fuzz"],
        "rateLimit": 50,
        "concurrency": 25,
        "bulkSize": 25,
        "retries": 1,
        "requestTimeout": 12,
        "processTimeout": {
            "minimumSeconds": 3600,
            "perTargetSeconds": 180,
        },
        "maxContextUrls": 100,
        "includeStateChangingUrls": True,
    },
}


def list_profiles() -> str:
    return json.dumps(PROFILES, indent=2)


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _base_url(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    if not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _context_endpoint_urls(context: dict[str, Any], *, include_state_changing: bool, max_urls: int) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    reasons: list[str] = []
    for collection, reason in (
        ("interestingEndpoints", "included interesting workspace endpoints"),
        ("authSurface", "included authentication-surface endpoints"),
        ("stateChangingCandidates", "included state-changing endpoints"),
    ):
        if collection == "stateChangingCandidates" and not include_state_changing:
            continue
        for item in context.get(collection, []):
            if not isinstance(item, dict):
                continue
            if not include_state_changing and str(item.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            url = _normalize_url(str(item.get("url", "")))
            if url and url not in urls:
                urls.append(url)
        if context.get(collection):
            reasons.append(reason)
    for item in context.get("knownEndpoints", {}).get("interesting", []):
        if not isinstance(item, dict):
            continue
        url = _normalize_url(str(item.get("url", "")))
        if url and url not in urls:
            urls.append(url)
    return urls[:max_urls], reasons


def _context_tags(context: dict[str, Any]) -> tuple[list[str], list[str]]:
    tags: set[str] = set()
    reasons: list[str] = []
    endpoints = json.dumps(
        {
            "interestingEndpoints": context.get("interestingEndpoints", []),
            "authSurface": context.get("authSurface", []),
            "observations": context.get("observations", []),
        },
        sort_keys=True,
    ).lower()
    if "graphql" in endpoints:
        tags.add("graphql")
        reasons.append("workspace context contains GraphQL endpoints or observations")
    if "\"apiroute\": true" in endpoints or "/api" in endpoints or "json_endpoint" in endpoints:
        tags.add("api")
        reasons.append("workspace context contains API or JSON endpoint signals")
    if context.get("authSurface"):
        tags.update({"default-login", "panel"})
        reasons.append("workspace context contains authentication surface")
    if context.get("stateChangingCandidates"):
        tags.add("misconfig")
        reasons.append("workspace context contains state-changing candidates")
    return sorted(tags), reasons


def _scope_checked_urls(urls: list[str], workspace_id: str, *, strict: bool) -> tuple[list[str], list[dict[str, str]]]:
    authorized: list[str] = []
    skipped: list[dict[str, str]] = []
    for url in urls:
        try:
            require_in_scope(url, workspace_id)
        except McpError as exc:
            if strict:
                raise
            skipped.append({"url": url, "error": str(exc)})
            continue
        if url not in authorized:
            authorized.append(url)
    return authorized, skipped


def _target_urls(args: dict[str, Any], target: str, profile: dict[str, Any], workspace_id: str) -> tuple[list[str], dict[str, Any]]:
    explicit_urls = [_normalize_url(item) for item in _as_str_list(args.get("targetUrls"))]
    explicit_urls = [item for item in explicit_urls if item]
    if explicit_urls:
        urls, _ = _scope_checked_urls(explicit_urls, workspace_id, strict=True)
        return urls, {"source": "operator", "reasons": ["operator supplied targetUrls"], "contextUsed": False}

    include_workspace_urls = args.get("includeWorkspaceUrls", True) is not False
    urls = [_base_url(target)]
    adaptation = {"source": "target", "reasons": ["included target base URL"], "contextUsed": False}
    if include_workspace_urls and workspace_id:
        context = workspace.prepare_target_context(workspace_id, target, purpose="nuclei_command_generation", max_tokens=1200)
        context_urls, reasons = _context_endpoint_urls(
            context,
            include_state_changing=bool(profile.get("includeStateChangingUrls")),
            max_urls=int(args.get("maxContextUrls", profile["maxContextUrls"])),
        )
        for url in context_urls:
            if url not in urls:
                urls.append(url)
        urls, skipped = _scope_checked_urls(urls, workspace_id, strict=False)
        adaptation = {
            "source": "workspace_context",
            "reasons": ["included target base URL", *reasons],
            "contextUsed": True,
            "contextSummary": {
                "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
                "interestingEndpointCount": len(context.get("interestingEndpoints", [])),
                "authSurfaceCount": len(context.get("authSurface", [])),
                "stateChangingCandidateCount": len(context.get("stateChangingCandidates", [])),
            },
        }
        if skipped:
            adaptation["skippedOutOfScopeUrls"] = skipped
    else:
        urls, skipped = _scope_checked_urls(urls, workspace_id, strict=False)
        if skipped:
            adaptation["skippedOutOfScopeUrls"] = skipped
    return [item for item in urls if item], adaptation


def _write_target_list(workspace_id: str, host: str, profile_name: str, urls: list[str]) -> Path:
    path = workspace.target_output_path(workspace_id, host, "nuclei", f"{profile_name}-targets.txt")
    path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return path


def _process_timeout_seconds(args: dict[str, Any], profile: dict[str, Any], target_count: int) -> tuple[int, dict[str, Any]]:
    policy = profile["processTimeout"]
    rate_limit = max(int(args.get("rateLimit", profile["rateLimit"])), 1)
    profile_rate_limit = max(int(profile["rateLimit"]), 1)
    rate_scale = max(profile_rate_limit / rate_limit, 1.0)
    target_budget = int(policy["perTargetSeconds"]) * max(target_count, 1)
    calculated = int(max(int(policy["minimumSeconds"]), target_budget) * rate_scale)
    if args.get("timeoutSeconds") is not None:
        explicit = int(args["timeoutSeconds"])
        return explicit, {
            "source": "operator",
            "timeoutSeconds": explicit,
            "recommendedTimeoutSeconds": calculated,
            "warning": "operator timeout is below the profile-derived recommendation"
            if explicit < calculated
            else "",
        }
    return calculated, {
        "source": "profile",
        "timeoutSeconds": calculated,
        "minimumSeconds": int(policy["minimumSeconds"]),
        "perTargetSeconds": int(policy["perTargetSeconds"]),
        "targetCount": target_count,
        "rateLimit": rate_limit,
        "profileRateLimit": profile_rate_limit,
        "rateScale": rate_scale,
    }


def _profile_options(args: dict[str, Any], profile_name: str, profile: dict[str, Any], context: dict[str, Any] | None = None) -> tuple[list[str], list[str], dict[str, Any]]:
    severity = _as_str_list(args.get("severity")) or list(profile["severity"])
    tags = _as_str_list(args.get("tags")) or list(profile["tags"])
    adaptation_reasons = []
    if context:
        inferred_tags, reasons = _context_tags(context)
        for tag in inferred_tags:
            if tag not in tags:
                tags.append(tag)
        adaptation_reasons.extend(reasons)
    return severity, sorted(set(tags)), {"profile": profile_name, "reasons": adaptation_reasons}


def build_command(args: dict[str, Any]) -> dict[str, Any]:
    profile_name = str(args.get("profile", "medium"))
    if profile_name not in PROFILES:
        raise McpError(-32602, f"Unknown nuclei profile: {profile_name}")
    profile = PROFILES[profile_name]
    target = args["target"]
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target, workspace_id)
    require_external_output_allowed(
        args,
        "output",
        workspace.target_output_dir(workspace_id, scope_result["host"], "nuclei"),
    )
    output = Path(args.get("output") or workspace.target_output_path(workspace_id, scope_result["host"], "nuclei", f"{profile_name}.jsonl"))
    context = None
    if args.get("includeWorkspaceUrls", True) is not False:
        context = workspace.prepare_target_context(workspace_id, target, purpose="nuclei_command_generation", max_tokens=1200)
    severity, tags, tag_adaptation = _profile_options(args, profile_name, profile, context)
    urls, target_adaptation = _target_urls(args, target, profile, workspace_id)
    target_list = _write_target_list(workspace_id, scope_result["host"], profile_name, urls)

    cmd = [
        NUCLEI_BIN,
        "-l",
        str(target_list),
        "-jsonl",
        "-o",
        str(output),
        "-severity",
        ",".join(severity),
        "-tags",
        ",".join(tags),
        "-rl",
        str(int(args.get("rateLimit", profile["rateLimit"]))),
        "-c",
        str(int(args.get("concurrency", profile["concurrency"]))),
        "-bs",
        str(int(args.get("bulkSize", profile["bulkSize"]))),
        "-retries",
        str(int(args.get("retries", profile["retries"]))),
        "-timeout",
        str(int(args.get("requestTimeout", profile["requestTimeout"]))),
    ]
    templates = _as_str_list(args.get("templates"))
    for template in templates:
        cmd.extend(["-t", template])
    workflows = _as_str_list(args.get("workflows"))
    for workflow in workflows:
        cmd.extend(["-w", workflow])
    extra_vars = args.get("vars", {})
    if extra_vars is not None and not isinstance(extra_vars, dict):
        raise McpError(-32602, "vars must be an object.")
    for name, value in sorted((extra_vars or {}).items()):
        cmd.extend(["-V", f"{name}={value}"])

    display_cmd = list(cmd)
    credential_meta = None
    credential_id = args.get("credentialId")
    if credential_id:
        credential = credentials.credential_for_target(str(credential_id), target)
        credential_meta = credentials.redact_credential(credential)
        for name, value in credentials.headers_for_credential_target(credential, target).items():
            cmd.extend(["-H", f"{name}: {value}"])
        for name, value in credentials.redacted_headers_for_credential_target(credential, target).items():
            display_cmd.extend(["-H", f"{name}: {value}"])

    adaptation = {
        "profilePolicy": {
            "name": profile_name,
            "description": profile["description"],
            "severity": severity,
            "tags": tags,
            "rateLimit": int(args.get("rateLimit", profile["rateLimit"])),
            "concurrency": int(args.get("concurrency", profile["concurrency"])),
            "bulkSize": int(args.get("bulkSize", profile["bulkSize"])),
            "requestTimeout": int(args.get("requestTimeout", profile["requestTimeout"])),
            "processTimeout": profile["processTimeout"],
        },
        "targetSelection": target_adaptation,
        "tagSelection": tag_adaptation,
        "targetCount": len(urls),
        "targetListPath": str(target_list),
    }
    process_timeout, process_timeout_policy = _process_timeout_seconds(args, profile, len(urls))
    return {
        "profile": profile_name,
        "target": target,
        "workspaceId": workspace_id,
        "scope": scope_result,
        "output": str(output),
        "targetList": str(target_list),
        "targets": urls,
        "severity": severity,
        "tags": tags,
        "command": display_cmd,
        "_executionCommand": cmd,
        "shellCommand": stringify_command(display_cmd),
        "rationale": profile["description"],
        "adaptation": adaptation,
        "executionPolicy": {
            "requestTimeoutSeconds": int(args.get("requestTimeout", profile["requestTimeout"])),
            "processTimeoutSeconds": process_timeout,
            "processTimeoutPolicy": process_timeout_policy,
        },
        **({"credential": credential_meta} if credential_meta else {}),
    }


def _finalize_run(built: dict[str, Any], result: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "profile": built["profile"],
        "target": built["target"],
        "host": built["scope"]["host"],
        "command": built["command"],
        "outputPath": built["output"],
        "targetList": built["targetList"],
        "targets": built["targets"],
        "severity": built["severity"],
        "tags": built["tags"],
        "adaptation": built["adaptation"],
        "executionPolicy": built["executionPolicy"],
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
            "nuclei",
            "tool_output",
            "jsonl",
            output_path.read_text(encoding="utf-8", errors="replace"),
            metadata,
        )
    else:
        ingestion = store_tool_transcript(built["workspaceId"], built["target"], "nuclei", built["profile"], result, metadata)
    action = workspace.record_action(
        built["workspaceId"],
        built["scope"]["host"],
        {
            "type": "tool_run",
            "tool": "nuclei",
            "profile": built["profile"],
            "target": built["target"],
            "command": built["command"],
            "shellCommand": built["shellCommand"],
            "outputPath": built["output"],
            "targetList": built["targetList"],
            "targetCount": len(built["targets"]),
            "returnCode": result["returnCode"],
            "timeoutSeconds": result["timeoutSeconds"],
            "timedOut": result.get("timedOut", False),
            "executionPolicy": built["executionPolicy"],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId") if ingestion else "",
        },
        ingestion.get("evidenceId") if ingestion else "",
    )
    visible_built = {key: value for key, value in built.items() if not key.startswith("_")}
    return {**visible_built, "run": result, "action": action, "ingestion": ingestion}


def _nuclei_event_data(built: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    return {
        "workspaceId": built["workspaceId"],
        "target": built["target"],
        "host": built["scope"]["host"],
        "profile": built["profile"],
        "targetCount": len(built["targets"]),
        "executionPolicy": built["executionPolicy"],
        "approval": approval,
    }


def _finalize_background_run(_record: dict[str, Any], result: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    return _finalize_run(data["built"], result, data.get("approval", {}))


background_jobs.register_finalizer("nuclei.run_profile", _finalize_background_run)


def run_profile(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running nuclei requires confirm=true.")
    built = build_command(args)
    approval = approval_metadata(args)
    process_timeout = int(built["executionPolicy"]["processTimeoutSeconds"])
    run_in_background = background_requested(args)
    event_data = _nuclei_event_data(built, approval)
    if run_in_background:
        visible_built = {key: value for key, value in built.items() if not key.startswith("_")}
        job = start_background_command(
            built["_executionCommand"],
            timeout_seconds=process_timeout,
            event_type="nuclei.run",
            summary=f"Ran nuclei profile {built['profile']} against {built['scope']['host']}",
            display_cmd=built["command"],
            event_data=event_data,
            tool="nuclei.run_profile",
            workspace_id=built["workspaceId"],
            target=built["target"],
            output_path=built["output"],
            finalizer_name="nuclei.run_profile",
            finalizer_data={"built": visible_built, "approval": approval},
        )
        return json.dumps(
            {
                **visible_built,
                "background": True,
                "job": job,
                "status": "started",
                "message": f"Nuclei is running in the background. Poll with jobs.status(jobId={job['jobId']!r}).",
            },
            indent=2,
        )
    result = run_command(
        built["_executionCommand"],
        timeout_seconds=process_timeout,
        event_type="nuclei.run",
        summary=f"Ran nuclei profile {built['profile']} against {built['scope']['host']}",
        display_cmd=built["command"],
        event_data=event_data,
    )
    return json.dumps(_finalize_run(built, result, approval), indent=2)


def job_status(args: dict[str, Any]) -> str:
    job = get_background_job(str(args["jobId"]))
    return json.dumps(job, indent=2)


def list_jobs(args: dict[str, Any]) -> str:
    return json.dumps(list_background_jobs(int(args.get("limit", 20))), indent=2)
