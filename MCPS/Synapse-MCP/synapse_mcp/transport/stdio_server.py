#!/usr/bin/env python3
# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Any

from .. import __version__
from ..adapters.infra import nmap_adapter, shodan_adapter
from ..adapters.social import pretext_generator
from ..adapters.web import (
    access_control,
    command_injection_adapter,
    cors,
    crawler_adapter,
    cve_intel,
    csrf,
    ffuf_adapter,
    graphql,
    headers_cookies,
    insecure_deser,
    js_intel,
    jwt_analysis,
    lfi_rfi,
    nuclei_adapter,
    open_redirect_adapter,
    spec_import,
    sqlmap_adapter,
    ssrf_adapter,
    ssi,
    ssti,
    xss_adapter,
    xxe,
    tls_posture,
)
from ..core import background_jobs, cache, credentials, documentation, dumps, evidence, fingerprint, perimeter, scope, workspace
from ..core.adapters import default_registry as adapter_registry
from ..core.errors import McpError
from ..core.paths import PROMPT_PATH
from ..core.purple_team import gap_analysis
from ..app.actions.legacy_bridge import bind_retained_legacy_implementation


PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "synapse-mcp"
SERVER_VERSION = __version__
MAIN_PROMPT_NAME = "synapse-main"


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


DEFAULT_TOOL_CALL_DEADLINE_SECONDS = _float_env("SYNAPSE_MCP_TOOL_TIMEOUT_SECONDS", 45)
FAST_TOOL_CALL_DEADLINE_SECONDS = _float_env("SYNAPSE_MCP_FAST_TOOL_TIMEOUT_SECONDS", 15)
STATUS_TOOL_CALL_DEADLINE_SECONDS = _float_env("SYNAPSE_MCP_STATUS_TOOL_TIMEOUT_SECONDS", 30)

FAST_TOOLS = {
    "jobs.list",
    "jobs.cancel",
    "adapters.list",
    "adapters.capabilities",
    "documentation.list_templates",
    "scope.check_target",
    "credentials.list",
    "credentials.get",
    "dumps.list",
    "cache.inspect_scope_data",
    "cache.inspect_generated_artifacts",
    "ffuf.profiles",
    "nuclei.profiles",
    "nmap.profiles",
    "shodan.session_key.status",
    "cve.capabilities",
    "cve.sources",
    "cve.session_key.status",
    "shodan.company_queries",
    "evidence.tail",
    "fingerprint.read_host",
    "approve_pretext_candidate",
    "mark_detection_outcome",
}
# The MCP stdin loop is single-flight, so this pool does not add request-level
# concurrency. Its purpose is timeout recovery: a tool that exceeds its deadline
# keeps running in its worker thread (Python cannot safely kill it), so a few
# spare workers keep one orphaned thread from starving every later call —
# including jobs.status / jobs.cancel. Workspace writes are flock-guarded and
# JSON writes use tmp+rename; long-running work should still use background
# jobs so synchronous workers stay short-lived. Override with
# SYNAPSE_MCP_TOOL_WORKERS.
_TOOL_EXECUTOR_MAX_WORKERS = max(_int_env("SYNAPSE_MCP_TOOL_WORKERS", 4), 1)
_TOOL_EXECUTOR = ThreadPoolExecutor(max_workers=_TOOL_EXECUTOR_MAX_WORKERS, thread_name_prefix="synapse-mcp-tool")


class ToolCallTimeout(Exception):
    def __init__(self, tool_name: str, seconds: float):
        super().__init__(f"MCP tool call timed out after {seconds:g}s: {tool_name}")
        self.tool_name = tool_name
        self.seconds = seconds

HTTP_POLICY_PROPERTIES: dict[str, Any] = {
    "httpBackend": {"type": "string", "enum": ["direct", "proxy", "disabled"], "default": "direct"},
    "proxyUrl": {"type": "string"},
    "disableTraffic": {"type": "boolean", "default": False},
    "maxBodyBytes": {"type": "integer", "minimum": 0},
    "followRedirects": {"type": "boolean", "default": True},
    "verifyTls": {"type": "boolean", "default": True},
    "http2": {"type": "boolean", "default": False},
}
CRAWLER_HTTP_POLICY_PROPERTIES = {key: value for key, value in HTTP_POLICY_PROPERTIES.items() if key != "followRedirects"}
REDACTION_MODE_VALUES = ["operator", "operator_raw", "high_level", "internal", "raw", "safe"]


def _tool_deadline_seconds(name: str, _args: dict[str, Any]) -> float:
    if name == "jobs.status":
        return STATUS_TOOL_CALL_DEADLINE_SECONDS
    if name in FAST_TOOLS:
        return FAST_TOOL_CALL_DEADLINE_SECONDS
    return DEFAULT_TOOL_CALL_DEADLINE_SECONDS


def call_tool_with_deadline(name: str, args: dict[str, Any]) -> str:
    seconds = _tool_deadline_seconds(name, args)
    if seconds <= 0:
        return call_tool(name, args)
    future = _TOOL_EXECUTOR.submit(call_tool, name, args)
    try:
        return future.result(timeout=seconds)
    except TimeoutError as exc:
        # Python cannot safely stop the running worker thread. The call is left
        # to finish; Synapse state writes use tmp+rename so late completion does
        # not corrupt JSON files, and spare executor workers
        # (SYNAPSE_MCP_TOOL_WORKERS) keep the orphaned thread from starving
        # later calls such as jobs.status / jobs.cancel.
        raise ToolCallTimeout(name, seconds)
    finally:
        if future.done():
            future.cancel()


def _timeout_error_message(exc: ToolCallTimeout) -> str:
    if exc.tool_name == "jobs.status":
        return (
            f"{exc}. Job status finalization may still be recoverable; retry jobs.status, "
            "inspect jobs.list(activeOnly=true), or cancel the job if it remains active."
        )
    return (
        f"{exc}. The Synapse MCP server recovered and is ready for another request. "
        "For long-running work, use the tool's background job mode and poll with jobs.status(jobId=...)."
    )


PASSIVE_ANALYSIS_ACTION_EXCLUDED_ROOTS = {"documentation", "access_control", "perimeter", "fingerprint", "js", "nuclei"}


def _is_recordable_passive_analysis_tool(name: str) -> bool:
    root = name.split(".", 1)[0].lower()
    if root in PASSIVE_ANALYSIS_ACTION_EXCLUDED_ROOTS:
        return False
    return name.endswith(".analyze_workspace") or name.endswith(".passive_analyze")


def _tool_result_has_error(result: str) -> bool:
    from ..app.actions.outcomes import legacy_payload_signals_error

    return legacy_payload_signals_error(result)


def _record_passive_analysis_action(name: str, args: dict[str, Any], result: str) -> None:
    if not _is_recordable_passive_analysis_tool(name) or _tool_result_has_error(result):
        return
    workspace_id = args.get("workspaceId")
    target = args.get("target")
    if not workspace_id or not target:
        return
    workspace.record_action(
        str(workspace_id),
        str(target),
        {
            "type": "passive_analysis",
            "tool": name,
            "target": str(target),
        },
    )


_LEGACY_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "jobs.list",
        "description": "List recent Synapse background jobs, optionally limited to active jobs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "default": 20},
                "activeOnly": {"type": "boolean", "default": False},
                "workspaceId": {"type": "string"},
                "includeResult": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "jobs.status",
        "description": "Return status and final result metadata for a Synapse background job.",
    },
    {
        "name": "jobs.cancel",
        "description": "Cancel a running Synapse background job by jobId.",
        "inputSchema": {
            "type": "object",
            "properties": {"jobId": {"type": "string"}},
            "required": ["jobId"],
        },
    },
    {
        "name": "adapters.list",
        "description": "List registered Synapse adapters and high-level safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "adapters.capabilities",
        "description": "Return full capability and safety metadata for one registered Synapse adapter.",
        "inputSchema": {
            "type": "object",
            "properties": {"adapter": {"type": "string"}},
            "required": ["adapter"],
        },
    },
    {
        "name": "documentation.list_templates",
        "description": "List built-in documentation templates and their expected context types.",
        "inputSchema": {
            "type": "object",
            "properties": {"contextType": {"type": "string"}},
        },
    },
    {
        "name": "documentation.list_layers",
        "description": "List normalized passive report layers that can be rendered from workspace state.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "perimeter.analyze_workspace",
        "description": "Passively classify external perimeter assets, web applications, technologies, login portals, and review candidates from stored workspace data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "includeTargets": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "perimeter.build_summary",
        "description": "Return stored external perimeter inventory summary, refreshing from workspace data when requested.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "perimeter.render_report",
        "description": "Render external perimeter inventory and review items as Markdown or HTML from stored workspace data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "refresh": {"type": "boolean", "default": False},
                "format": {"type": "string", "enum": ["markdown", "html"], "default": "markdown"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.build_report_context",
        "description": "Build a structured report context from normalized workspace data without rendering it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "assessmentType": {"type": "string"},
                "startDate": {"type": "string"},
                "endDate": {"type": "string"},
                "includeFindings": {"type": "boolean", "default": True},
                "includeEvidence": {"type": "boolean", "default": True},
                "includeCoverage": {"type": "boolean", "default": True},
                "redactionMode": {"type": "string", "default": "high_level"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.build_layer_report_context",
        "description": "Build a normalized passive report context for one workspace layer without rendering it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "layer": {"type": "string", "enum": ["perimeter", "js", "auth", "access_control", "web_vulnerabilities", "cve", "engagement"]},
                "refresh": {"type": "boolean", "default": False},
                "redactionMode": {"type": "string", "default": "high_level"},
            },
            "required": ["workspaceId", "layer"],
        },
    },
    {
        "name": "documentation.build_workspace_report_context",
        "description": "Build a normalized passive report context combining selected workspace layers without rendering it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "targets": {"type": "array", "items": {"type": "string"}},
                "layers": {"type": "array", "items": {"type": "string"}},
                "refresh": {"type": "boolean", "default": False},
                "redactionMode": {"type": "string", "default": "high_level"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.plan_scope_groups",
        "description": "Plan stable logical target groups for bounded analysis and reporting without changing workspace authorization scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "targetBatchSize": {"type": "integer", "minimum": 1, "maximum": 40, "default": 20},
                "groupCursor": {"type": "integer", "minimum": 0, "default": 0},
                "groupLimit": {"type": "integer", "minimum": 1, "maximum": 40, "default": 5},
                "includeTargets": {"type": "boolean", "default": False},
                "scopeGroups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "targets": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["targets"],
                    },
                },
                "refreshGroups": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.prepare_validation_batch",
        "description": "Prepare one passive, resumable page of candidate validations for a scope group. This sends no traffic; execution still requires exact approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "groupId": {"type": "string"},
                "batchSize": {"type": "integer", "minimum": 1, "maximum": 40, "default": 20},
                "cursor": {"type": "integer", "minimum": 0, "default": 0},
                "targetBatchSize": {"type": "integer", "minimum": 1, "maximum": 40, "default": 20},
                "refreshQueue": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.render_workspace_report_batches",
        "description": "Render bounded, resumable workspace report groups and record-sized report parts under reports/<workspace>/<run>/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "runId": {"type": "string"},
                "targetBatchSize": {"type": "integer", "minimum": 1, "maximum": 40, "default": 20},
                "recordBatchSize": {"type": "integer", "minimum": 1, "maximum": 40, "default": 20},
                "groupCursor": {"type": "integer", "minimum": 0, "default": 0},
                "partCursor": {"type": "integer", "minimum": 0, "default": 0},
                "maxParts": {"type": "integer", "minimum": 1, "maximum": 40, "default": 1},
                "maxGroups": {"type": "integer", "minimum": 1, "maximum": 10, "default": 1},
                "layers": {"type": "array", "items": {"type": "string"}},
                "refresh": {"type": "boolean", "default": False},
                "refreshGroups": {"type": "boolean", "default": False},
                "redactionMode": {"type": "string", "default": "internal"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.build_finding_context",
        "description": "Build a structured single-finding context with linked evidence metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "includeEvidence": {"type": "boolean", "default": True},
                "redactionMode": {"type": "string", "default": "high_level"},
                "includeRawHttp": {"type": "boolean", "default": False},
                "includeRequestBodies": {"type": "boolean", "default": False},
                "includeResponseBodies": {"type": "boolean", "default": False},
                "includeCredentials": {"type": "boolean", "default": False},
                "includeApprovalMetadata": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target", "findingId"],
        },
    },
    {
        "name": "documentation.build_finding_draft",
        "description": "Build an operator-editable finding draft from one workspace finding and linked evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "template": {"type": "string", "default": "standard_finding"},
                "redactionMode": {"type": "string", "default": "high_level"},
            },
            "required": ["workspaceId", "target", "findingId"],
        },
    },
    {
        "name": "documentation.build_evidence_pack",
        "description": "Build a structured evidence pack for a target or finding using the requested redaction policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "redactionMode": {"type": "string", "default": "high_level"},
                "includeRawHttp": {"type": "boolean", "default": False},
                "includeRequestBodies": {"type": "boolean", "default": False},
                "includeResponseBodies": {"type": "boolean", "default": False},
                "includeCredentials": {"type": "boolean", "default": False},
                "includeApprovalMetadata": {"type": "boolean", "default": True},
                "includeHashes": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "documentation.summarize_coverage",
        "description": "Summarize workspace coverage, adapter usage, findings by severity, and inferred untested areas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "redactionMode": {"type": "string", "default": "high_level"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.render_markdown",
        "description": "Render a documentation context or workspace-derived context using a built-in Markdown template.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "template": {"type": "string", "default": "standard_markdown_report"},
                "contextType": {"type": "string"},
                "context": {"type": "object", "additionalProperties": True},
                "redactionMode": {"type": "string", "default": "high_level"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.render_layer_report",
        "description": "Render one normalized passive workspace layer report as HTML or Markdown. Defaults to HTML.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "layer": {"type": "string", "enum": ["perimeter", "js", "auth", "access_control", "web_vulnerabilities", "cve", "engagement"]},
                "refresh": {"type": "boolean", "default": False},
                "format": {"type": "string", "enum": ["html", "markdown"], "default": "html"},
                "redactionMode": {"type": "string", "default": "high_level"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean", "default": False},
                "returnContent": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId", "layer"],
        },
    },
    {
        "name": "documentation.render_workspace_report",
        "description": "Render the default all-layers workspace report as HTML or Markdown from normalized passive workspace state. Defaults to HTML.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "targets": {"type": "array", "items": {"type": "string"}},
                "layers": {"type": "array", "items": {"type": "string"}},
                "refresh": {"type": "boolean", "default": False},
                "format": {"type": "string", "enum": ["html", "markdown"], "default": "html"},
                "redactionMode": {"type": "string", "default": "internal"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean", "default": False},
                "returnContent": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.render_assessment_summary",
        "description": "Render the default assessment summary report from stored workspace context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "assessmentType": {"type": "string"},
                "startDate": {"type": "string"},
                "endDate": {"type": "string"},
                "includeFindings": {"type": "boolean", "default": True},
                "includeEvidence": {"type": "boolean", "default": True},
                "includeCoverage": {"type": "boolean", "default": True},
                "template": {"type": "string", "default": "assessment_summary_report"},
                "redactionMode": {"type": "string", "default": "high_level"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "documentation.export_json",
        "description": "Export a documentation context as JSON under the workspace reports directory or an approved output path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "contextType": {"type": "string", "default": "report"},
                "context": {"type": "object", "additionalProperties": True},
                "redactionMode": {"type": "string", "default": "high_level"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "scope.set",
        "description": "Persist the authorized host allowlist for Synapse tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
                "patterns": {"type": "array", "items": {"type": "string"}},
                "cidrs": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "organization": {"type": "string"},
                "workspaceId": {"type": "string"},
                "cursor": {"type": "string"},
                "inventoryLimit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "includeInventory": {"type": "boolean", "default": False},
            },
            "required": ["hosts"],
        },
    },
    {
        "name": "project.start",
        "description": "Initialize project scope/evidence folders and optionally fingerprint hosts from an offline Burp dump.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "organization": {"type": "string"},
                "workspaceId": {"type": "string"},
                "hosts": {"type": "array", "items": {"type": "string"}},
                "patterns": {"type": "array", "items": {"type": "string"}},
                "cidrs": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "dumpPath": {"type": "string"},
                "fingerprint": {"type": "boolean", "default": True},
                "limit": {"type": "integer", "minimum": 1, "default": 5000},
                "cursor": {"type": "string"},
                "inventoryLimit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "includeInventory": {"type": "boolean", "default": False},
            },
            "required": ["organization", "hosts"],
        },
    },
    {
        "name": "scope.check_target",
        "description": "Check whether a target host or URL is in the persisted authorized scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "cursor": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "includeInventory": {"type": "boolean", "default": False},
            },
            "required": ["target"],
        },
    },
    {
        "name": "workspace.create",
        "description": "Create or update a file-backed Synapse workspace for an engagement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "organization": {"type": "string"},
                "notes": {"type": "string"},
                "hosts": {"type": "array", "items": {"type": "string"}},
                "patterns": {"type": "array", "items": {"type": "string"}},
                "cidrs": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "workspace.add_target",
        "description": "Add or update a target record inside a Synapse workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "kind": {"type": "string", "default": "host"},
                "notes": {"type": "string"},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "workspace.ingest_data",
        "description": "Store raw data, normalize entities, update workspace state, and return compact LLM context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "source": {"type": "string"},
                "dataType": {"type": "string", "default": "tool_output"},
                "format": {"type": "string", "default": "text"},
                "rawData": {"type": "string"},
                "metadata": {"type": "object", "additionalProperties": True},
            },
            "required": ["target", "source", "rawData"],
        },
    },
    {
        "name": "workspace.prepare_target_context",
        "description": "Return compact target context assembled from normalized workspace entities and evidence references.",
    },
    {
        "name": "workspace.summary",
        "description": "Summarize targets and normalized entity counts for one Synapse workspace.",
    },
    {
        "name": "workspace.delete",
        "description": "Inspect or permanently erase one local workspace directory. Requires confirm=true to delete.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "confirm": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId"],
        },
    },
    {
        "name": "workspace.create_finding",
        "description": "Record an operator-reviewed finding in the workspace knowledge layer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string", "default": "info"},
                "confidence": {"type": "string", "default": "low"},
                "status": {"type": "string", "default": "confirmed"},
                "description": {"type": "string"},
                "evidenceIds": {"type": "array", "items": {"type": "string"}},
                "affectedAssets": {"type": "array", "items": {"type": "string"}},
                "reproductionSteps": {"type": "array", "items": {"type": "string"}},
                "impact": {"type": "string"},
                "remediation": {"type": "string"},
                "operatorReviewed": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target", "title"],
        },
    },
    {
        "name": "workspace.update_finding",
        "description": "Update lifecycle fields for a workspace finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "updates": {"type": "object", "additionalProperties": True},
            },
            "required": ["workspaceId", "target", "findingId", "updates"],
        },
    },
    {
        "name": "workspace.promote_observation_to_finding",
        "description": "Promote a normalized observation or candidate to a lifecycle-managed finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "observationId": {"type": "string"},
                "observationKey": {"type": "string"},
                "type": {"type": "string"},
                "value": {"type": "string"},
                "title": {"type": "string"},
                "severity": {"type": "string", "default": "info"},
                "confidence": {"type": "string", "default": "low"},
                "status": {"type": "string", "default": "candidate"},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "workspace.link_evidence_to_finding",
        "description": "Attach evidence IDs to an existing finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "evidenceIds": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["workspaceId", "target", "findingId", "evidenceIds"],
        },
    },
    {
        "name": "workspace.mark_finding_reviewed",
        "description": "Mark a finding as operator-reviewed and set its reviewed status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
                "status": {"type": "string", "default": "confirmed"},
                "reviewer": {"type": "string", "default": "operator"},
                "notes": {"type": "string"},
            },
            "required": ["workspaceId", "target", "findingId"],
        },
    },
    {
        "name": "approve_pretext_candidate",
        "description": "Approve one draft phishing pretext candidate after operator review. Requires confirm=true to change status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "entityKey": {"type": "string"},
                "confirm": {"type": "boolean", "default": False},
            },
            "required": ["workspaceId", "target", "entityKey"],
        },
    },
    {
        "name": "mark_detection_outcome",
        "description": "Record whether a blue-team control detected a tagged action and generate/update the corresponding detection-gap entity when a MITRE mapping exists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "actionKey": {"type": "string"},
                "detected": {"type": ["boolean", "null"]},
                "notes": {"type": "string", "default": ""},
            },
            "required": ["workspaceId", "target", "actionKey", "detected"],
        },
    },
    {
        "name": "workspace.set_entity_reportable",
        "description": (
            "Set isReportable on matching workspace entities in any layer (services, endpoints, "
            "parameters, findings, actions, observations) and archive the disposition. Records "
            "marked isReportable=false stay in workspace state for later granular analysis but are "
            "excluded from generated reports. Default is true; flip to false on operator review."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "entityType": {
                    "type": "string",
                    "enum": ["services", "endpoints", "parameters", "findings", "actions", "observations", "pretextCandidates", "detectionGaps"],
                },
                "isReportable": {"type": "boolean"},
                "selector": {
                    "type": "object",
                    "description": (
                        "Identity matchers (key, id, findingId, observationId, observationKey, "
                        "candidateId, actionId) and/or attribute matchers (type, value, valueContains, "
                        "urlContains). Attribute matchers enable bulk disposition across a layer."
                    ),
                    "additionalProperties": True,
                },
                "reason": {"type": "string"},
                "reviewer": {"type": "string", "default": "operator"},
            },
            "required": ["workspaceId", "target", "entityType", "isReportable", "selector"],
        },
    },
    {
        "name": "workspace.record_candidate_validation",
        "description": (
            "Record a validation outcome on a candidate observation, common to every DATA-model "
            "layer. Works on the consolidated web test_candidate (per vulnClass inside "
            "candidateDetails) and on any single-class *_candidate observation (e.g. access-control "
            "candidates). outcome=refuted retains the record but marks it retired/non-reportable "
            "when nothing reportable remains; outcome=confirmed keeps it reportable and returns a "
            "finding draft (promote it via workspace.promote_observation_to_finding)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "selector": {
                    "type": "object",
                    "description": (
                        "Identity matchers (key, id, observationId, observationKey, candidateId) "
                        "and/or attribute matchers (type, value, valueContains, urlContains)."
                    ),
                    "additionalProperties": True,
                },
                "outcome": {
                    "type": "string",
                    "enum": ["proposed", "testing", "confirmed", "refuted", "inconclusive"],
                },
                "vulnClass": {
                    "type": "string",
                    "description": "For a test_candidate, the class to update (sqli/ssrf/lfi/ssti). Omit to apply to all classes on the surface.",
                },
                "evidenceIds": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "reviewer": {"type": "string", "default": "operator"},
            },
            "required": ["workspaceId", "target", "selector", "outcome"],
        },
    },
    {
        "name": "workspace.curate_candidate",
        "description": (
            "Agent curation of a surface test_candidate: precisely add or remove vulnerability "
            "classes instead of adapters blanketing every parameter. Identify the surface by "
            "candidateId or by url (with optional method/parameter/location); a url also lets a "
            "not-yet-existing candidate be created for add. Removing a class marks it refuted and "
            "drops it from candidateFor (retained + marked); the surface is retired when nothing "
            "reportable remains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "surfaceSelector": {
                    "type": "object",
                    "description": "candidateId, or url (+ optional method/parameter/location) identifying the surface.",
                    "additionalProperties": True,
                },
                "add": {"type": "array", "items": {"type": "string"}, "description": "Vuln classes to add (e.g. sqli, ssrf, lfi, ssti)."},
                "remove": {"type": "array", "items": {"type": "string"}, "description": "Vuln classes to remove/refute."},
                "reason": {"type": "string"},
                "reviewer": {"type": "string", "default": "agent"},
            },
            "required": ["workspaceId", "target", "surfaceSelector"],
        },
    },
    {
        "name": "workspace.export_finding_context",
        "description": "Export one finding with linked evidence metadata and markdown report location.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "findingId": {"type": "string"},
            },
            "required": ["workspaceId", "target", "findingId"],
        },
    },
    {
        "name": "credentials.set",
        "description": "Store or replace a scoped HTTP credential. Secrets are persisted locally and redacted from responses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "type": {"type": "string", "enum": ["bearer", "basic", "cookie", "header", "session"]},
                "scopes": {"type": "array", "items": {"type": "string"}},
                "secret": {"type": "string"},
                "label": {"type": "string"},
                "username": {"type": "string"},
                "headerName": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["id", "type", "scopes", "secret", "confirm"],
        },
    },
    {
        "name": "credentials.list",
        "description": "List stored scoped credentials with secrets redacted.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "credentials.set_auth_profile",
        "description": "Store a scoped HTTP login profile used to obtain or refresh a cookie credential. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "credentialId": {"type": "string"},
                "scopes": {"type": "array", "items": {"type": "string"}},
                "loginUrl": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "POST"},
                "contentType": {"type": "string", "enum": ["form", "json"], "default": "form"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "usernameField": {"type": "string", "default": "username"},
                "passwordField": {"type": "string", "default": "password"},
                "extraFields": {"type": "object", "additionalProperties": True},
                "cookieNames": {"type": "array", "items": {"type": "string"}},
                "successStatusCodes": {"type": "array", "items": {"type": "integer"}},
                "successPattern": {"type": "string"},
                "failurePattern": {"type": "string"},
                "label": {"type": "string"},
                "allowCredentialInUrl": {"type": "boolean"},
                "confirm": {"type": "boolean"},
            },
            "required": ["id", "credentialId", "scopes", "loginUrl", "username", "password", "confirm"],
        },
    },
    {
        "name": "credentials.set_browser_auth_profile",
        "description": "Store a scoped browser authentication profile for JavaScript, SSO, MFA, or multi-step login flows. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "credentialId": {"type": "string"},
                "scopes": {"type": "array", "items": {"type": "string"}},
                "loginUrl": {"type": "string"},
                "provider": {"type": "string", "enum": ["playwright", "selenium_remote"], "default": "playwright"},
                "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "default": "chromium"},
                "remoteUrl": {"type": "string"},
                "headless": {"type": "boolean"},
                "manualCompletion": {"type": "boolean", "default": False},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "usernameSelectors": {"type": "array", "items": {"type": "string"}},
                "passwordSelectors": {"type": "array", "items": {"type": "string"}},
                "submitSelectors": {"type": "array", "items": {"type": "string"}},
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": True,
                        "properties": {
                            "action": {"type": "string"},
                            "selector": {"type": "string"},
                            "value": {"type": "string"},
                            "url": {"type": "string"},
                            "key": {"type": "string"},
                            "state": {"type": "string"},
                            "timeoutMillis": {"type": "integer"},
                        },
                    },
                },
                "successUrlPattern": {"type": "string"},
                "successSelector": {"type": "string"},
                "successPattern": {"type": "string"},
                "failurePattern": {"type": "string"},
                "protectedUrl": {"type": "string"},
                "successStatusCodes": {"type": "array", "items": {"type": "integer"}},
                "cookieNames": {"type": "array", "items": {"type": "string"}},
                "captureStorage": {"type": "boolean", "default": True},
                "tokenStorageKeys": {"type": "array", "items": {"type": "string"}},
                "authorizationStorageKey": {"type": "string"},
                "authorizationScheme": {"type": "string", "default": "Bearer"},
                "captureBrowserHeaders": {"type": "boolean", "default": True},
                "label": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["id", "credentialId", "scopes", "loginUrl", "confirm"],
        },
    },
    {
        "name": "credentials.authenticate",
        "description": "Run a stored authentication profile and refresh its cookie credential. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profileId": {"type": "string"},
                "target": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 45},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
            },
            "required": ["profileId", "confirm"],
        },
    },
    {
        "name": "credentials.browser_auth_check_setup",
        "description": "Check local browser-auth dependencies and browser launch readiness without authenticating.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["playwright", "selenium_remote"], "default": "playwright"},
                "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "default": "chromium"},
                "remoteUrl": {"type": "string"},
            },
        },
    },
    {
        "name": "credentials.browser_authenticate",
        "description": "Run a stored browser authentication profile and refresh a scoped session credential. Runs as a background job by default. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profileId": {"type": "string"},
                "target": {"type": "string"},
                "workspaceId": {"type": "string"},
                "provider": {"type": "string", "enum": ["playwright", "selenium_remote"]},
                "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"]},
                "remoteUrl": {"type": "string"},
                "headless": {"type": "boolean"},
                "background": {"type": "boolean", "default": True},
                "authTimeoutSeconds": {"type": "integer", "minimum": 30, "default": 1800},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 45},
                "validateExistingSessionFirst": {"type": "boolean", "default": False},
                "manualValues": {"type": "object", "additionalProperties": True},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
            },
            "required": ["profileId", "confirm"],
        },
    },
    {
        "name": "credentials.validate_session",
        "description": "Validate a stored credential against an authorized protected URL. Requires confirm=true because it sends one authenticated request.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "credentialId": {"type": "string"},
                "target": {"type": "string"},
                "protectedUrl": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 45},
                "successStatusCodes": {"type": "array", "items": {"type": "integer"}},
                "successPattern": {"type": "string"},
                "failurePattern": {"type": "string"},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
            },
            "required": ["credentialId", "target", "confirm"],
        },
    },
    {
        "name": "credentials.get",
        "description": "Read one stored scoped credential with the secret redacted.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "credentials.delete",
        "description": "Delete a stored scoped credential or authentication profile. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "confirm": {"type": "boolean"}},
            "required": ["id", "confirm"],
        },
    },
    {
        "name": "dumps.list",
        "description": "List available offline Burp proxy dumps.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cache.inspect_scope_data",
        "description": (
            "Inspect local dump artifacts by hostname and identify artifacts whose hosts are no longer in "
            "authorized scope. Does not delete files."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cache.clean_out_of_scope",
        "description": (
            "Delete local dump artifacts whose parsed hosts are all outside current authorized scope. "
            "Requires confirm=true; mixed-scope and unknown-host artifacts are kept."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"confirm": {"type": "boolean"}},
            "required": ["confirm"],
        },
    },
    {
        "name": "cache.inspect_generated_artifacts",
        "description": (
            "Inspect duplicate generated output artifacts and replaceable raw evidence records that can be "
            "pruned to keep only the newest copies. Does not delete files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"keep": {"type": "integer", "minimum": 1, "default": 1}},
        },
    },
    {
        "name": "cache.clean_generated_artifacts",
        "description": (
            "Prune duplicate generated output artifacts and replaceable raw evidence records after review. "
            "Requires confirm=true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"confirm": {"type": "boolean"}, "keep": {"type": "integer", "minimum": 1, "default": 1}},
            "required": ["confirm"],
        },
    },
    {
        "name": "sqli.analyze_workspace",
        "description": "Passively score normalized workspace parameters for SQL injection candidates. Does not execute sqlmap or send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 55},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "sqli.analyze_dump",
        "description": (
            "Analyze an offline Burp dump for SQL injection candidates and suggested sqlmap commands. "
            "Does not execute sqlmap."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dumpPath": {"type": "string"},
                "level": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1},
                "risk": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1},
                "maxCandidatesPerRequest": {"type": "integer", "minimum": 1, "default": 5},
                "onlyInteresting": {"type": "boolean", "default": True},
                "includeCommands": {"type": "boolean", "default": True},
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "ingest": {"type": "boolean", "default": False},
            },
            "required": ["dumpPath"],
        },
    },
    {
        "name": "sqli.build_sqlmap_command",
        "description": (
            "Build validated sqlmap command(s) without executing them. Given workspaceId+target, "
            "promotes every interesting candidate surface — all injectable parameters grouped per "
            "route, not just one parameter of one URL — into targeted sqlmap invocations and marks "
            "each promoted sqli candidate as under testing. Without workspace context, returns one "
            "generic command."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "level": {"type": "integer", "minimum": 1, "maximum": 5},
                "risk": {"type": "integer", "minimum": 1, "maximum": 3},
                "options": {"type": "object", "additionalProperties": True},
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 55},
                "maxTargets": {"type": "integer", "minimum": 1, "default": 25},
                "recordPromotion": {"type": "boolean", "default": True},
            },
            "required": ["level", "risk"],
        },
    },
    {
        "name": "xss.analyze_workspace",
        "description": "Passively score normalized workspace parameters for XSS candidates. Does not replay payloads or send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 55},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "xss.analyze_dump",
        "description": (
            "Analyze an offline Burp dump for XSS-relevant request sources, response controls, HTML sinks, "
            "reflections, and manual test code. Does not send traffic."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dumpPath": {"type": "string"},
                "onlyInteresting": {"type": "boolean", "default": True},
                "maxFindingsPerResponse": {"type": "integer", "minimum": 1, "default": 12},
                "includeTestCode": {"type": "boolean", "default": True},
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "ingest": {"type": "boolean", "default": False},
            },
            "required": ["dumpPath"],
        },
    },
    {
        "name": "xss.generate_test_code",
        "description": "Generate an explicit staged XSS test plan. Defaults to an inert reflection marker and does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "parameter": {"type": "string"},
                "context": {"type": "string", "default": "unknown"},
                "url": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["reflection_marker", "context_breakout", "execution"],
                    "default": "reflection_marker",
                },
                "marker": {
                    "type": "string",
                    "description": "Optional 4-80 character ASCII alphanumeric marker. Returned and sent without rewriting.",
                },
            },
            "required": ["parameter"],
        },
    },
    {
        "name": "xss.execute_test",
        "description": "Run approved benign XSS reflection probes against an in-scope HTTP target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "context": {"type": "string", "default": "unknown"},
                "mode": {
                    "type": "string",
                    "enum": ["reflection_marker", "context_breakout", "execution"],
                    "default": "reflection_marker",
                },
                "marker": {"type": "string"},
                "payload": {"type": "string"},
                "maxPayloads": {"type": "integer", "minimum": 1, "default": 1},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "spec_import.capabilities",
        "description": "Return spec_import adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "headers_cookies.capabilities",
        "description": "Return headers_cookies adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "jwt.capabilities",
        "description": "Return jwt adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "csrf.capabilities",
        "description": "Return csrf adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "csrf.analyze_workspace",
        "description": "Passively classify state-changing forms using normalized anti-CSRF token names and workflow-specific login/recovery/registration prerequisites. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 35},
                "ingest": {"type": "boolean", "default": True},
                "workflowContexts": {
                    "type": "array",
                    "description": "Operator-reviewed prerequisites keyed by exact form URL. Login requires a scenario, approved credential reference, and approval ID; recovery/registration requires concrete impact plus evidence IDs.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "attackerAccountScenario": {"type": "string"},
                            "credentialedBaselineApproved": {"type": "boolean"},
                            "baselineCredentialId": {"type": "string"},
                            "approvalId": {"type": "string"},
                            "unauthorizedStateChangeImpact": {"type": "string"},
                            "impactEvidenceIds": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["url"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "csrf.generate_test_plan",
        "description": "Generate a manual CSRF reproduction outline for a candidate without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "inputNames": {"type": "array", "items": {"type": "string"}},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "cors.capabilities",
        "description": "Return cors adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cors.analyze_workspace",
        "description": "Passively classify observed CORS policies using browser response-sharing semantics. Public wildcard and uncorroborated fixed-origin policies are informational. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "cors.generate_test_plan",
        "description": "Generate a bounded CORS Origin probe plan requiring an exact attacker-controlled origin plus credential acceptance for a reportable credentialed-read candidate. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "probeOrigin": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "cors.execute_test",
        "description": "Send one bounded CORS Origin probe and apply browser-semantic read/credential verdicts against an in-scope target. Requires confirm=true.",
    },
    {
        "name": "insecure_deser.capabilities",
        "description": "Return insecure_deser adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "insecure_deser.analyze_workspace",
        "description": "Passively detect recognizable serialized object blob markers in normalized workspace inputs. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "xxe.capabilities",
        "description": "Return xxe adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "xxe.analyze_workspace",
        "description": "Passively identify XML/SOAP-accepting endpoints as XXE candidates. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "xxe.generate_test_plan",
        "description": "Generate a guarded manual XXE validation outline without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "xxe.execute_test",
        "description": "Run an approved benign in-band XML entity expansion probe against an in-scope target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string", "default": "POST"},
                "marker": {"type": "string"},
                "payload": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "graphql.capabilities",
        "description": "Return graphql adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "graphql.analyze_workspace",
        "description": "Passively identify GraphQL endpoints and introspection candidates. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 50},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "graphql.generate_test_plan",
        "description": "Generate a bounded GraphQL introspection probe plan without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "graphql.execute_test",
        "description": "Send one bounded GraphQL introspection POST against an in-scope target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "tls_posture.capabilities",
        "description": "Return tls_posture adapter capabilities and metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "tls_posture.analyze_workspace",
        "description": "Passively normalize TLS posture observations from already-collected SSL data. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 100},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "jwt.analyze",
        "description": "Offline analysis of a supplied JWT (alg=none, weak built-in secrets, kid injection surface, missing expiry, privileged claims). Sends no traffic; never stores or echoes the token or any matched secret.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "The compact JWT to analyze."},
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "ingest": {"type": "boolean", "default": False, "description": "When true with workspaceId+target, stores redacted observations."},
            },
            "required": ["token"],
        },
    },
    {
        "name": "headers_cookies.analyze_workspace",
        "description": "Passively analyze recorded response security headers and cookie flags for hygiene weaknesses. Does not send traffic.",
    },
    {
        "name": "spec_import.import_spec",
        "description": "Passively import an OpenAPI/Swagger/Postman specification, normalizing documented endpoints, parameters, and auth schemes into the workspace. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "rawData": {"type": "string", "description": "The specification document (JSON, or YAML if PyYAML is available)."},
                "format": {"type": "string", "enum": ["openapi", "swagger", "postman"], "description": "Optional; auto-detected when omitted."},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target", "rawData"],
        },
    },
    {
        "name": "ssrf.analyze_workspace",
        "description": "Passively analyze normalized workspace endpoints, parameters, and forms for SSRF candidates. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 35},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "ssrf.generate_test_plan",
        "description": "Generate a manual SSRF test plan for a candidate without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "priority": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
                "callbackBaseUrl": {"type": "string"},
            },
        },
    },
    {
        "name": "ssrf.execute_test",
        "description": "Send one approved SSRF canary URL probe to an in-scope target parameter. Requires confirm=true and callbackBaseUrl or callbackUrl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "callbackBaseUrl": {"type": "string"},
                "callbackUrl": {"type": "string"},
                "payload": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "open_redirect.analyze_workspace",
        "description": "Passively analyze normalized workspace endpoints, parameters, and forms for open redirect candidates. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 35},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "open_redirect.generate_test_plan",
        "description": "Generate a manual open redirect test plan for a candidate without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "priority": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
                "externalUrl": {"type": "string"},
            },
        },
    },
    {
        "name": "open_redirect.execute_test",
        "description": "Run an approved harmless external URL redirect probe against an in-scope target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "externalUrl": {"type": "string"},
                "payload": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "followRedirects": {
                    "type": "boolean",
                    "default": False,
                    "description": "Open redirect probes always capture Location headers without following redirects.",
                },
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "command_injection.analyze_workspace",
        "description": "Passively analyze normalized workspace endpoints and parameters for command injection candidates using fingerprint OS hints. Does not send traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "organization": {"type": "string", "default": "unknown-org"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "maximum": 100, "default": 35},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "command_injection.generate_test_plan",
        "description": "Generate benign OS-aware manual command injection payloads for a candidate without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "osFamily": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
                "marker": {"type": "string"},
            },
        },
    },
    {
        "name": "command_injection.prepare_replay",
        "description": "Build a no-traffic manual replay request for one benign command injection marker payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string", "default": "query"},
                "osFamily": {"type": "string", "default": "unknown"},
                "marker": {"type": "string"},
                "payload": {"type": "string"},
            },
        },
    },
    {
        "name": "command_injection.execute_test",
        "description": "Execute one benign command injection marker test against an in-scope HTTP target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string", "default": "query"},
                "osFamily": {"type": "string", "default": "unknown"},
                "marker": {"type": "string"},
                "payload": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "cve.capabilities",
        "description": "Return CVE intelligence adapter capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cve.sources",
        "description": "Report configured CVE source endpoints, enabled sources, and last per-source status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sources": {
                    "description": "Optional comma-separated source list or array to evaluate as enabled for this view.",
                    "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                },
            },
        },
    },
    {
        "name": "cve.set_source_endpoint",
        "description": "Set an unpersisted runtime endpoint override for a known CVE source. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "enum": ["nvd", "cisa_kev", "poc_github_index", "github_search", "searchsploit"]},
                "url": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["source", "url", "confirm"],
        },
    },
    {
        "name": "cve.reset_source_endpoint",
        "description": "Clear an unpersisted runtime endpoint override for a known CVE source. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "enum": ["nvd", "cisa_kev", "poc_github_index", "github_search", "searchsploit"]},
                "confirm": {"type": "boolean"},
            },
            "required": ["source", "confirm"],
        },
    },
    {
        "name": "cve.session_key.set",
        "description": "Set a runtime-only CVE provider API key for this MCP process. Key values are never echoed or persisted. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["nvd", "github"]},
                "apiKey": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["provider", "apiKey", "confirm"],
        },
    },
    {
        "name": "cve.session_key.clear",
        "description": "Clear a runtime-only CVE provider API key for this MCP process. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["nvd", "github"]},
                "confirm": {"type": "boolean"},
            },
            "required": ["provider", "confirm"],
        },
    },
    {
        "name": "cve.session_key.status",
        "description": "Show which CVE provider session keys are configured without revealing key values.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "cve.correlate",
        "description": "Correlate fingerprinted technology components with selected CVE intelligence sources and ingest cve_candidate observations. Requires confirm=true because it can touch third-party sources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "sources": {
                    "description": "Comma-separated source list or array. Defaults to SYNAPSE_CVE_SOURCES.",
                    "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                },
                "refresh": {"type": "boolean", "default": False},
                "minCvss": {"type": "number", "minimum": 0, "maximum": 10},
                "includeVersionUnknown": {
                    "type": "boolean",
                    "default": False,
                    "description": "Opt into broad NVD keyword correlation for components without a version. Uncorroborated results remain suppressed.",
                },
                "nvdResultsPerComponent": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
                "maxCandidates": {"type": "integer", "minimum": 1, "maximum": 250, "default": 25},
                "providerRateLimitCapacity": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10000,
                    "description": "Optional per-source credential-tier token-bucket capacity override; provider-safe defaults apply when omitted.",
                },
                "providerRateLimitWindowSeconds": {
                    "type": "number",
                    "minimum": 0.01,
                    "maximum": 3600,
                    "description": "Optional token-bucket refill window override in seconds.",
                },
                "providerMaxAttempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 3,
                    "description": "Maximum attempts for a provider query, including the initial request.",
                },
                "providerMaxWaitSeconds": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 300,
                    "default": 30,
                    "description": "Maximum cumulative provider-budget and Retry-After wait for one query before returning a resumable rate_limited source status.",
                },
                "ingest": {"type": "boolean", "default": True},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 20},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
            },
            "required": ["workspaceId", "target", "confirm"],
        },
    },
    {
        "name": "cve.plan_tests",
        "description": "Build a no-traffic CVE verification plan from a cve_candidate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "cveId": {"type": "string"},
                "component": {"type": "string"},
                "version": {"type": "string"},
                "pocReferences": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "knownExploited": {"type": "boolean"},
                "exploitMaturity": {"type": "string"},
                "nucleiTemplate": {"type": "string"},
            },
        },
    },
    {
        "name": "cve.prepare_replay",
        "description": "Build a no-traffic manual replay request for one benign CVE verification marker.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "cveId": {"type": "string"},
                "component": {"type": "string"},
                "version": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string", "default": "query"},
                "payload": {"type": "string"},
            },
        },
    },
    {
        "name": "cve.execute_test",
        "description": "Run one approved benign CVE verification request against an in-scope HTTP target, or return a delegateToNuclei payload when a nuclei template is present. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "cveId": {"type": "string"},
                "component": {"type": "string"},
                "version": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string", "default": "query"},
                "payload": {"type": "string"},
                "nucleiTemplate": {"type": "string"},
                "forceDirectReplay": {"type": "boolean", "default": False},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "ssti.capabilities",
        "description": "Return SSTI adapter capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ssti.passive_analyze",
        "description": "Passively identify SSTI candidate surfaces from workspace endpoints, parameters, and observations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "default": 35},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "ssti.plan_tests",
        "description": "Generate a conservative SSTI test plan without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "ssti.prepare_replay",
        "description": "Build a no-traffic manual replay request for one built-in benign SSTI payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "payload": {"type": "string"},
            },
        },
    },
    {
        "name": "ssti.execute_test",
        "description": "Run approved benign SSTI arithmetic probes against an in-scope HTTP target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "payload": {"type": "string"},
                "maxPayloads": {"type": "integer", "minimum": 1, "default": 3},
                "workspaceId": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1},
                **HTTP_POLICY_PROPERTIES,
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "lfi.capabilities",
        "description": "Return LFI/RFI adapter capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "lfi.passive_analyze",
        "description": "Passively identify LFI/RFI/path traversal/file download candidate surfaces from workspace context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "default": 35},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "lfi.plan_tests",
        "description": "Generate a conservative LFI/RFI test plan without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "lfi.execute_test",
        "description": "Run approved benign LFI/RFI file-handling probes against an in-scope HTTP target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "payload": {"type": "string"},
                "maxPayloads": {"type": "integer", "minimum": 1, "default": 3},
                "workspaceId": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1},
                **HTTP_POLICY_PROPERTIES,
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "ssi.capabilities",
        "description": "Return SSI adapter capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ssi.passive_analyze",
        "description": "Passively identify SSI candidate surfaces from workspace endpoints, parameters, and observations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 25},
                "minScore": {"type": "integer", "minimum": 0, "default": 25},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "ssi.plan_tests",
        "description": "Generate a conservative SSI test plan without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "reasons": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "ssi.prepare_replay",
        "description": "Build a no-traffic manual replay request for one built-in benign SSI payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "payload": {"type": "string"},
            },
        },
    },
    {
        "name": "ssi.execute_test",
        "description": "Run approved benign SSI marker probes against an in-scope HTTP target. Requires confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "candidate": {"type": "object", "additionalProperties": True},
                "candidateId": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "parameter": {"type": "string"},
                "location": {"type": "string"},
                "payload": {"type": "string"},
                "maxPayloads": {"type": "integer", "minimum": 1, "default": 2},
                "workspaceId": {"type": "string"},
                "credentialId": {"type": "string"},
                "requestTimeout": {"type": "integer", "minimum": 1},
                **HTTP_POLICY_PROPERTIES,
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "access_control.capabilities",
        "description": "Return access-control adapter capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "access_control.identify_objects",
        "description": "Identify object identifiers and privileged function surfaces from workspace context without replaying requests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxCandidates": {"type": "integer", "minimum": 1, "default": 100},
                "minScore": {"type": "integer", "minimum": 0, "default": 25},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "access_control.record_context",
        "description": "Record an authorized user/role context for access-control matrix planning without storing secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "contextId": {"type": "string"},
                "label": {"type": "string"},
                "role": {"type": "string"},
                "userType": {"type": "string"},
                "credentialId": {"type": "string"},
                "authState": {"type": "string"},
                "notes": {"type": "string"},
                "observedEndpointPatterns": {"type": "array", "items": {"type": "string"}},
                "ownedObjectTypes": {"type": "array", "items": {"type": "string"}},
                "metadata": {"type": "object", "additionalProperties": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "access_control.build_test_matrix",
        "description": "Build BOLA/BOPLA/BFLA-style planned access-control tests from object candidates and recorded contexts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "contexts": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "refreshObjects": {"type": "boolean", "default": True},
                "minScore": {"type": "integer", "minimum": 0, "default": 25},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "access_control.plan_tests",
        "description": "Generate detailed operator guidance for one access-control matrix entry without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "matrixId": {"type": "string"},
                "matrixEntry": {"type": "object", "additionalProperties": True},
                "endpointPattern": {"type": "string"},
                "method": {"type": "string"},
                "objectType": {"type": "string"},
                "testClass": {"type": "string"},
                "requiredContexts": {"type": "array", "items": {"type": "string"}},
                "riskTier": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
    },
    {
        "name": "access_control.execute_matrix_test",
        "description": "Replay an approved executable access-control matrix entry across its exact recorded context IDs and compare sanitized responses. Requires confirm=true. Authenticated contexts must resolve a valid credentialId and are never downgraded to anonymous; anonymous traffic requires an explicitly anonymous baseline context. Redirects are not followed by default so redirect-to-login responses stay visible as denials; pass followRedirects=true to override.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "matrixId": {"type": "string"},
                "matrixEntry": {"type": "object", "additionalProperties": True},
                "requestUrl": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "contexts": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                "substitutions": {"type": "object", "additionalProperties": True},
                "headers": {"type": "object", "additionalProperties": True},
                "body": {"type": "string"},
                "jsonBody": {"type": "object", "additionalProperties": True},
                "allowStateChanging": {"type": "boolean", "default": False},
                "requestTimeout": {"type": "integer", "minimum": 1},
                "totalBudgetSeconds": {"type": "number", "minimum": 1, "default": 30},
                **HTTP_POLICY_PROPERTIES,
                "followRedirects": {"type": "boolean", "default": False},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["workspaceId", "target", "requestUrl", "confirm"],
        },
    },
    {
        "name": "js.capabilities",
        "description": "Return JavaScript intelligence capability and safety metadata.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "js.discover_assets",
        "description": "Passively discover JavaScript asset URLs from stored sitemap, crawler, and workspace endpoint data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxAssets": {"type": "integer", "minimum": 1, "default": 50},
                "includeEvidenceRaw": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "js.fetch_assets",
        "description": "Fetch bounded in-scope JavaScript assets through the configured HTTP backend and store them under the target workspace. Requires confirm=true unless traffic is disabled.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "assets": {"type": "array", "items": {"oneOf": [{"type": "string"}, {"type": "object", "additionalProperties": True}]}},
                "maxAssets": {"type": "integer", "minimum": 1, "default": 20},
                "maxBytesPerAsset": {"type": "integer", "minimum": 1, "default": 750000},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                "totalBudgetSeconds": {"type": "number", "minimum": 1, "default": 30},
                "refresh": {"type": "boolean", "default": False},
                "credentialId": {"type": "string"},
                "userAgent": {"type": "string", "default": "SynapseJSIntel/0.1"},
                **HTTP_POLICY_PROPERTIES,
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "js.analyze_static",
        "description": "Statically analyze stored JavaScript assets without executing code or sending traffic. Runs as a background job by default.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "manifestPath": {"type": "string"},
                "assetPaths": {"type": "array", "items": {"type": "string"}},
                "maxBytesPerAsset": {"type": "integer", "minimum": 1, "default": 750000},
                "timeoutSeconds": {"type": "integer", "minimum": 30, "default": 1800},
                "background": {"type": "boolean", "default": True},
                "maxConcurrentJobs": {"type": "integer", "minimum": 1, "default": 3},
                "normalizeAfter": {"type": "boolean", "default": False},
                "normalizeTimeoutSeconds": {"type": "integer", "minimum": 30, "default": 1800},
                "baseUrl": {"type": "string"},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "js.normalize_endpoints",
        "description": "Normalize JavaScript-derived endpoints and parameters into workspace entities marked as inferred/derived. Runs as a background job by default.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "analysisPath": {"type": "string"},
                "baseUrl": {"type": "string"},
                "ingest": {"type": "boolean", "default": True},
                "timeoutSeconds": {"type": "integer", "minimum": 30, "default": 1800},
                "background": {"type": "boolean", "default": True},
                "maxConcurrentJobs": {"type": "integer", "minimum": 1, "default": 3},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "js.build_app_model",
        "description": "Build a compact JavaScript-derived application model summary for operators and agents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "analysisPath": {"type": "string"},
                "maxEndpoints": {"type": "integer", "minimum": 1, "default": 25},
                "maxTokens": {"type": "integer", "minimum": 500, "default": 2500},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "js.render_app_map",
        "description": "Render a sitemap-style application map that combines observed workspace requests with JS-inferred endpoints, source assets, parameters, confidence, and JS signals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "analysisPath": {"type": "string"},
                "format": {"type": "string", "enum": ["html", "markdown", "json"], "default": "html"},
                "outputPath": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "sitemap.from_dump",
        "description": "Build a Burp-like site map from an offline Burp dump without sending traffic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dumpPath": {"type": "string"},
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
                "workspaceId": {"type": "string"},
                "onlyInScope": {"type": "boolean", "default": True},
                "includeLinks": {"type": "boolean", "default": True},
                "defaultScheme": {"type": "string", "default": "https"},
            },
            "required": ["dumpPath"],
        },
    },
    {
        "name": "crawler.crawl",
        "description": "Actively crawl one authorized in-scope HTTP(S) target and build a Burp-like site map. Runs as a background job by default. Requires confirm=true.",
    },
    {
        "name": "crawler.extended",
        "description": "After a prior crawler.crawl run, submit discovered POST forms with scoped credentials to extend authenticated application mapping. Runs as a background job by default. Requires credentialId and confirm=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "maxPages": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
                "maxDepth": {"type": "integer", "minimum": 0, "maximum": 10, "default": 6},
                "requestTimeout": {"type": "integer", "minimum": 1, "maximum": 60, "default": 15},
                "delayMillis": {"type": "integer", "minimum": 0, "maximum": 10000, "default": 0},
                "userAgent": {"type": "string", "default": "SynapseCrawler/0.1"},
                "credentialId": {"type": "string"},
                "workspaceId": {"type": "string"},
                "includeStatic": {"type": "boolean", "default": False},
                "includeInScopeHosts": {"type": "boolean", "default": True},
                "analyzeScripts": {"type": "boolean", "default": True},
                "followGetForms": {"type": "boolean", "default": True},
                "maxPostForms": {"type": "integer", "minimum": 0, "maximum": 500, "default": 50},
                "includeSensitivePostForms": {"type": "boolean", "default": False},
                **CRAWLER_HTTP_POLICY_PROPERTIES,
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "background": {"type": "boolean", "default": True},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["target", "credentialId", "confirm"],
        },
    },
    {
        "name": "ffuf.profiles",
        "description": "List constrained ffuf profiles supported by Synapse MCP.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ffuf.build_command",
        "description": "Build a constrained ffuf command without running it. Requires target to be in scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "wordlist": {"type": "string"},
                "threads": {"type": "integer", "minimum": 1},
                "requestTimeout": {"type": "integer", "minimum": 1},
                "extensions": {"type": "array", "items": {"type": "string"}},
                "matchCodes": {"type": "array", "items": {"type": "integer"}},
                "filterSizes": {"type": "array", "items": {"type": "integer"}},
                "credentialId": {"type": "string"},
                "workspaceId": {"type": "string"},
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["target", "wordlist"],
        },
    },
    {
        "name": "ffuf.run_profile",
        "description": "Run a constrained ffuf profile. Runs as a background job by default. Requires confirm=true and target in scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "wordlist": {"type": "string"},
                "threads": {"type": "integer", "minimum": 1},
                "requestTimeout": {"type": "integer", "minimum": 1},
                "extensions": {"type": "array", "items": {"type": "string"}},
                "matchCodes": {"type": "array", "items": {"type": "integer"}},
                "filterSizes": {"type": "array", "items": {"type": "integer"}},
                "credentialId": {"type": "string"},
                "workspaceId": {"type": "string"},
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "background": {"type": "boolean", "default": True},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["target", "wordlist", "confirm"],
        },
    },
    {
        "name": "nuclei.profiles",
        "description": "List adaptive nuclei profiles supported by Synapse MCP.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nuclei.build_command",
        "description": "Build an adaptive nuclei command from profile policy and workspace context without running it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "workspaceId": {"type": "string"},
                "targetUrls": {"type": "array", "items": {"type": "string"}},
                "includeWorkspaceUrls": {"type": "boolean", "default": True},
                "maxContextUrls": {"type": "integer", "minimum": 1},
                "severity": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "templates": {"type": "array", "items": {"type": "string"}},
                "workflows": {"type": "array", "items": {"type": "string"}},
                "vars": {"type": "object", "additionalProperties": True},
                "rateLimit": {"type": "integer", "minimum": 1},
                "concurrency": {"type": "integer", "minimum": 1},
                "bulkSize": {"type": "integer", "minimum": 1},
                "retries": {"type": "integer", "minimum": 0},
                "requestTimeout": {"type": "integer", "minimum": 1},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "credentialId": {"type": "string"},
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei.run_profile",
        "description": "Run an adaptive nuclei profile. Runs as a background job by default. Requires confirm=true and target in scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "workspaceId": {"type": "string"},
                "targetUrls": {"type": "array", "items": {"type": "string"}},
                "includeWorkspaceUrls": {"type": "boolean", "default": True},
                "maxContextUrls": {"type": "integer", "minimum": 1},
                "severity": {"type": "array", "items": {"type": "string"}},
                "tags": {"type": "array", "items": {"type": "string"}},
                "templates": {"type": "array", "items": {"type": "string"}},
                "workflows": {"type": "array", "items": {"type": "string"}},
                "vars": {"type": "object", "additionalProperties": True},
                "rateLimit": {"type": "integer", "minimum": 1},
                "concurrency": {"type": "integer", "minimum": 1},
                "bulkSize": {"type": "integer", "minimum": 1},
                "retries": {"type": "integer", "minimum": 0},
                "requestTimeout": {"type": "integer", "minimum": 1},
                "credentialId": {"type": "string"},
                "output": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "background": {"type": "boolean", "default": True},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["target", "confirm"],
        },
    },
    {
        "name": "nmap.profiles",
        "description": "List constrained nmap profiles supported by Synapse MCP.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nmap.build_command",
        "description": "Build a constrained nmap command without running it. Requires target to be in scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "workspaceId": {"type": "string"},
                "outputBase": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nmap.run_profile",
        "description": "Run a constrained nmap profile. Runs as a background job by default. Requires confirm=true and target in scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "enum": ["low_noise", "medium", "pentest_aggressive"], "default": "medium"},
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "workspaceId": {"type": "string"},
                "outputBase": {"type": "string"},
                "allowExternalOutput": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 30},
                "background": {"type": "boolean", "default": True},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["target", "confirm"],
        },
    },
    {
        "name": "shodan.session_key.set",
        "description": "Set the Shodan API key for this Synapse MCP process only. The key is kept in memory and is not returned or written to evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apiKey": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["apiKey", "confirm"],
        },
    },
    {
        "name": "shodan.session_key.clear",
        "description": "Clear the in-memory Shodan API key for this Synapse MCP process.",
        "inputSchema": {
            "type": "object",
            "properties": {"confirm": {"type": "boolean"}},
            "required": ["confirm"],
        },
    },
    {
        "name": "shodan.session_key.status",
        "description": "Report whether a Shodan API key is configured without revealing the key.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shodan.host",
        "description": "Look up an IP address in Shodan and summarize exposed services, open ports, and possible CVEs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "history": {"type": "boolean", "default": False},
                "minify": {"type": "boolean", "default": False},
                "raw": {"type": "boolean", "default": False},
                "workspaceId": {"type": "string"},
                "ingest": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["ip", "confirm"],
        },
    },
    {
        "name": "shodan.internetdb",
        "description": "Look up an IP address in Shodan InternetDB for passive hostnames, ports, tags, CPEs, and CVEs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "raw": {"type": "boolean", "default": False},
                "workspaceId": {"type": "string"},
                "ingest": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["ip", "confirm"],
        },
    },
    {
        "name": "shodan.domain",
        "description": "Enumerate Shodan DNS records and subdomains for a domain, preserving DNS and asset relationships without treating ordinary resolution as origin-IP leakage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "history": {"type": "boolean", "default": False},
                "type": {"type": "string"},
                "page": {"type": "integer", "minimum": 1, "default": 1},
                "raw": {"type": "boolean", "default": False},
                "workspaceId": {"type": "string"},
                "ingest": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["domain", "confirm"],
        },
    },
    {
        "name": "shodan.resolve",
        "description": "Resolve one or more hostnames through Shodan DNS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostnames": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["hostnames", "confirm"],
        },
    },
    {
        "name": "shodan.reverse",
        "description": "Reverse-resolve one or more IP addresses through Shodan DNS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ips": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["ips", "confirm"],
        },
    },
    {
        "name": "shodan.search_count",
        "description": "Count Shodan results for an auditable query without returning result banners.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "facets": {"type": "string", "default": "port,org,domain,asn"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["query", "confirm"],
        },
    },
    {
        "name": "shodan.search",
        "description": "Search Shodan for exposed services using an auditable query. Results are normalized per discovered asset with relations back to the query seed. May consume query credits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "facets": {"type": "string"},
                "page": {"type": "integer", "minimum": 1, "default": 1},
                "minify": {"type": "boolean", "default": True},
                "fields": {"type": "string"},
                "raw": {"type": "boolean", "default": False},
                "target": {"type": "string"},
                "workspaceId": {"type": "string"},
                "ingest": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["query", "confirm"],
        },
    },
    {
        "name": "shodan.search_facets",
        "description": "List Shodan search facet names for building OSINT queries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "shodan.search_filters",
        "description": "List Shodan search filter names for building OSINT queries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
        },
    },
    {
        "name": "shodan.target_summary",
        "description": "Build a target-level Shodan summary for a hostname or IP: DNS relations, resolved addresses, host/InternetDB service metadata, TLS context, and possible CVEs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "domain": {"type": "string", "description": "Optional registrable/root domain to enumerate when target is a hostname."},
                "includeHost": {"type": "boolean", "default": True},
                "includeInternetDb": {"type": "boolean", "default": True},
                "includeDomain": {"type": "boolean", "default": True},
                "maxHostIps": {"type": "integer", "minimum": 0, "maximum": 25, "default": 3},
                "maxInternetDbIps": {"type": "integer", "minimum": 0, "maximum": 100, "default": 10},
                "history": {"type": "boolean", "default": False},
                "minify": {"type": "boolean", "default": False},
                "type": {"type": "string"},
                "page": {"type": "integer", "minimum": 1, "default": 1},
                "raw": {"type": "boolean", "default": False},
                "workspaceId": {"type": "string"},
                "ingest": {"type": "boolean"},
                "timeoutSeconds": {"type": "integer", "minimum": 1},
                "confirm": {"type": "boolean"},
            },
            "required": ["target", "confirm"],
        },
    },
    {
        "name": "shodan.company_queries",
        "description": "Build passive Shodan queries for a company, domain, organization, or hostname. Does not call the API.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "company": {"type": "string"},
                "domain": {"type": "string"},
                "hostname": {"type": "string"},
                "org": {"type": "string"},
            },
        },
    },
    {
        "name": "evidence.log_event",
        "description": "Append an operator-reviewed event to the local evidence log.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "summary": {"type": "string"},
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "organization": {"type": "string"},
                "data": {"type": "object", "additionalProperties": True},
            },
            "required": ["type", "summary"],
        },
    },
    {
        "name": "evidence.tail",
        "description": "Read recent local evidence events.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "default": 20}},
        },
    },
    {
        "name": "evidence.init_project",
        "description": "Create organization and hostname evidence folders for a new project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "organization": {"type": "string"},
                "hosts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["organization"],
        },
    },
    {
        "name": "evidence.host_context",
        "description": "Read evidence context previously logged for a hostname or URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "organization": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "default": 50},
            },
            "required": ["target"],
        },
    },
    {
        "name": "fingerprint.from_dump",
        "description": "Fingerprint hosts from an offline Burp dump and save fingerprint.json under organization/host evidence folders.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dumpPath": {"type": "string"},
                "organization": {"type": "string", "default": "unknown-org"},
                "target": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "default": 5000},
            },
            "required": ["dumpPath"],
        },
    },
    {
        "name": "fingerprint.analyze_workspace",
        "description": "Passively fingerprint technology components from normalized workspace services, endpoints, headers, cookies, and observations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "organization": {"type": "string"},
                "ingest": {"type": "boolean", "default": True},
            },
            "required": ["workspaceId", "target"],
        },
    },
    {
        "name": "fingerprint.probe_versions",
        "description": "Run approved bounded benign GET probes to enrich known workspace technology components with exact versions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceId": {"type": "string"},
                "target": {"type": "string"},
                "maxRequests": {"type": "integer", "minimum": 0, "default": 8},
                "requestTimeout": {"type": "integer", "minimum": 1, "default": 10},
                **HTTP_POLICY_PROPERTIES,
                "confirm": {"type": "boolean"},
                "approvalId": {"type": "string"},
                "approvalReason": {"type": "string"},
                "riskTier": {"type": "string"},
            },
            "required": ["workspaceId", "target", "confirm"],
        },
    },
    {
        "name": "fingerprint.read_host",
        "description": "Read the saved fingerprint.json for a hostname or URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "organization": {"type": "string", "default": "unknown-org"},
            },
            "required": ["target"],
        },
    },
]

# Keep every documentation entry point aligned with the shared redaction-policy
# boundary. `operator`/`operator_raw` are public presentation names;
# `internal`/`raw` remain compatibility policy names and `safe` is deprecated.
for _tool_schema in _LEGACY_TOOL_SCHEMAS:
    _input_schema = _tool_schema.get("inputSchema")
    _properties = _input_schema.get("properties") if isinstance(_input_schema, dict) else None
    _redaction_schema = _properties.get("redactionMode") if isinstance(_properties, dict) else None
    if isinstance(_redaction_schema, dict):
        _redaction_schema["enum"] = list(REDACTION_MODE_VALUES)
        _redaction_schema["description"] = (
            "Presentation aliases operator/operator_raw map to compatibility policies internal/raw; "
            "high_level is the concise internal view and safe is deprecated."
        )

from . import projection
from ..app.actions.adapter_metadata import derive_adapter_operational_metadata


adapter_registry.set_action_metadata_provider(derive_adapter_operational_metadata)


TOOL_SCHEMAS = projection.projected_tools_list()

RESOURCES = [
    {"uri": "synapse://dumps", "name": "Offline Burp Proxy Dumps", "mimeType": "application/json"},
    {"uri": "synapse://scope", "name": "Authorized Scope", "mimeType": "application/json"},
    {"uri": "synapse://credentials", "name": "Scoped Credentials", "mimeType": "application/json"},
    {"uri": "synapse://evidence/recent", "name": "Recent Evidence Events", "mimeType": "application/json"},
    {"uri": "synapse://jobs/active", "name": "Active Background Jobs", "mimeType": "application/json"},
    {"uri": "synapse://workspaces", "name": "Synapse Workspaces", "mimeType": "application/json"},
    {"uri": "synapse://prompt/main", "name": "Synapse Main Prompt", "mimeType": "text/markdown"},
]

PROMPTS = [{"name": MAIN_PROMPT_NAME, "description": "Shared Synapse operating prompt.", "arguments": []}]

PACKAGED_MAIN_PROMPT = """# Synapse Agent Instructions

Synapse is a local-first MCP control plane for authorized, human-in-the-loop
security assessment workflows. Use it to manage scope, workspace state,
evidence, credential references, passive analysis, guarded adapters, background
jobs, and internal reports.

Work only on authorized targets. Treat scope and execution approval as separate
gates: active traffic, credential mutation, browser authentication,
command-backed scanners, third-party OSINT calls, and destructive local cleanup
require explicit operator approval for the exact action.

Prefer passive and local analysis before active testing. Keep candidates,
findings, gaps, recommendations, and evidence distinct. Do not promote scanner
output or passive observations to confirmed findings without operator review.
Do not put secrets in prompts, commands, evidence, notes, or final responses;
use credential IDs and redacted credential metadata.

Repository launches normally expose the full AGENTS.md policy. Set
SYNAPSE_PROMPT_PATH to an explicit prompt file when running the packaged
console script from outside the repository.
"""


def json_line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _cwd_repo_prompt_path() -> Path | None:
    cwd = Path.cwd()
    for base in (cwd, *cwd.parents):
        if (base / "MCPS" / "Synapse-MCP").is_dir() and (base / "AGENTS.md").is_file():
            return base / "AGENTS.md"
    return None


def read_main_prompt() -> str:
    try:
        return PROMPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        if os.environ.get("SYNAPSE_PROMPT_PATH") or os.environ.get("SYNAPSE_ROOT"):
            raise McpError(-32000, f"Main prompt file not found: {PROMPT_PATH}") from exc

    repo_prompt = _cwd_repo_prompt_path()
    if repo_prompt and repo_prompt != PROMPT_PATH:
        try:
            return repo_prompt.read_text(encoding="utf-8")
        except FileNotFoundError:
            pass
    return PACKAGED_MAIN_PROMPT


def _tool_schema(name: str) -> dict[str, Any] | None:
    for schema in TOOL_SCHEMAS:
        if schema.get("name") == name:
            return schema
    return None


def _schema_type_matches(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _validate_schema_value(name: str, field: str, value: Any, schema: dict[str, Any]) -> None:
    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        for alternative in alternatives:
            if not isinstance(alternative, dict):
                continue
            try:
                _validate_schema_value(name, field, value, alternative)
            except McpError:
                continue
            break
        else:
            raise McpError(-32602, f"Invalid arguments for {name}: field {field} does not match any allowed shape")
        return

    expected = schema.get("type")
    if isinstance(expected, str) and not _schema_type_matches(value, expected):
        raise McpError(-32602, f"Invalid arguments for {name}: field {field} must be {expected}")
    allowed = schema.get("enum")
    if isinstance(allowed, list) and value not in allowed:
        rendered = ", ".join(str(item) for item in allowed)
        raise McpError(-32602, f"Invalid arguments for {name}: field {field} must be one of: {rendered}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise McpError(-32602, f"Invalid arguments for {name}: field {field} must be >= {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            raise McpError(-32602, f"Invalid arguments for {name}: field {field} must be <= {maximum}")
    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema_value(name, f"{field}[{index}]", item, item_schema)
    if isinstance(value, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for nested_name, nested_value in value.items():
                nested_schema = properties.get(nested_name)
                if isinstance(nested_schema, dict):
                    _validate_schema_value(name, f"{field}.{nested_name}", nested_value, nested_schema)
        required = schema.get("required")
        if isinstance(required, list):
            for nested_name in required:
                if isinstance(nested_name, str) and nested_name not in value:
                    raise McpError(-32602, f"Invalid arguments for {name}: field {field} is missing {nested_name}")


def validate_tool_arguments(name: str, args: dict[str, Any]) -> None:
    input_schema = projection.resolved_input_schema(name)
    required = input_schema.get("required", [])
    if isinstance(required, list):
        for field in required:
            if field == "confirm":
                continue
            if isinstance(field, str) and field not in args:
                raise McpError(-32602, f"Invalid arguments for {name}: missing required field {field}")
    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return
    for field, value in args.items():
        if field.startswith("_"):
            raise McpError(-32602, f"Invalid arguments for {name}: field {field} is reserved for internal workers")
        prop = properties.get(field)
        if not isinstance(prop, dict):
            continue
        _validate_schema_value(name, field, value, prop)


def call_tool(name: str, args: dict[str, Any]) -> str:
    result = _call_tool_impl(name, args)
    _record_passive_analysis_action(name, args, result)
    return result


def _call_tool_impl(name: str, args: dict[str, Any]) -> str:
    projected = projection.project_call(name, args)
    if projected is not None:
        return projected
    return _retained_legacy_call_impl(name, args)


def _retained_legacy_call_impl(name: str, args: dict[str, Any]) -> str:
    if name == "jobs.list":
        return json.dumps(
            background_jobs.list_jobs(
                int(args.get("limit", 20)),
                bool(args.get("activeOnly", False)),
                str(args.get("workspaceId", "")),
                bool(args.get("includeResult", False)),
            ),
            indent=2,
        )
    if name == "jobs.status":
        return json.dumps(background_jobs.status(args["jobId"], bool(args.get("includeResult", False))), indent=2)
    if name == "jobs.cancel":
        return json.dumps(background_jobs.cancel(args["jobId"]), indent=2)
    if name == "adapters.list":
        return json.dumps({"adapters": adapter_registry.list()}, indent=2)
    if name == "adapters.capabilities":
        return json.dumps(adapter_registry.capabilities(args["adapter"]), indent=2)
    if name == "documentation.list_templates":
        return json.dumps(documentation.list_templates(args), indent=2)
    if name == "documentation.list_layers":
        return json.dumps(documentation.list_layers(args), indent=2)
    if name == "perimeter.analyze_workspace":
        return json.dumps(perimeter.analyze_workspace(args), indent=2)
    if name == "perimeter.build_summary":
        return json.dumps(perimeter.build_summary(args), indent=2)
    if name == "perimeter.render_report":
        return json.dumps(perimeter.render_report(args), indent=2)
    if name == "documentation.build_report_context":
        return json.dumps(documentation.build_report_context(args), indent=2)
    if name == "documentation.build_layer_report_context":
        return json.dumps(documentation.build_layer_report_context(args), indent=2)
    if name == "documentation.build_workspace_report_context":
        return json.dumps(documentation.build_workspace_report_context(args), indent=2)
    if name == "documentation.plan_scope_groups":
        return json.dumps(documentation.plan_scope_groups(args), indent=2)
    if name == "documentation.prepare_validation_batch":
        return json.dumps(documentation.prepare_validation_batch(args), indent=2)
    if name == "documentation.render_workspace_report_batches":
        return json.dumps(documentation.render_workspace_report_batches(args), indent=2)
    if name == "documentation.build_finding_context":
        return json.dumps(documentation.build_finding_context(args), indent=2)
    if name == "documentation.build_finding_draft":
        return json.dumps(documentation.build_finding_draft(args), indent=2)
    if name == "documentation.build_evidence_pack":
        return json.dumps(documentation.build_evidence_pack(args), indent=2)
    if name == "documentation.summarize_coverage":
        return json.dumps(documentation.summarize_coverage(args), indent=2)
    if name == "documentation.render_markdown":
        return json.dumps(documentation.render_markdown(args), indent=2)
    if name == "documentation.render_layer_report":
        return json.dumps(documentation.render_layer_report(args), indent=2)
    if name == "documentation.render_workspace_report":
        return json.dumps(documentation.render_workspace_report(args), indent=2)
    if name == "documentation.render_assessment_summary":
        return json.dumps(documentation.render_assessment_summary(args), indent=2)
    if name == "documentation.export_json":
        return json.dumps(documentation.export_json(args), indent=2)
    if name == "scope.set":
        result = scope.save_scope(
            args["hosts"],
            args.get("notes", ""),
            args.get("organization", ""),
            args.get("patterns"),
            args.get("cidrs"),
            cursor=args.get("cursor"),
            limit=int(args.get("inventoryLimit", 50)),
            include_inventory=bool(args.get("includeInventory", False)),
        )
        if args.get("workspaceId"):
            result["workspace"] = workspace.create_workspace(
                args["workspaceId"],
                organization=args.get("organization", ""),
                notes=args.get("notes", ""),
                hosts=args["hosts"],
                patterns=args.get("patterns"),
                cidrs=args.get("cidrs"),
            )
        return json.dumps(result, indent=2)
    if name == "project.start":
        workspace_id = args.get("workspaceId") or args["organization"]
        result: dict[str, Any] = {
            "scope": scope.save_scope(
                args["hosts"],
                args.get("notes", ""),
                args["organization"],
                args.get("patterns"),
                args.get("cidrs"),
                cursor=args.get("cursor"),
                limit=int(args.get("inventoryLimit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            "workspace": workspace.create_workspace(
                workspace_id,
                organization=args["organization"],
                notes=args.get("notes", ""),
                hosts=args["hosts"],
                patterns=args.get("patterns"),
                cidrs=args.get("cidrs"),
            ),
            "authenticationGuidance": credentials.auth_process_guidance(),
        }
        evidence_project = evidence.ensure_project(args["organization"], args["hosts"])
        evidence_hosts = evidence_project.get("hosts", [])
        result["evidenceProject"] = {
            "initialized": evidence_project.get("initialized", False),
            "organization": evidence_project.get("organization", args["organization"]),
            "path": evidence_project.get("path", ""),
            "hostCount": len(evidence_hosts) if isinstance(evidence_hosts, list) else 0,
        }
        if args.get("dumpPath") and args.get("fingerprint", True):
            result["fingerprint"] = fingerprint.from_dump(
                args["dumpPath"],
                args["organization"],
                "",
                int(args.get("limit", 5000)),
            )
        evidence.log_event(
            "project.start",
            f"Started project for {args['organization']} with {len(args['hosts'])} hosts.",
            {
                "organization": args["organization"],
                "workspaceId": workspace_id,
                "hosts": args["hosts"],
                "patterns": args.get("patterns", []),
                "cidrs": args.get("cidrs", []),
                "notes": args.get("notes", ""),
                "dumpPath": args.get("dumpPath", ""),
                "fingerprint": bool(args.get("dumpPath") and args.get("fingerprint", True)),
            },
        )
        return json.dumps(result, indent=2)
    if name == "scope.check_target":
        return json.dumps(
            scope.check_target(
                args["target"],
                cursor=args.get("cursor"),
                limit=int(args.get("limit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            indent=2,
        )
    if name == "workspace.create":
        return json.dumps(
            workspace.create_workspace(
                args["workspaceId"],
                args.get("organization", ""),
                args.get("notes", ""),
                args.get("hosts", []),
                args.get("patterns"),
                args.get("cidrs"),
            ),
            indent=2,
        )
    if name == "workspace.add_target":
        return json.dumps(
            workspace.add_target(args["workspaceId"], args["target"], args.get("kind", "host"), args.get("notes", "")),
            indent=2,
        )
    if name == "workspace.ingest_data":
        return json.dumps(
            workspace.ingest_data(
                args.get("workspaceId"),
                args["target"],
                args["source"],
                args.get("dataType", "tool_output"),
                args.get("format", "text"),
                args["rawData"],
                args.get("metadata", {}),
            ),
            indent=2,
        )
    if name == "workspace.prepare_target_context":
        return json.dumps(
            workspace.prepare_target_context(
                args["workspaceId"],
                args["target"],
                args.get("purpose", "next_step_planning"),
                int(args.get("maxTokens", 1500)),
            ),
            indent=2,
        )
    if name == "workspace.summary":
        return json.dumps(
            workspace.workspace_summary(
                args["workspaceId"],
                cursor=args.get("cursor"),
                limit=int(args.get("limit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            indent=2,
        )
    if name == "workspace.delete":
        return json.dumps(workspace.delete_workspace(args["workspaceId"], bool(args.get("confirm"))), indent=2)
    if name == "workspace.create_finding":
        return json.dumps(
            workspace.create_finding(
                args["workspaceId"],
                args["target"],
                args["title"],
                args.get("severity", "info"),
                args.get("confidence", "low"),
                args.get("description", ""),
                args.get("evidenceIds", []),
                args.get("status", "confirmed"),
                args.get("affectedAssets"),
                args.get("reproductionSteps"),
                args.get("impact", ""),
                args.get("remediation", ""),
                bool(args.get("operatorReviewed", True)),
            ),
            indent=2,
        )
    if name == "workspace.update_finding":
        return json.dumps(
            workspace.update_finding(args["workspaceId"], args["target"], args["findingId"], args.get("updates", {})),
            indent=2,
        )
    if name == "workspace.promote_observation_to_finding":
        selector = {
            key: args[key]
            for key in ("observationId", "observationKey", "type", "value")
            if args.get(key)
        }
        return json.dumps(
            workspace.promote_observation_to_finding(
                args["workspaceId"],
                args["target"],
                selector,
                args.get("title", ""),
                args.get("severity", "info"),
                args.get("confidence", "low"),
                args.get("status", "candidate"),
            ),
            indent=2,
        )
    if name == "workspace.link_evidence_to_finding":
        return json.dumps(
            workspace.link_evidence_to_finding(args["workspaceId"], args["target"], args["findingId"], args.get("evidenceIds", [])),
            indent=2,
        )
    if name == "workspace.mark_finding_reviewed":
        return json.dumps(
            workspace.mark_finding_reviewed(
                args["workspaceId"],
                args["target"],
                args["findingId"],
                args.get("status", "confirmed"),
                args.get("reviewer", "operator"),
                args.get("notes", ""),
            ),
            indent=2,
        )
    if name == "approve_pretext_candidate":
        return json.dumps(
            pretext_generator.approve_pretext_candidate(
                args["workspaceId"],
                args["target"],
                args["entityKey"],
                bool(args.get("confirm", False)),
            ),
            indent=2,
        )
    if name == "mark_detection_outcome":
        return json.dumps(
            gap_analysis.mark_detection_outcome(
                args["workspaceId"],
                args["target"],
                args["actionKey"],
                args.get("detected"),
                args.get("notes", ""),
            ),
            indent=2,
        )
    if name == "workspace.set_entity_reportable":
        return json.dumps(
            workspace.set_entity_reportable(
                args["workspaceId"],
                args["target"],
                args["entityType"],
                args.get("selector", {}),
                bool(args.get("isReportable", True)),
                args.get("reason", ""),
                args.get("reviewer", "operator"),
            ),
            indent=2,
        )
    if name == "workspace.record_candidate_validation":
        return json.dumps(
            workspace.record_candidate_validation(
                args["workspaceId"],
                args["target"],
                args.get("selector", {}),
                args["outcome"],
                args.get("vulnClass", ""),
                args.get("evidenceIds", []),
                args.get("notes", ""),
                args.get("reviewer", "operator"),
            ),
            indent=2,
        )
    if name == "workspace.curate_candidate":
        return json.dumps(
            workspace.curate_candidate(
                args["workspaceId"],
                args["target"],
                args.get("surfaceSelector", {}),
                args.get("add", []),
                args.get("remove", []),
                args.get("reason", ""),
                args.get("reviewer", "agent"),
            ),
            indent=2,
        )
    if name == "workspace.export_finding_context":
        return json.dumps(workspace.export_finding_context(args["workspaceId"], args["target"], args["findingId"]), indent=2)
    if name == "credentials.set":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing credentials requires confirm=true.")
        return json.dumps(credentials.save_credential(args), indent=2)
    if name == "credentials.list":
        return json.dumps(credentials.list_credentials(), indent=2)
    if name == "credentials.set_auth_profile":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing authentication profiles requires confirm=true.")
        return json.dumps(credentials.save_auth_profile(args), indent=2)
    if name == "credentials.set_browser_auth_profile":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing browser authentication profiles requires confirm=true.")
        return json.dumps(credentials.save_browser_auth_profile(args), indent=2)
    if name == "credentials.authenticate":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Authentication requires confirm=true.")
        return json.dumps(credentials.authenticate(args), indent=2)
    if name == "credentials.browser_auth_check_setup":
        return json.dumps(credentials.browser_auth_check_setup(args), indent=2)
    if name == "credentials.browser_authenticate":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Browser authentication requires confirm=true.")
        return json.dumps(credentials.browser_authenticate(args), indent=2)
    if name == "credentials.validate_session":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Session validation requires confirm=true.")
        return json.dumps(credentials.validate_session(args), indent=2)
    if name == "credentials.get":
        return json.dumps(credentials.get_credential(args["id"]), indent=2)
    if name == "credentials.delete":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Deleting credentials requires confirm=true.")
        return json.dumps(credentials.delete_credential(args["id"]), indent=2)
    if name == "dumps.list":
        return json.dumps(dumps.list_dumps(), indent=2)
    if name == "cache.inspect_scope_data":
        return json.dumps(cache.inspect_scope_data(), indent=2)
    if name == "cache.clean_out_of_scope":
        return json.dumps(cache.clean_out_of_scope(bool(args.get("confirm"))), indent=2)
    if name == "cache.inspect_generated_artifacts":
        return json.dumps(cache.inspect_generated_artifacts(int(args.get("keep", 1))), indent=2)
    if name == "cache.clean_generated_artifacts":
        return json.dumps(cache.clean_generated_artifacts(bool(args.get("confirm")), int(args.get("keep", 1))), indent=2)
    if name == "sqli.analyze_workspace":
        return sqlmap_adapter.analyze_workspace(args)
    if name == "sqli.analyze_dump":
        return sqlmap_adapter.analyze_dump(args)
    if name == "sqli.build_sqlmap_command":
        return sqlmap_adapter.build_command(args)
    if name == "xss.analyze_workspace":
        return xss_adapter.analyze_workspace(args)
    if name == "xss.analyze_dump":
        return xss_adapter.analyze_dump(args)
    if name == "xss.generate_test_code":
        return xss_adapter.generate_test_code(args)
    if name == "xss.execute_test":
        return xss_adapter.execute_test(args)
    if name == "spec_import.capabilities":
        return spec_import.capabilities(args)
    if name == "spec_import.import_spec":
        return spec_import.import_spec(args)
    if name == "headers_cookies.capabilities":
        return headers_cookies.capabilities(args)
    if name == "headers_cookies.analyze_workspace":
        return headers_cookies.analyze_workspace(args)
    if name == "jwt.capabilities":
        return jwt_analysis.capabilities(args)
    if name == "jwt.analyze":
        return jwt_analysis.analyze(args)
    if name == "csrf.capabilities":
        return csrf.capabilities(args)
    if name == "csrf.analyze_workspace":
        return csrf.analyze_workspace(args)
    if name == "csrf.generate_test_plan":
        return csrf.generate_test_plan(args)
    if name == "cors.capabilities":
        return cors.capabilities(args)
    if name == "cors.analyze_workspace":
        return cors.analyze_workspace(args)
    if name == "cors.generate_test_plan":
        return cors.generate_test_plan(args)
    if name == "cors.execute_test":
        return cors.execute_test(args)
    if name == "insecure_deser.capabilities":
        return insecure_deser.capabilities(args)
    if name == "insecure_deser.analyze_workspace":
        return insecure_deser.analyze_workspace(args)
    if name == "xxe.capabilities":
        return xxe.capabilities(args)
    if name == "xxe.analyze_workspace":
        return xxe.analyze_workspace(args)
    if name == "xxe.generate_test_plan":
        return xxe.generate_test_plan(args)
    if name == "xxe.execute_test":
        return xxe.execute_test(args)
    if name == "graphql.capabilities":
        return graphql.capabilities(args)
    if name == "graphql.analyze_workspace":
        return graphql.analyze_workspace(args)
    if name == "graphql.generate_test_plan":
        return graphql.generate_test_plan(args)
    if name == "graphql.execute_test":
        return graphql.execute_test(args)
    if name == "tls_posture.capabilities":
        return tls_posture.capabilities(args)
    if name == "tls_posture.analyze_workspace":
        return tls_posture.analyze_workspace(args)
    if name == "ssrf.analyze_workspace":
        return ssrf_adapter.analyze_workspace(args)
    if name == "ssrf.generate_test_plan":
        return ssrf_adapter.generate_test_plan(args)
    if name == "ssrf.execute_test":
        return ssrf_adapter.execute_test(args)
    if name == "open_redirect.analyze_workspace":
        return open_redirect_adapter.analyze_workspace(args)
    if name == "open_redirect.generate_test_plan":
        return open_redirect_adapter.generate_test_plan(args)
    if name == "open_redirect.execute_test":
        return open_redirect_adapter.execute_test(args)
    if name == "command_injection.analyze_workspace":
        return command_injection_adapter.analyze_workspace(args)
    if name == "command_injection.generate_test_plan":
        return command_injection_adapter.generate_test_plan(args)
    if name == "command_injection.prepare_replay":
        return command_injection_adapter.prepare_replay(args)
    if name == "command_injection.execute_test":
        return command_injection_adapter.execute_test(args)
    if name == "cve.capabilities":
        return cve_intel.capabilities(args)
    if name == "cve.sources":
        return cve_intel.sources(args)
    if name == "cve.set_source_endpoint":
        return cve_intel.set_source_endpoint(args)
    if name == "cve.reset_source_endpoint":
        return cve_intel.reset_source_endpoint(args)
    if name == "cve.session_key.set":
        return cve_intel.set_session_key(args)
    if name == "cve.session_key.clear":
        return cve_intel.clear_session_key(args)
    if name == "cve.session_key.status":
        return cve_intel.session_key_status(args)
    if name == "cve.correlate":
        return cve_intel.correlate(args)
    if name == "cve.plan_tests":
        return cve_intel.plan_tests(args)
    if name == "cve.prepare_replay":
        return cve_intel.prepare_replay(args)
    if name == "cve.execute_test":
        return cve_intel.execute_test(args)
    if name == "ssti.capabilities":
        return ssti.capabilities(args)
    if name == "ssti.passive_analyze":
        return ssti.passive_analyze(args)
    if name == "ssti.plan_tests":
        return ssti.plan_tests(args)
    if name == "ssti.prepare_replay":
        return ssti.prepare_replay(args)
    if name == "ssti.execute_test":
        return ssti.execute_test(args)
    if name == "lfi.capabilities":
        return lfi_rfi.capabilities(args)
    if name == "lfi.passive_analyze":
        return lfi_rfi.passive_analyze(args)
    if name == "lfi.plan_tests":
        return lfi_rfi.plan_tests(args)
    if name == "lfi.execute_test":
        return lfi_rfi.execute_test(args)
    if name == "ssi.capabilities":
        return ssi.capabilities(args)
    if name == "ssi.passive_analyze":
        return ssi.passive_analyze(args)
    if name == "ssi.plan_tests":
        return ssi.plan_tests(args)
    if name == "ssi.prepare_replay":
        return ssi.prepare_replay(args)
    if name == "ssi.execute_test":
        return ssi.execute_test(args)
    if name == "access_control.capabilities":
        return access_control.capabilities(args)
    if name == "access_control.identify_objects":
        return access_control.identify_objects(args)
    if name == "access_control.record_context":
        return access_control.record_context(args)
    if name == "access_control.build_test_matrix":
        return access_control.build_test_matrix(args)
    if name == "access_control.plan_tests":
        return access_control.plan_tests(args)
    if name == "access_control.execute_matrix_test":
        return access_control.execute_matrix_test(args)
    if name == "js.capabilities":
        return js_intel.capabilities(args)
    if name == "js.discover_assets":
        return js_intel.discover_assets(args)
    if name == "js.fetch_assets":
        return js_intel.fetch_assets(args)
    if name == "js.analyze_static":
        return js_intel.analyze_static(args)
    if name == "js.normalize_endpoints":
        return js_intel.normalize_endpoints(args)
    if name == "js.build_app_model":
        return js_intel.build_app_model(args)
    if name == "js.render_app_map":
        return js_intel.render_app_map(args)
    if name == "sitemap.from_dump":
        return crawler_adapter.sitemap_from_dump(args)
    if name == "crawler.crawl":
        return crawler_adapter.crawl(args)
    if name == "crawler.extended":
        return crawler_adapter.crawl_extended(args)
    if name == "ffuf.profiles":
        return ffuf_adapter.list_profiles()
    if name == "ffuf.build_command":
        built = ffuf_adapter.build_command(args)
        return json.dumps({key: value for key, value in built.items() if not key.startswith("_")}, indent=2)
    if name == "ffuf.run_profile":
        return ffuf_adapter.run_profile(args)
    if name == "nuclei.profiles":
        return nuclei_adapter.list_profiles()
    if name == "nuclei.build_command":
        built = nuclei_adapter.build_command(args)
        return json.dumps({key: value for key, value in built.items() if not key.startswith("_")}, indent=2)
    if name == "nuclei.run_profile":
        return nuclei_adapter.run_profile(args)
    if name == "nmap.profiles":
        return nmap_adapter.list_profiles()
    if name == "nmap.build_command":
        return json.dumps(nmap_adapter.build_command(args), indent=2)
    if name == "nmap.run_profile":
        return nmap_adapter.run_profile(args)
    if name == "shodan.session_key.set":
        return shodan_adapter.set_session_key(args)
    if name == "shodan.session_key.clear":
        return shodan_adapter.clear_session_key(args)
    if name == "shodan.session_key.status":
        return shodan_adapter.session_key_status(args)
    if name == "shodan.host":
        return shodan_adapter.host_lookup(args)
    if name == "shodan.internetdb":
        return shodan_adapter.internetdb_lookup(args)
    if name == "shodan.domain":
        return shodan_adapter.domain_info(args)
    if name == "shodan.resolve":
        return shodan_adapter.resolve(args)
    if name == "shodan.reverse":
        return shodan_adapter.reverse(args)
    if name == "shodan.search_count":
        return shodan_adapter.search_count(args)
    if name == "shodan.search":
        return shodan_adapter.search(args)
    if name == "shodan.search_facets":
        return shodan_adapter.search_facets(args)
    if name == "shodan.search_filters":
        return shodan_adapter.search_filters(args)
    if name == "shodan.target_summary":
        return shodan_adapter.target_summary(args)
    if name == "shodan.company_queries":
        return shodan_adapter.company_queries(args)
    if name == "evidence.log_event":
        event_data = dict(args.get("data") or {})
        for key in ("workspaceId", "target", "organization"):
            if args.get(key) is not None and key not in event_data:
                event_data[key] = args[key]
        return json.dumps(evidence.log_event(args["type"], args["summary"], event_data), indent=2)
    if name == "evidence.tail":
        return json.dumps(evidence.tail_events(int(args.get("limit", 20))), indent=2)
    if name == "evidence.init_project":
        return json.dumps(evidence.ensure_project(args["organization"], args.get("hosts", [])), indent=2)
    if name == "evidence.host_context":
        return json.dumps(
            evidence.host_context(args["target"], args.get("organization"), int(args.get("limit", 50))),
            indent=2,
        )
    if name == "fingerprint.from_dump":
        return json.dumps(
            fingerprint.from_dump(
                args["dumpPath"],
                args.get("organization", "unknown-org"),
                args.get("target", ""),
                int(args.get("limit", 5000)),
            ),
            indent=2,
        )
    if name == "fingerprint.analyze_workspace":
        return json.dumps(fingerprint.analyze_workspace(args), indent=2)
    if name == "fingerprint.probe_versions":
        return json.dumps(fingerprint.probe_versions(args), indent=2)
    if name == "fingerprint.read_host":
        return json.dumps(
            fingerprint.read_host_fingerprint(args["target"], args.get("organization", "unknown-org")),
            indent=2,
        )
    raise McpError(-32601, f"Unknown tool: {name}")


bind_retained_legacy_implementation(_retained_legacy_call_impl)


def read_resource(uri: str) -> tuple[str, str]:
    if uri == "synapse://prompt/main":
        return "text/markdown", read_main_prompt()
    if uri == "synapse://dumps":
        return "application/json", json.dumps(dumps.list_dumps(), indent=2)
    if uri == "synapse://scope":
        return "application/json", json.dumps(scope.load_scope(), indent=2)
    if uri == "synapse://credentials":
        return "application/json", json.dumps(credentials.list_credentials(), indent=2)
    if uri == "synapse://evidence/recent":
        return "application/json", json.dumps(evidence.tail_events(), indent=2)
    if uri == "synapse://jobs/active":
        return "application/json", json.dumps(background_jobs.active_jobs(), indent=2)
    workspace_resource = workspace.read_workspace_resource(uri)
    if workspace_resource:
        return workspace_resource
    raise McpError(-32602, f"Unknown resource: {uri}")


def get_prompt(name: str) -> dict[str, Any]:
    if name != MAIN_PROMPT_NAME:
        raise McpError(-32602, f"Unknown prompt: {name}")
    return {
        "description": "Shared Synapse operating prompt.",
        "messages": [{"role": "user", "content": {"type": "text", "text": read_main_prompt()}}],
    }


def handle(request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    if method and method.startswith("notifications/"):
        return None
    req_id = request.get("id")
    try:
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
        elif method == "tools/list":
            result = {"tools": projection.projected_tools_list()}
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {}) or {}
            if not isinstance(arguments, dict):
                raise McpError(-32602, f"Invalid arguments for {tool_name}: arguments must be object")
            validate_tool_arguments(tool_name, arguments)
            text = call_tool_with_deadline(tool_name, arguments)
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        elif method == "resources/list":
            result = {"resources": RESOURCES}
        elif method == "resources/read":
            uri = request.get("params", {}).get("uri", "")
            mime_type, text = read_resource(uri)
            result = {"contents": [{"uri": uri, "mimeType": mime_type, "text": text}]}
        elif method == "prompts/list":
            result = {"prompts": PROMPTS}
        elif method == "prompts/get":
            result = get_prompt(request.get("params", {}).get("name", ""))
        else:
            raise McpError(-32601, f"Unsupported method: {method}")
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except McpError as exc:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": exc.code, "message": exc.message}}
    except ToolCallTimeout as exc:
        try:
            evidence.log_event(
                "mcp.tool_timeout",
                f"MCP tool call timed out: {exc.tool_name}",
                {"tool": exc.tool_name, "timeoutSeconds": exc.seconds},
            )
        except Exception:
            pass
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32003, "message": _timeout_error_message(exc)}}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(exc)}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            print(
                json_line({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}),
                flush=True,
            )
            continue
        response = handle(request)
        if response is not None:
            print(json_line(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
