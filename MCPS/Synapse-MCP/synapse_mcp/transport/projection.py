# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Legacy MCP projection of registered application actions."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from synapse_mcp.app.actions import (
    ActionRequest,
    ExecutionContext,
    ExecutionUnknown,
    REGISTRY,
    Success,
)
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import ExecutionPlanError, reject_reserved_runtime_fields

from .legacy_projection_map import LEGACY_DISPATCH_ACTIONS, LEGACY_PROJECTION_MAP


def _legacy_tool_schemas() -> list[dict[str, Any]]:
    from . import stdio_server

    return stdio_server._LEGACY_TOOL_SCHEMAS


def _projection_by_legacy_name(name: str, *, dispatch_only: bool = False):
    for action_id, projection in LEGACY_PROJECTION_MAP.items():
        if projection.legacy_name == name:
            if dispatch_only and action_id not in LEGACY_DISPATCH_ACTIONS:
                return None
            return action_id, projection
    return None


def project_call(name: str, args: dict[str, Any]) -> str | None:
    """Execute a migrated legacy name through the application registry."""

    matched = _projection_by_legacy_name(name, dispatch_only=True)
    if matched is None:
        return None
    action_id, legacy = matched
    descriptor = REGISTRY.get(action_id)
    try:
        reject_reserved_runtime_fields(args)
    except ExecutionPlanError as exc:
        raise McpError(-32602, str(exc)) from exc
    typed_input = descriptor.input_model.model_validate(args)

    from . import stdio_server

    request = ActionRequest(
        input=typed_input,
        context=ExecutionContext(
            workspace_id=args.get("workspaceId"),
            correlation_id=uuid4().hex,
            deadline_seconds=stdio_server._tool_deadline_seconds(name, args),
            legacy_approval_asserted=args.get("confirm"),
        ),
    )
    outcome = REGISTRY.execute(action_id, request)
    if isinstance(outcome, Success):
        legacy_payload = outcome.legacy_payload
        if legacy.serializer == "transport":
            serialized = json.dumps(legacy_payload, indent=2)
        else:
            if not isinstance(legacy_payload, str):
                raise TypeError(f"{name} executor must return a serialized string")
            serialized = legacy_payload
        return serialized
    if isinstance(outcome, ExecutionUnknown):
        raise RuntimeError("ExecutionUnknown is produced only by the transport timeout boundary")
    if outcome.legacy_code is None:
        raise RuntimeError(f"{name} returned an error outcome without a legacy code")
    raise McpError(outcome.legacy_code, outcome.message)


def resolved_input_schema(name: str) -> dict[str, Any]:
    """Resolve one input schema from its descriptor or the legacy list."""

    matched = _projection_by_legacy_name(name)
    if matched is not None:
        action_id, _ = matched
        return REGISTRY.get(action_id).input_model.contract_document.parsed()
    for tool in _legacy_tool_schemas():
        if tool.get("name") == name:
            schema = tool.get("inputSchema", {})
            return schema if isinstance(schema, dict) else {}
    return {}


def projected_tools_list() -> list[dict[str, Any]]:
    """Project the complete ordered legacy tool list from both schema sources."""

    tools: list[dict[str, Any]] = []
    for legacy_tool in _legacy_tool_schemas():
        tool = dict(legacy_tool)
        if _projection_by_legacy_name(str(tool.get("name"))) is not None:
            tool["inputSchema"] = resolved_input_schema(str(tool["name"]))
        tools.append(tool)
    return tools
