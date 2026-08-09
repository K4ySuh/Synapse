# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Opt-in MCP 2026-07-28 transport spike over three Registry v2 actions."""

from __future__ import annotations

import argparse
import inspect
import os
from typing import Any, Callable
from uuid import uuid4

from synapse_mcp import __version__
from synapse_mcp.app.actions import (
    ActionRequest,
    ApprovalRequired,
    ExecutionContext,
    Idempotency,
    REGISTRY,
    Success,
)


MODERN_SPIKE_ENV = "SYNAPSE_ENABLE_MODERN_SPIKE"
MODERN_AUTHORITY_PROFILE_ENV = "SYNAPSE_MODERN_AUTHORITY_PROFILE"
MODERN_AUTHORITY_GRANT_ENV = "SYNAPSE_MODERN_AUTHORITY_GRANT_ID"
MODERN_AUTHORITY_SESSION_ENV = "SYNAPSE_MODERN_AUTHORITY_SESSION_ID"
MODERN_REQUEST_STATE_ENV = "SYNAPSE_MODERN_REQUEST_STATE_ID"
MODERN_PROTOCOL_REVISION = "2026-07-28"
MODERN_SDK_VERSION = "2.0.0"
MODERN_ACTION_IDS = (
    "workspace.summary",
    "headers_cookies.analyze_workspace",
    "cors.execute_test",
)
ACTIVE_ACTION_ID = "cors.execute_test"


def _require_sdk() -> tuple[Any, Any, Any, Any]:
    try:
        from mcp.server import MCPServer
        from mcp.server.mcpserver import Context
        from mcp.types import CallToolResult, InputRequiredResult, TextContent, ToolAnnotations
    except ImportError as exc:  # pragma: no cover - exercised by the default installation profile
        raise RuntimeError(
            "The modern spike requires the isolated optional extra: pip install -e '.[modern-spike]'"
        ) from exc
    return MCPServer, CallToolResult, InputRequiredResult, (TextContent, ToolAnnotations, Context)


def _annotations(descriptor: Any, tool_annotations: Any) -> Any:
    effects = descriptor.effects
    read_only = not effects.traffic and not effects.local_writes and not effects.local_change
    idempotent = effects.replay_safety in {
        Idempotency.PURE_READ,
        Idempotency.IDEMPOTENT_WRITE,
        Idempotency.IDEMPOTENT_CONTROL,
    }
    return tool_annotations(
        title=descriptor.title,
        readOnlyHint=read_only,
        destructiveHint=effects.local_destruction or effects.remote_state_change,
        idempotentHint=idempotent,
        openWorldHint=bool(effects.traffic),
    )


def _signature_for(descriptor: Any, input_required_result: Any, context_type: Any) -> inspect.Signature:
    parameters = []
    for name, field in descriptor.input_model.model_fields.items():
        if name == "confirm":
            continue
        default = inspect.Parameter.empty if field.is_required() else field.default
        parameters.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=field.rebuild_annotation(),
            )
        )
    parameters.append(
        inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=context_type)
    )
    return inspect.Signature(
        parameters,
        return_annotation=descriptor.output_model | input_required_result,
    )


def _projected_callable(
    action_id: str,
    *,
    call_tool_result: Any,
    input_required_result: Any,
    text_content: Any,
    context_type: Any,
) -> Callable[..., Any]:
    descriptor = REGISTRY.get(action_id)

    def dispatch(**arguments: Any) -> Any:
        context = arguments.pop("ctx")
        # The SDK materializes omitted optional parameters as their None default;
        # legacy-derived action models distinguish omission from an explicit null.
        canonical_arguments = {key: value for key, value in arguments.items() if value is not None}
        if "confirm" in descriptor.input_model.model_fields:
            # Temporary input-shape compatibility only. False cannot authorize
            # execution; the trusted grant receipt is the sole modern signal.
            canonical_arguments["confirm"] = False
        validated_input = descriptor.input_model.model_validate(canonical_arguments)
        request = ActionRequest(
            input=validated_input,
            context=ExecutionContext(
                workspace_id=arguments.get("workspaceId"),
                correlation_id=f"modern-spike-{uuid4().hex}",
                deadline_seconds=descriptor.task_policy.deadline_tier.value,
                legacy_approval_asserted=None,
                execution_profile=os.environ.get(MODERN_AUTHORITY_PROFILE_ENV, "observe"),
                authority_session_id=os.environ.get(MODERN_AUTHORITY_SESSION_ENV, "local-modern-spike"),
                selected_grant_id=os.environ.get(MODERN_AUTHORITY_GRANT_ENV, ""),
                idempotency_key=f"modern-{uuid4().hex}",
                request_state_id=os.environ.get(MODERN_REQUEST_STATE_ENV, ""),
            ),
        )
        outcome = REGISTRY.execute(action_id, request)
        if isinstance(outcome, ApprovalRequired) and context.protocol_version == MODERN_PROTOCOL_REVISION:
            details = outcome.details or {}
            return input_required_result(
                meta={
                    "synapse/status": "approval_required",
                    "synapse/actionId": action_id,
                    "synapse/dispatch": "not_started",
                    "synapse/reason": outcome.reason_code or "approval_required",
                    "synapse/requirement": details.get("requirement"),
                },
                requestState=str(details.get("requestStateId") or "approval-required:authority-state"),
            )
        if not isinstance(outcome, Success):
            reason = getattr(outcome, "reason_code", None) or outcome.kind
            raise RuntimeError(f"{outcome.kind}[{reason}]: {outcome.message}")
        structured = outcome.payload.model_dump(mode="json", by_alias=True)
        return call_tool_result(
            content=[text_content(text=f"{descriptor.title}: completed")],
            structuredContent=structured,
            isError=False,
        )

    dispatch.__name__ = action_id.replace(".", "_")
    dispatch.__doc__ = descriptor.summary
    dispatch.__annotations__ = {
        "ctx": context_type,
        "return": descriptor.output_model | input_required_result,
    }
    dispatch.__signature__ = _signature_for(  # type: ignore[attr-defined]
        descriptor,
        input_required_result,
        context_type,
    )
    return dispatch


def build_server() -> Any:
    """Build the reversible three-action SDK server when explicitly enabled."""

    if os.environ.get(MODERN_SPIKE_ENV) != "1":
        raise RuntimeError(f"Modern MCP spike is disabled; set {MODERN_SPIKE_ENV}=1 to opt in")
    MCPServer, CallToolResult, InputRequiredResult, content_types = _require_sdk()
    TextContent, ToolAnnotations, Context = content_types
    server = MCPServer(
        name="synapse-modern-spike",
        description="Isolated Registry v2 transport feasibility spike",
        version=__version__,
    )
    for action_id in MODERN_ACTION_IDS:
        descriptor = REGISTRY.get(action_id)
        server.add_tool(
            _projected_callable(
                action_id,
                call_tool_result=CallToolResult,
                input_required_result=InputRequiredResult,
                text_content=TextContent,
                context_type=Context,
            ),
            name=action_id,
            title=descriptor.title,
            description=descriptor.summary,
            annotations=_annotations(descriptor, ToolAnnotations),
            meta={
                "synapse/profile": "authority-aware-modern-spike",
                "synapse/protocolRevision": MODERN_PROTOCOL_REVISION,
                "synapse/sdkVersion": MODERN_SDK_VERSION,
                "synapse/effectsSource": "action_registry_v2",
            },
        )
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("The spike transport is restricted to loopback hosts")
    server = build_server()
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run(
            "streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
        )


if __name__ == "__main__":
    main()
