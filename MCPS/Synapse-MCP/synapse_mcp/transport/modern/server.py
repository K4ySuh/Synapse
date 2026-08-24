# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Official Python SDK adapter over the Phase 3B application projections."""

from __future__ import annotations

from dataclasses import dataclass
import inspect
import json
import logging
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from synapse_mcp import __version__
from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.app.facade.contracts import (
    COMPACT_INPUT_MODELS,
    ApplicationOperation,
    FacadeCallContext,
    FacadeEnvelope,
)
from synapse_mcp.app.facade.projections import CompactProjection, DirectProjection, SurfaceMode
from synapse_mcp.app.facade.resources import ResourceAccessError, ResourceReferenceService
from synapse_mcp.app.facade.services import (
    ActionExecutionService,
    CompactFacadeService,
    OperationHandleService,
)

from .config import ModernAdapterConfig, is_loopback_host, load_rotation_keyring
from .http_security import AuthenticatedHTTPMiddleware
from .identity import (
    CURRENT_HTTP_PRINCIPAL,
    AuthorityBindingResolver,
    TokenPrincipalResolver,
)


LOGGER = logging.getLogger(__name__)
MODERN_PROTOCOL_REVISION = "2026-07-28"
MODERN_SDK_VERSION = "2.0.0"
RESOURCE_URI_TEMPLATE = "synapse://artifact/{reference}"
SERVER_INSTRUCTIONS = (
    "Synapse is a local-first control plane for authorized human-in-the-loop security work. "
    "Use capabilities.search and actions.describe before dynamic execution. Passive calls fail "
    "closed on traffic, credentials, secrets, remote mutation, and destructive effects. Active "
    "calls use server-held scope and authority; tool arguments never grant authority. Approval "
    "requests must be reviewed through the trusted operator service. When an approval result "
    "contains operationHandle and tasks.control is available, resume with tasks.control using "
    "operation=resume and that handle. Protocol input_required results are retried with the same "
    "tool and arguments using their request state. Artifact links are opaque and reauthorized on "
    "every read. Opaque resourceRef objects returned for local source files or dump directories may "
    "be passed back in matching source-path fields; Synapse resolves them only after rebinding checks. "
    "Never place secrets in arguments, notes, logs, or reports."
)


@dataclass(slots=True)
class ModernAdapterRuntime:
    config: ModernAdapterConfig
    server: Any
    projection: CompactProjection | DirectProjection
    execution: ActionExecutionService
    resources: ResourceReferenceService
    operations: OperationHandleService
    bindings: AuthorityBindingResolver
    tokens: TokenPrincipalResolver | None


def _require_sdk() -> dict[str, Any]:
    try:
        from mcp import MCPError
        from mcp.server import CacheHint, MCPServer
        from mcp.server.mcpserver import Context
        from mcp.server.request_state import RequestStateSecurity
        from mcp.server.transport_security import TransportSecuritySettings
        from mcp.types import (
            CallToolResult,
            InputRequiredResult,
            INVALID_PARAMS,
            ResourceLink,
            TextContent,
            ToolAnnotations,
        )
    except ImportError as exc:  # pragma: no cover - default installation profile
        raise RuntimeError("The modern adapter requires: pip install -e '.[modern]'") from exc
    return locals()


def _principal(config: ModernAdapterConfig) -> str:
    if config.transport == "stdio":
        return config.stdio_principal
    principal = CURRENT_HTTP_PRINCIPAL.get()
    if not principal:
        raise PermissionError("authenticated HTTP principal is unavailable")
    return principal


def _trace_id(context: Any, *, observability: str = "otel") -> str:
    if observability == "otel":
        try:
            from opentelemetry import trace

            span_context = trace.get_current_span().get_span_context()
            if span_context.is_valid:
                return f"{span_context.trace_id:032x}"
        except Exception:  # pragma: no cover - tracing is deliberately optional
            pass
    return f"mcp-{uuid4().hex}"


def _workspace_from_payload(
    operation: str,
    payload: dict[str, Any],
    *,
    principal_id: str,
    request_state: str,
    resources: ResourceReferenceService,
    operations: OperationHandleService,
) -> str:
    if request_state:
        return operations.workspace_hint(request_state, principal_id=principal_id)
    direct = payload.get("workspaceId")
    if isinstance(direct, str) and direct:
        return direct
    nested = payload.get("arguments")
    if isinstance(nested, dict):
        workspace_id = nested.get("workspaceId")
        if isinstance(workspace_id, str) and workspace_id:
            return workspace_id
    if operation == "artifacts.inspect":
        reference = payload.get("resourceRef")
        if isinstance(reference, str) and reference:
            return resources.workspace_hint(reference, principal_id=principal_id)
    handle = payload.get("operationHandle")
    if isinstance(handle, str) and handle:
        return operations.workspace_hint(handle, principal_id=principal_id)
    return ""


def _call_context(runtime: ModernAdapterRuntime, sdk_context: Any, operation: str, payload: dict[str, Any]) -> FacadeCallContext:
    principal_id = _principal(runtime.config)
    request_state = str(sdk_context.request_state or "")
    workspace_id = _workspace_from_payload(
        operation,
        payload,
        principal_id=principal_id,
        request_state=request_state,
        resources=runtime.resources,
        operations=runtime.operations,
    )
    binding = runtime.bindings.resolve(principal_id, workspace_id)
    return FacadeCallContext(
        principal_id=principal_id,
        workspace_id=workspace_id or binding.workspace_id,
        execution_profile=binding.execution_profile,
        authority_session_id=binding.authority_session_id,
        selected_grant_id=binding.selected_grant_id,
        correlation_id=_trace_id(sdk_context, observability=runtime.config.observability),
    )


def _annotations(value: Any, tool_annotations: Any) -> Any:
    return tool_annotations(
        title=None,
        readOnlyHint=value.read_only,
        destructiveHint=value.destructive,
        idempotentHint=value.idempotent,
        openWorldHint=value.open_world,
    )


def _public_schema(schema: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(schema))
    properties = value.get("properties")
    if isinstance(properties, dict):
        properties.pop("confirm", None)
        properties.pop("allowExternalOutput", None)
    required = value.get("required")
    if isinstance(required, list):
        value["required"] = [
            name for name in required if name not in {"confirm", "allowExternalOutput"}
        ]
    return value


def _signature(model: type[Any], *, context_type: Any, input_required_type: Any) -> inspect.Signature:
    parameters: list[inspect.Parameter] = []
    for name, field in model.model_fields.items():
        public_name = field.alias or name
        if public_name in {"confirm", "allowExternalOutput"}:
            continue
        if field.is_required():
            default = inspect.Parameter.empty
        else:
            default = field.get_default(call_default_factory=True)
        parameters.append(
            inspect.Parameter(
                public_name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=field.rebuild_annotation(),
            )
        )
    parameters.append(inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=context_type))
    return inspect.Signature(parameters, return_annotation=FacadeEnvelope | input_required_type)


def _protocol_error(
    envelope: FacadeEnvelope,
    sdk: dict[str, Any],
    *,
    protocol_version: str,
    surface: str,
) -> Exception:
    diagnostics = envelope.diagnostics or {}
    data: dict[str, Any] = {
        "reason": str(diagnostics.get("reasonCode") or "validation_failure")[:128],
        "traceId": envelope.trace_id[:128],
        "protocolVersion": protocol_version,
        "surface": surface,
    }
    errors = diagnostics.get("errors")
    if isinstance(errors, list):
        data["errors"] = errors[:20]
    return sdk["MCPError"](sdk["INVALID_PARAMS"], envelope.summary[:1000], data)


def _tool_result(
    envelope: FacadeEnvelope,
    sdk_context: Any,
    sdk: dict[str, Any],
    *,
    surface: str,
) -> Any:
    compatibility_meta = {
        "synapse/protocolVersion": str(sdk_context.protocol_version),
        "synapse/surface": surface,
    }
    if envelope.outcome_kind == "validation_failure":
        raise _protocol_error(
            envelope,
            sdk,
            protocol_version=str(sdk_context.protocol_version),
            surface=surface,
        )
    if envelope.outcome_kind == "approval_required" and sdk_context.protocol_version == MODERN_PROTOCOL_REVISION:
        handle = envelope.operation_handle
        if not handle:
            raise sdk["MCPError"](-32603, "Approval state could not be persisted")
        return sdk["InputRequiredResult"](
            meta={
                **compatibility_meta,
                "synapse/status": "approval_required",
                "synapse/operationHandle": handle,
                "synapse/requestedInput": envelope.requested_input or {"review": "operator_authority"},
                "synapse/reason": envelope.diagnostics.get("reasonCode", "approval_required"),
                "synapse/dispatch": "not_started",
                "synapse/traceId": envelope.trace_id,
            },
            requestState=handle,
        )
    structured = envelope.model_dump(mode="json", by_alias=True)
    is_error = envelope.outcome_kind != "success"
    content: list[Any] = [sdk["TextContent"](text=envelope.summary[:1000])]
    for reference in envelope.resource_references:
        content.append(
            sdk["ResourceLink"](
                name=reference.artifact_type,
                title=f"Synapse {reference.artifact_type}",
                uri=f"synapse://artifact/{reference.reference}",
                description="Opaque, workspace-bound Synapse artifact.",
                mimeType=reference.media_type,
                size=reference.size,
            )
        )
    return sdk["CallToolResult"](
        content=content,
        structuredContent=structured,
        isError=is_error,
        meta=compatibility_meta,
    )


def _input_model(runtime: ModernAdapterRuntime, operation: ApplicationOperation) -> type[Any]:
    if runtime.config.surface is SurfaceMode.MODERN_COMPACT:
        return COMPACT_INPUT_MODELS[operation.name]
    return REGISTRY.get(operation.name).input_model


def _projected_callable(runtime: ModernAdapterRuntime, operation: ApplicationOperation, sdk: dict[str, Any]) -> Callable[..., Any]:
    def dispatch(**arguments: Any) -> Any:
        sdk_context = arguments.pop("ctx")
        payload = {key: value for key, value in arguments.items() if value is not None}
        try:
            context = _call_context(runtime, sdk_context, operation.name, payload)
            if sdk_context.request_state:
                envelope = runtime.execution.resume(
                    str(sdk_context.request_state),
                    context=context,
                    response_operation=operation.name,
                )
            elif isinstance(runtime.projection, CompactProjection):
                envelope = runtime.projection.invoke(operation.name, payload, context=context)
            else:
                envelope = runtime.projection.invoke(operation.name, payload, context=context)
        except (PermissionError, ResourceAccessError) as exc:
            reason = getattr(exc, "reason_code", "principal_binding_denied")
            raise sdk["MCPError"](
                -32002,
                str(exc),
                {
                    "reason": reason,
                    "protocolVersion": str(sdk_context.protocol_version),
                    "surface": runtime.config.surface.value,
                },
            ) from exc
        return _tool_result(
            envelope,
            sdk_context,
            sdk,
            surface=runtime.config.surface.value,
        )

    dispatch.__name__ = operation.name.replace(".", "_")
    dispatch.__doc__ = operation.description
    dispatch.__annotations__ = {
        "ctx": sdk["Context"],
        "return": FacadeEnvelope | sdk["InputRequiredResult"],
    }
    dispatch.__signature__ = _signature(  # type: ignore[attr-defined]
        _input_model(runtime, operation),
        context_type=sdk["Context"],
        input_required_type=sdk["InputRequiredResult"],
    )
    return dispatch


def build_runtime(
    config: ModernAdapterConfig,
    *,
    bindings: AuthorityBindingResolver | None = None,
    tokens: TokenPrincipalResolver | None = None,
) -> ModernAdapterRuntime:
    # Retained descriptors are canonical application actions, not a legacy-only
    # surface. Bind their frozen implementation adapter in standalone modern
    # processes as well as in the hand-written transport process.
    from synapse_mcp.app.actions.legacy_bridge import retained_legacy_implementation_bound

    if not retained_legacy_implementation_bound():
        from synapse_mcp.transport import stdio_server as _retained_transport  # noqa: F401

    sdk = _require_sdk()
    state_dir = config.state_dir
    resources = ResourceReferenceService(state_path=state_dir / "resources.json")
    operations = OperationHandleService(state_path=state_dir / "operations.json")
    execution = ActionExecutionService(resources=resources, operations=operations)
    if config.surface is SurfaceMode.MODERN_COMPACT:
        projection: CompactProjection | DirectProjection = CompactProjection(
            CompactFacadeService(resources=resources, operations=operations)
        )
        execution = projection.service.execution
    else:
        projection = DirectProjection(execution=execution)
    binding_resolver = bindings or AuthorityBindingResolver(config.identity_bindings_path)
    token_resolver = tokens
    if config.transport == "streamable-http" and token_resolver is None:
        token_resolver = TokenPrincipalResolver(config.http_token_map_path)

    if config.request_state_keyring_path is None:
        request_state_security = sdk["RequestStateSecurity"].ephemeral(
            ttl=config.request_state_ttl_seconds,
            audience=config.audience,
        )
        LOGGER.warning("Modern adapter is using an ephemeral local request-state key; retries do not survive restart")
    else:
        request_state_security = sdk["RequestStateSecurity"](
            keys=load_rotation_keyring(config.request_state_keyring_path),
            ttl=config.request_state_ttl_seconds,
            audience=config.audience,
            bind_principal=(
                (lambda _context: config.stdio_principal)
                if config.transport == "stdio"
                else (lambda _context: CURRENT_HTTP_PRINCIPAL.get())
            ),
        )
    server = sdk["MCPServer"](
        name=config.server_name,
        title="Synapse Modern MCP",
        description="Production official-SDK adapter over Synapse application services.",
        instructions=SERVER_INSTRUCTIONS,
        version=__version__,
        request_state_security=request_state_security,
        cache_hints={
            "server/discover": sdk["CacheHint"](ttl_ms=60_000, scope="public"),
            "tools/list": sdk["CacheHint"](ttl_ms=60_000, scope="public"),
            "resources/templates/list": sdk["CacheHint"](ttl_ms=60_000, scope="public"),
            "resources/read": sdk["CacheHint"](ttl_ms=0, scope="private"),
        },
    )
    if config.observability == "disabled":
        from mcp.server._otel import OpenTelemetryMiddleware

        server._lowlevel_server.middleware = [
            middleware
            for middleware in server._lowlevel_server.middleware
            if not isinstance(middleware, OpenTelemetryMiddleware)
        ]
    runtime = ModernAdapterRuntime(
        config=config,
        server=server,
        projection=projection,
        execution=execution,
        resources=resources,
        operations=operations,
        bindings=binding_resolver,
        tokens=token_resolver,
    )
    for operation in projection.operations():
        server.add_tool(
            _projected_callable(runtime, operation, sdk),
            name=operation.name,
            title=operation.title,
            description=operation.description,
            annotations=_annotations(operation.annotations, sdk["ToolAnnotations"]),
            meta={
                "synapse/surface": config.surface.value,
                "synapse/actionId": operation.action_id,
                "synapse/actionOutputSchema": operation.action_output_schema,
                "synapse/effectsDynamic": operation.annotations.effects_dynamic,
                "synapse/resourceReferences": operation.annotations.resource_references,
                "synapse/sdkVersion": MODERN_SDK_VERSION,
            },
        )
        registered = server._tool_manager.get_tool(operation.name)
        if registered is None:  # pragma: no cover - SDK registration invariant
            raise RuntimeError(f"official SDK failed to register {operation.name}")
        if config.surface is SurfaceMode.MODERN_COMPACT:
            # The SDK's generated callable model defaults to ignoring unknown
            # kwargs. Compact kwargs are control-plane positions, so fail them
            # closed before the facade can be invoked.
            registered.fn_metadata.arg_model.model_config["extra"] = "forbid"
            registered.fn_metadata.arg_model.model_rebuild(force=True)
        registered.parameters = _public_schema(operation.input_schema)
        registered.fn_metadata.output_schema = operation.output_schema

    def read_synapse_artifact(reference: str, **values: Any) -> str | bytes:
        ctx = values.pop("ctx")
        try:
            principal_id = _principal(config)
            workspace_id = resources.workspace_hint(reference, principal_id=principal_id)
            binding = binding_resolver.resolve(principal_id, workspace_id)
            context = FacadeCallContext(
                principal_id=principal_id,
                workspace_id=workspace_id,
                execution_profile=binding.execution_profile,
                authority_session_id=binding.authority_session_id,
                selected_grant_id=binding.selected_grant_id,
                correlation_id=_trace_id(ctx, observability=config.observability),
            )
            artifact = resources.resolve(reference, context=context)
        except (PermissionError, ResourceAccessError) as exc:
            reason = getattr(exc, "reason_code", "principal_binding_denied")
            raise sdk["MCPError"](-32002, str(exc), {"reason": reason}) from exc
        if artifact.encoding == "utf-8":
            return artifact.content
        import base64

        return base64.b64decode(artifact.content)

    read_synapse_artifact.__annotations__ = {
        "reference": str,
        "ctx": sdk["Context"],
        "return": str | bytes,
    }
    read_synapse_artifact.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        (
            inspect.Parameter("reference", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str),
            inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=sdk["Context"]),
        ),
        return_annotation=str | bytes,
    )
    server.resource(
        RESOURCE_URI_TEMPLATE,
        name="synapse-artifact",
        title="Synapse artifact",
        description="Read one opaque artifact after principal, session, workspace, root, and version checks.",
        mime_type="application/octet-stream",
    )(read_synapse_artifact)

    return runtime


def build_http_app(runtime: ModernAdapterRuntime) -> Any:
    sdk = _require_sdk()
    config = runtime.config
    security = None
    if config.allowed_hosts or config.allowed_origins or not is_loopback_host(config.host):
        security = sdk["TransportSecuritySettings"](
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.allowed_hosts),
            allowed_origins=list(config.allowed_origins),
        )
    app = runtime.server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security=security,
        host=config.host,
    )
    if runtime.tokens is None:  # pragma: no cover - configuration gate
        raise RuntimeError("HTTP principal resolver was not configured")
    return AuthenticatedHTTPMiddleware(app, config=config, tokens=runtime.tokens)


def run_runtime(runtime: ModernAdapterRuntime) -> None:
    config = runtime.config
    if config.transport == "stdio":
        runtime.server.run("stdio")
        return
    import uvicorn

    app = build_http_app(runtime)
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level="info",
        proxy_headers=False,
        ssl_certfile=str(config.tls_certfile) if config.tls_certfile else None,
        ssl_keyfile=str(config.tls_keyfile) if config.tls_keyfile else None,
    )
