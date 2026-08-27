# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Deterministic compact and direct projections over application services."""

from __future__ import annotations

from enum import Enum
from typing import Any

from synapse_mcp.app.actions import CAPABILITY_PACKS, REGISTRY
from synapse_mcp.app.actions.registry import ActionRegistry
from synapse_mcp.app.capability_packs.loader import AssembledCapabilityPacks
from synapse_mcp.app.context import ContextQueryResult

from .catalog import action_annotations, model_facing_action_input_schema
from .contracts import (
    COMPACT_INPUT_MODELS,
    ApplicationOperation,
    ActionDescription,
    CatalogPage,
    FacadeCallContext,
    FacadeEnvelope,
    OperationAnnotations,
    ResolvedArtifact,
    compact_json_schema,
    compact_schema,
    concise_json_object_schema,
    dynamic_json_object_schema,
    facade_envelope_schema,
    json_schema,
)
from .services import ActionExecutionService, COMPACT_OPERATION_NAMES, CompactFacadeService


class SurfaceMode(str, Enum):
    LEGACY = "legacy"
    MODERN_COMPACT = "modern-compact"
    MODERN_DIRECT = "modern-direct"


_COMPACT_DETAILS = {
    "engagement.open": (
        "Open engagement",
        "Initialize an engagement workspace.",
        OperationAnnotations(read_only=False, destructive=False, open_world=False, idempotent=False),
    ),
    "engagement.inspect": (
        "Inspect engagement",
        "Return a workspace summary.",
        OperationAnnotations(read_only=True, destructive=False, open_world=False, idempotent=True),
    ),
    "context.query": (
        "Query target context",
        "Compile bounded workspace context.",
        OperationAnnotations(read_only=True, destructive=False, open_world=False, idempotent=True),
    ),
    "capabilities.search": (
        "Search capabilities",
        "Search canonical actions.",
        OperationAnnotations(read_only=True, destructive=False, open_world=False, idempotent=True),
    ),
    "actions.describe": (
        "Describe action",
        "Describe a canonical action.",
        OperationAnnotations(read_only=True, destructive=False, open_world=False, idempotent=True),
    ),
    "actions.run_passive": (
        "Run passive action",
        "Run a passive-gated action.",
        OperationAnnotations(
            read_only=False,
            destructive=False,
            open_world=False,
            idempotent=False,
            resource_references=True,
            effects_dynamic=True,
        ),
    ),
    "actions.run_active": (
        "Run action",
        "Run an authority-gated action.",
        OperationAnnotations(
            read_only=False,
            destructive=True,
            open_world=True,
            idempotent=False,
            resource_references=True,
            effects_dynamic=True,
        ),
    ),
    "reviews.apply": (
        "Apply reviewed decision",
        "Apply an operator review.",
        OperationAnnotations(read_only=False, destructive=False, open_world=False, idempotent=False),
    ),
    "artifacts.inspect": (
        "Inspect artifact",
        "Inspect a bound artifact.",
        OperationAnnotations(
            read_only=True,
            destructive=False,
            open_world=False,
            idempotent=True,
            resource_references=True,
        ),
    ),
    "reports.render": (
        "Render report",
        "Render a local report.",
        OperationAnnotations(
            read_only=False,
            destructive=False,
            open_world=False,
            idempotent=False,
            resource_references=True,
        ),
    ),
    "tasks.control": (
        "Control work",
        "Control jobs, handles, and work.",
        OperationAnnotations(
            read_only=False,
            destructive=True,
            open_world=True,
            idempotent=False,
            effects_dynamic=True,
        ),
    ),
}


class CompactProjection:
    def __init__(
        self,
        service: CompactFacadeService | None = None,
        *,
        registry: ActionRegistry = REGISTRY,
        capability_packs: AssembledCapabilityPacks = CAPABILITY_PACKS,
    ) -> None:
        self.service = service or CompactFacadeService(
            registry=registry,
            capability_packs=capability_packs,
        )
        self.registry = self.service.execution.registry

    def _selected_output_schema(self, action_id: str, *, boundary: str) -> dict[str, Any]:
        try:
            schema = self.registry.contract_schema(action_id)["outputSchema"]
        except LookupError:
            return dynamic_json_object_schema(boundary=boundary)
        return concise_json_object_schema(schema)

    def operations(self) -> tuple[ApplicationOperation, ...]:
        result_schemas = {
            "engagement.open": self._selected_output_schema(
                "project.start",
                boundary="Unavailable without project.start.",
            ),
            "engagement.inspect": self._selected_output_schema(
                "workspace.summary",
                boundary="Unavailable without workspace.summary.",
            ),
            "context.query": concise_json_object_schema(
                compact_json_schema(ContextQueryResult),
                boundary="Closed application-validated context.",
            ),
            "capabilities.search": concise_json_object_schema(compact_json_schema(CatalogPage)),
            "actions.describe": concise_json_object_schema(compact_json_schema(ActionDescription)),
            "actions.run_passive": dynamic_json_object_schema(
                boundary="Runtime-selected validated action output.",
                properties=("background", "job", "status", "result", "error"),
            ),
            "actions.run_active": dynamic_json_object_schema(
                boundary="Runtime-selected validated action output.",
                properties=("background", "job", "status", "result", "error"),
            ),
            "reviews.apply": dynamic_json_object_schema(
                boundary="Runtime-selected review output.",
                properties=("workspaceId", "target", "finding", "observation", "decision"),
            ),
            "artifacts.inspect": concise_json_object_schema(compact_json_schema(ResolvedArtifact)),
            "reports.render": self._selected_output_schema(
                "documentation.render_workspace_report",
                boundary="Unavailable without reporting.",
            ),
            "tasks.control": dynamic_json_object_schema(
                boundary="Job, operation-handle, or operational work-item state.",
                properties=("jobs", "job", "workItems", "workItemId", "count", "state", "operationHandle", "status"),
            ),
        }
        return tuple(
            ApplicationOperation(
                name=name,
                title=_COMPACT_DETAILS[name][0],
                description=_COMPACT_DETAILS[name][1],
                input_schema=compact_json_schema(COMPACT_INPUT_MODELS[name]),
                output_schema=compact_schema(
                    facade_envelope_schema(
                        name,
                        result_schemas[name],
                        compact=True,
                    )
                ),
                annotations=_COMPACT_DETAILS[name][2],
            )
            for name in COMPACT_OPERATION_NAMES
        )

    def invoke(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        context: FacadeCallContext,
    ) -> FacadeEnvelope:
        return self.service.invoke(operation, payload, context=context)


class DirectProjection:
    """One generated operation per canonical action, without copied metadata."""

    def __init__(
        self,
        *,
        registry: ActionRegistry = REGISTRY,
        execution: ActionExecutionService | None = None,
    ) -> None:
        self.registry = registry
        self.execution = execution or ActionExecutionService(registry=registry)

    def operations(self) -> tuple[ApplicationOperation, ...]:
        operations = []
        for descriptor in self.registry.descriptors():
            action_id = str(descriptor.id)
            schemas = self.registry.contract_schema(action_id)
            operations.append(
                ApplicationOperation(
                    name=action_id,
                    title=descriptor.title,
                    description=descriptor.summary,
                    input_schema=model_facing_action_input_schema(schemas["inputSchema"]),
                    output_schema=facade_envelope_schema(
                        action_id,
                        schemas["outputSchema"],
                        action_id=action_id,
                    ),
                    annotations=action_annotations(descriptor),
                    action_id=action_id,
                    action_output_schema=schemas["outputSchema"],
                )
            )
        return tuple(operations)

    def invoke(
        self,
        action_id: str,
        arguments: dict[str, Any],
        *,
        context: FacadeCallContext,
        idempotency_key: str | None = None,
    ) -> FacadeEnvelope:
        return self.execution.run(
            operation=action_id,
            action_id=action_id,
            arguments=arguments,
            context=context,
            passive_only=False,
            idempotency_key=idempotency_key,
        )


def build_application_projection(
    mode: SurfaceMode | str,
    *,
    registry: ActionRegistry = REGISTRY,
    capability_packs: AssembledCapabilityPacks = CAPABILITY_PACKS,
) -> CompactProjection | DirectProjection | None:
    """Select one server-lifetime surface from trusted operator configuration."""

    selected = SurfaceMode(mode)
    if selected is SurfaceMode.LEGACY:
        return None
    if selected is SurfaceMode.MODERN_COMPACT:
        return CompactProjection(registry=registry, capability_packs=capability_packs)
    return DirectProjection(registry=registry)
