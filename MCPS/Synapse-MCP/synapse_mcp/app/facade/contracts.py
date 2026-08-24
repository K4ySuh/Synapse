# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Transport-independent contracts for the compact and direct services."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from synapse_mcp.app.context import ContextQueryInput


def _camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


class FacadeModel(BaseModel):
    """Strict public model with the repository's existing camel-case vocabulary."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        populate_by_name=True,
        alias_generator=_camel_case,
    )


class EngagementOpenInput(FacadeModel):
    organization: str
    hosts: list[str]
    workspace_id: str | None = None
    patterns: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    notes: str = ""
    dump_path: str | None = None
    fingerprint: bool = True
    limit: int = Field(default=5000, ge=1)
    cursor: str | None = None
    inventory_limit: int = Field(default=50, ge=1, le=500)
    include_inventory: bool = False


class EngagementInspectInput(FacadeModel):
    workspace_id: str
    cursor: str | None = None
    limit: int = Field(default=50, ge=1, le=500)
    include_inventory: bool = False


class CapabilitiesSearchInput(FacadeModel):
    query: str = ""
    pack: str | None = None
    intent: str | None = None
    effect: str | None = None
    risk: Literal["none", "low", "moderate", "high"] | None = None
    availability: Literal["available", "unavailable", "runtime_resolved"] | None = None
    credential_need: str | None = None
    scope: str | None = None
    cursor: str | None = None
    limit: int = Field(default=25, ge=1, le=100)


class ActionsDescribeInput(FacadeModel):
    action_id: str


class ActionExecutionInput(FacadeModel):
    action_id: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)


ReviewKind = Literal[
    "candidate_validation",
    "finding_promotion",
    "finding_signoff",
    "reportability",
    "pretext_approval",
]


class ReviewsApplyInput(FacadeModel):
    review: ReviewKind
    arguments: dict[str, JsonValue]
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)


class ArtifactsInspectInput(FacadeModel):
    resource_ref: str


class ReportsRenderInput(FacadeModel):
    workspace_id: str
    target: str | None = None
    targets: list[str] = Field(default_factory=list)
    layers: list[str] = Field(default_factory=list)
    refresh: bool = False
    format: Literal["html", "markdown"] = "html"
    redaction_mode: Literal[
        "operator",
        "operator_raw",
        "high_level",
        "internal",
        "raw",
        "safe",
    ] = "internal"
    output_path: str | None = None
    return_content: bool = False
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)


TaskOperation = Literal["list", "inspect", "cancel", "resume"]


class TasksControlInput(FacadeModel):
    operation: TaskOperation
    job_id: str | None = None
    operation_handle: str | None = None
    workspace_id: str | None = None
    limit: int = Field(default=20, ge=1, le=100)
    active_only: bool = False
    include_result: bool = False

    @model_validator(mode="after")
    def require_operation_identity(self) -> "TasksControlInput":
        if self.operation == "cancel" and not self.job_id:
            raise ValueError("tasks.control cancel requires jobId")
        if self.operation == "resume" and not self.operation_handle:
            raise ValueError("tasks.control resume requires operationHandle")
        if self.operation == "inspect" and not (self.job_id or self.operation_handle):
            raise ValueError("tasks.control inspect requires jobId or operationHandle")
        if self.operation == "inspect" and self.job_id and self.operation_handle:
            raise ValueError("tasks.control inspect accepts only one operation identity")
        return self


class EffectSummary(FacadeModel):
    traffic: list[str]
    local_writes: list[str]
    local_change: bool
    local_destruction: bool
    remote_state_change: bool
    credential_use: bool
    secret_use: bool
    replay_safety: str
    resolution_notes: list[str] = Field(default_factory=list)


class OperationAnnotations(FacadeModel):
    read_only: bool
    destructive: bool
    open_world: bool
    idempotent: bool
    resource_references: bool = False
    effects_dynamic: bool = False


class ResourceReference(FacadeModel):
    reference: str
    artifact_type: str
    media_type: str
    version: str
    size: int = Field(ge=0)


class ResolvedArtifact(FacadeModel):
    reference: ResourceReference
    encoding: Literal["utf-8", "base64"]
    content: str


class FacadeEnvelope(FacadeModel):
    operation: str
    action_id: str | None = None
    outcome_kind: str
    summary: str
    result: JsonValue | None = None
    requested_input: dict[str, JsonValue] | None = None
    evidence_references: list[str] = Field(default_factory=list)
    resource_references: list[ResourceReference] = Field(default_factory=list)
    diagnostics: dict[str, JsonValue] = Field(default_factory=dict)
    trace_id: str
    operation_handle: str | None = None


class CatalogItem(FacadeModel):
    action_id: str
    title: str
    description: str
    pack: str
    intent: str
    effects: EffectSummary
    risk: str
    availability: str
    credential_need: str
    scope: str
    approval_required: bool


class CatalogPage(FacadeModel):
    items: list[CatalogItem]
    total: int
    returned: int
    cursor: str | None = None
    next_cursor: str | None = None


class ActionDescription(FacadeModel):
    action_id: str
    title: str
    description: str
    pack: str
    intent: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    effects: EffectSummary
    risk: str
    scope: dict[str, JsonValue]
    credentials: dict[str, JsonValue]
    availability: dict[str, JsonValue]
    approval: dict[str, JsonValue]
    annotations: OperationAnnotations
    examples: list[dict[str, JsonValue]]


class ApplicationOperation(FacadeModel):
    name: str
    title: str
    description: str
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    annotations: OperationAnnotations
    action_id: str | None = None
    action_output_schema: dict[str, JsonValue] | None = None


@dataclass(frozen=True, slots=True)
class FacadeCallContext:
    """Trusted identity supplied by an adapter, never by model-facing input."""

    principal_id: str
    workspace_id: str = ""
    execution_profile: str = "observe"
    authority_session_id: str = ""
    selected_grant_id: str = ""
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if not self.principal_id.strip():
            raise PermissionError("A trusted principal is required")
        if self.execution_profile not in {"legacy", "observe", "supervised", "full_delegated"}:
            raise ValueError(f"Unknown execution profile: {self.execution_profile}")
        if self.execution_profile != "legacy" and not self.authority_session_id.strip():
            raise PermissionError("Authority-aware facade calls require a server-held session binding")


COMPACT_INPUT_MODELS: dict[str, type[BaseModel]] = {
    "engagement.open": EngagementOpenInput,
    "engagement.inspect": EngagementInspectInput,
    "context.query": ContextQueryInput,
    "capabilities.search": CapabilitiesSearchInput,
    "actions.describe": ActionsDescribeInput,
    "actions.run_passive": ActionExecutionInput,
    "actions.run_active": ActionExecutionInput,
    "reviews.apply": ReviewsApplyInput,
    "artifacts.inspect": ArtifactsInspectInput,
    "reports.render": ReportsRenderInput,
    "tasks.control": TasksControlInput,
}


def json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Return one deterministic validation schema using public aliases."""

    return model.model_json_schema(mode="validation", by_alias=True)


def compact_json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Remove non-semantic titles while preserving all validation keywords."""

    def strip_titles(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: strip_titles(child)
                for key, child in value.items()
                if key != "title"
            }
        if isinstance(value, list):
            return [strip_titles(child) for child in value]
        return value

    return strip_titles(json_schema(model))


_OUTCOME_KINDS = (
    "success",
    "approval_required",
    "validation_failure",
    "unavailable_capability",
    "policy_denial",
    "execution_failure",
    "execution_unknown",
)


def dynamic_json_object_schema(*, boundary: str, properties: tuple[str, ...] = ()) -> dict[str, Any]:
    """Describe one intentional JSON-object boundary without pretending it is static."""

    return {
        "type": "object",
        "properties": {name: {} for name in properties},
        "additionalProperties": {},
        "description": boundary,
    }


def concise_json_object_schema(schema: dict[str, Any], *, boundary: str = "") -> dict[str, Any]:
    """Keep an object's canonical top-level contract without expanding nested data."""

    properties = schema.get("properties")
    names = tuple(properties) if isinstance(properties, dict) else ()
    value: dict[str, Any] = {
        "type": "object",
        "properties": {name: {} for name in names},
        "required": [name for name in schema.get("required", []) if name in names],
        "additionalProperties": schema.get("additionalProperties", True) is not False,
    }
    if boundary:
        value["x-synapse-dynamic-boundary"] = boundary
    return value


def _embed_schema(schema: dict[str, Any], *, prefix: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebase a Pydantic schema's local definitions into an envelope document."""

    value = json.loads(json.dumps(schema))
    definitions = value.pop("$defs", {})

    def rewrite(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: (
                    f"#/$defs/{prefix}{child.removeprefix('#/$defs/')}"
                    if key == "$ref" and isinstance(child, str) and child.startswith("#/$defs/")
                    else rewrite(child)
                )
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [rewrite(child) for child in item]
        return item

    return rewrite(value), {f"{prefix}{name}": rewrite(child) for name, child in definitions.items()}


def facade_envelope_schema(
    operation: str,
    result_schema: dict[str, Any],
    *,
    action_id: str | None = None,
    compact: bool = False,
) -> dict[str, Any]:
    """Build the exact standard schema for returned structured facade envelopes."""

    result, definitions = _embed_schema(result_schema, prefix="Result")
    if compact:
        resource = {
            "type": "object",
            "required": ["reference"],
        }
    else:
        resource, resource_definitions = _embed_schema(json_schema(ResourceReference), prefix="Resource")
        definitions.update(resource_definitions)
    nullable_string = {"type": ["string", "null"]}
    properties: dict[str, Any] = {
        "operation": {"const": operation},
        "actionId": (
            {"const": action_id, "type": "string"}
            if action_id is not None
            else nullable_string
        ),
        "outcomeKind": {"enum": list(_OUTCOME_KINDS)},
        "summary": {"type": "string"},
        "result": {"anyOf": [result, {"type": "null"}]},
        "requestedInput": {
            "type": ["object", "null"],
            "additionalProperties": {},
        },
        "evidenceReferences": {"type": "array"} if compact else {"items": {"type": "string"}, "type": "array"},
        "resourceReferences": {"items": resource, "type": "array"},
        "diagnostics": {"type": "object"} if compact else {"additionalProperties": {}, "type": "object"},
        "traceId": {"type": "string"},
        "operationHandle": nullable_string,
    }
    if compact:
        branches = [
            {
                "if": {"properties": {"outcomeKind": {"const": "approval_required"}}},
                "then": {
                    "properties": {
                        "requestedInput": {"type": "object"},
                        "operationHandle": {"type": "string"},
                    }
                },
            },
        ]
    else:
        branches = [
            {
                "properties": {"outcomeKind": {"const": "success"}, "result": result},
                "required": ["result"],
            },
            {
                "properties": {
                    "outcomeKind": {"const": "approval_required"},
                    "result": {"type": "null"},
                    "requestedInput": {"type": "object"},
                    "operationHandle": {"type": "string"},
                },
                "required": ["requestedInput", "operationHandle"],
            },
            {
                "properties": {
                    "outcomeKind": {"enum": list(_OUTCOME_KINDS[2:])},
                    "result": {"type": "null"},
                    "operationHandle": {"type": "null"},
                }
            },
        ]
    document: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
        "allOf" if compact else "oneOf": branches,
    }
    if definitions:
        document["$defs"] = definitions
    if action_id is not None:
        document["x-synapse-action-output"] = action_id
    return document
