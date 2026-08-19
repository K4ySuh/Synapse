# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-independent compact facade and shared action execution service."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from synapse_mcp.app.actions import (
    ActionEffects,
    ActionId,
    ActionRequest,
    ApprovalRequired,
    ExecutionContext,
    ExecutionFailure,
    ExecutionUnknown,
    PolicyDenial,
    REGISTRY,
    Success,
    UnavailableCapability,
    ValidationFailure,
)
from synapse_mcp.app.actions.registry import ActionRegistry
from synapse_mcp.core import workspace
from synapse_mcp.policy.repository import AuthorityRepositoryError, WorkspaceAuthorityRepository

from .catalog import ActionCatalogService, effect_summary
from .contracts import (
    COMPACT_INPUT_MODELS,
    ActionExecutionInput,
    ActionsDescribeInput,
    ArtifactsInspectInput,
    CapabilitiesSearchInput,
    ContextQueryInput,
    EngagementInspectInput,
    EngagementOpenInput,
    FacadeCallContext,
    FacadeEnvelope,
    FacadeModel,
    ReportsRenderInput,
    ReviewsApplyInput,
    TasksControlInput,
)
from .resources import ResourceAccessError, ResourceReferenceService


COMPACT_OPERATION_NAMES = tuple(COMPACT_INPUT_MODELS)

REVIEW_ACTIONS = {
    "candidate_validation": "workspace.record_candidate_validation",
    "finding_promotion": "workspace.promote_observation_to_finding",
    "finding_signoff": "workspace.mark_finding_reviewed",
    "reportability": "workspace.set_entity_reportable",
    "pretext_approval": "social.approve_pretext_candidate",
}

_AUTHORITY_FIELDS = frozenset(
    {
        "authority",
        "authoritygrant",
        "authoritygrantid",
        "authorityprofile",
        "authoritysession",
        "authoritysessionid",
        "executionprofile",
        "grant",
        "grantid",
        "grantsecret",
        "principal",
        "principalid",
        "requeststate",
        "requeststateid",
        "selectedgrantid",
        "sessionselection",
    }
)


def passive_gate_reasons(effects: ActionEffects) -> tuple[str, ...]:
    """Return the fail-closed dimensions forbidden to the passive invoker."""

    reasons: list[str] = []
    if effects.traffic:
        reasons.append("traffic")
    if effects.credential_use:
        reasons.append("credential_use")
    if effects.secret_use:
        reasons.append("secret_use")
    if effects.remote_state_change:
        reasons.append("remote_state_change")
    if effects.local_destruction:
        reasons.append("local_destruction")
    return tuple(reasons)


def _normalized_key(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _authority_field(value: Any, *, declared_top_level: frozenset[str], depth: int = 0) -> str:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                continue
            normalized = _normalized_key(key)
            if normalized in _AUTHORITY_FIELDS:
                return key
            if normalized == "profile" and (depth > 0 or key not in declared_top_level):
                return key
            found = _authority_field(child, declared_top_level=declared_top_level, depth=depth + 1)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _authority_field(child, declared_top_level=declared_top_level, depth=depth + 1)
            if found:
                return found
    return ""


def _trace_id(context: FacadeCallContext) -> str:
    return context.correlation_id or f"facade-{uuid4().hex}"


def _validation_envelope(
    operation: str,
    context: FacadeCallContext,
    message: str,
    *,
    action_id: str | None = None,
    reason_code: str = "facade_validation_failed",
    trace_id: str | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> FacadeEnvelope:
    return FacadeEnvelope(
        operation=operation,
        action_id=action_id,
        outcome_kind="validation_failure",
        summary=message,
        diagnostics={"reasonCode": reason_code, **(diagnostics or {})},
        trace_id=trace_id or _trace_id(context),
    )


def _model_error_diagnostics(exc: ValidationError) -> dict[str, Any]:
    return {
        "errors": [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())),
                "type": str(error.get("type") or "validation_error"),
            }
            for error in exc.errors(include_input=False, include_url=False)
        ]
    }


def _evidence_references(value: Any) -> list[str]:
    found: list[str] = []

    def visit(item: Any, key: str = "") -> None:
        if isinstance(item, dict):
            for name, child in item.items():
                visit(child, str(name))
        elif isinstance(item, list):
            for child in item:
                visit(child, key)
        elif isinstance(item, str) and key.lower() in {
            "evidenceid",
            "evidenceids",
            "evidenceref",
            "evidencereference",
            "evidencereferences",
        }:
            found.append(item)

    visit(value)
    return list(dict.fromkeys(found))


@dataclass(slots=True)
class _PendingOperation:
    handle: str
    request_state_id: str
    action_id: str
    arguments: dict[str, Any]
    workspace_id: str
    principal_id: str
    authority_session_id: str
    correlation_id: str
    idempotency_key: str
    state: str = "input_required"


class OperationHandleService:
    """Opaque facade handles over server-held Phase 2 request state."""

    def __init__(self) -> None:
        self._operations: dict[str, _PendingOperation] = {}
        self._by_request_state: dict[str, str] = {}

    def register(
        self,
        *,
        request_state_id: str,
        action_id: str,
        arguments: dict[str, Any],
        workspace_id: str,
        context: FacadeCallContext,
        correlation_id: str,
        idempotency_key: str,
    ) -> str:
        existing = self._by_request_state.get(request_state_id)
        if existing:
            return existing
        handle = f"operation-{secrets.token_urlsafe(24)}"
        self._operations[handle] = _PendingOperation(
            handle=handle,
            request_state_id=request_state_id,
            action_id=action_id,
            arguments=dict(arguments),
            workspace_id=workspace.normalize_workspace_id(workspace_id),
            principal_id=context.principal_id,
            authority_session_id=context.authority_session_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        self._by_request_state[request_state_id] = handle
        return handle

    def inspect(self, handle: str, *, context: FacadeCallContext) -> dict[str, Any]:
        operation = self._bound(handle, context=context)
        return {
            "operationHandle": operation.handle,
            "actionId": operation.action_id,
            "workspaceId": operation.workspace_id,
            "state": operation.state,
        }

    def pending(self, handle: str, *, context: FacadeCallContext) -> _PendingOperation:
        operation = self._bound(handle, context=context)
        if operation.state != "input_required":
            raise ResourceAccessError("operation_replayed", "Operation handle was already consumed")
        return operation

    def mark_terminal(self, handle: str, state: str) -> None:
        if handle in self._operations:
            self._operations[handle].state = state

    def _bound(self, handle: str, *, context: FacadeCallContext) -> _PendingOperation:
        operation = self._operations.get(handle)
        if operation is None:
            raise ResourceAccessError("operation_handle_invalid", "Operation handle is unknown")
        if not secrets.compare_digest(operation.principal_id, context.principal_id):
            raise ResourceAccessError("operation_principal_mismatch", "Operation principal binding does not match")
        if not secrets.compare_digest(operation.authority_session_id, context.authority_session_id):
            raise ResourceAccessError("operation_authority_mismatch", "Operation authority binding does not match")
        trusted_workspace = workspace.normalize_workspace_id(context.workspace_id)
        if not trusted_workspace or not secrets.compare_digest(operation.workspace_id, trusted_workspace):
            raise ResourceAccessError("operation_workspace_mismatch", "Operation workspace binding does not match")
        return operation


class ActionExecutionService:
    """Shared validated dispatch used by compact and direct projections."""

    def __init__(
        self,
        *,
        registry: ActionRegistry = REGISTRY,
        resources: ResourceReferenceService | None = None,
        operations: OperationHandleService | None = None,
    ) -> None:
        self.registry = registry
        self.resources = resources or ResourceReferenceService()
        self.operations = operations or OperationHandleService()

    def run(
        self,
        *,
        operation: str,
        action_id: str,
        arguments: dict[str, Any],
        context: FacadeCallContext,
        passive_only: bool,
        idempotency_key: str | None = None,
        request_state_id: str = "",
        correlation_id: str = "",
        binding: dict[str, Any] | None = None,
    ) -> FacadeEnvelope:
        trace_id = correlation_id or _trace_id(context)
        try:
            parsed_id = ActionId.parse(action_id)
            descriptor = self.registry.get(parsed_id)
        except (ValueError, LookupError) as exc:
            return _validation_envelope(
                operation,
                context,
                str(exc),
                action_id=action_id,
                reason_code="action_id_invalid",
                trace_id=trace_id,
            )
        properties = descriptor.input_model.contract_document.parsed().get("properties", {})
        declared = frozenset(properties) if isinstance(properties, dict) else frozenset()
        forbidden = _authority_field(arguments, declared_top_level=declared)
        if forbidden:
            return _validation_envelope(
                operation,
                context,
                "Action arguments cannot select authority, grants, principals, profiles, or request state.",
                action_id=action_id,
                reason_code="model_authority_field_forbidden",
                trace_id=trace_id,
                diagnostics={"field": forbidden},
            )
        canonical_arguments = dict(arguments)
        if "confirm" in declared:
            if canonical_arguments.get("confirm") not in {None, False}:
                return _validation_envelope(
                    operation,
                    context,
                    "Legacy confirmation cannot authorize a facade action.",
                    action_id=action_id,
                    reason_code="legacy_confirmation_forbidden",
                    trace_id=trace_id,
                )
            canonical_arguments["confirm"] = False
        argument_workspace = str(canonical_arguments.get("workspaceId") or "")
        if context.workspace_id and argument_workspace:
            if workspace.normalize_workspace_id(context.workspace_id) != workspace.normalize_workspace_id(argument_workspace):
                return FacadeEnvelope(
                    operation=operation,
                    action_id=action_id,
                    outcome_kind="policy_denial",
                    summary="Trusted workspace and action workspace do not match.",
                    diagnostics={"reasonCode": "facade_workspace_mismatch"},
                    trace_id=trace_id,
                )
        try:
            validated_input = descriptor.input_model.model_validate(canonical_arguments)
        except ValidationError as exc:
            return _validation_envelope(
                operation,
                context,
                f"{action_id}: arguments failed canonical input validation.",
                action_id=action_id,
                reason_code="invalid_action_arguments",
                trace_id=trace_id,
                diagnostics=_model_error_diagnostics(exc),
            )
        trusted = binding or {}
        effective_workspace = str(argument_workspace or trusted.get("workspaceId") or context.workspace_id)
        effective_key = str(trusted.get("idempotencyKey") or idempotency_key or f"facade-{uuid4().hex}")
        request = ActionRequest(
            input=validated_input,
            context=ExecutionContext(
                workspace_id=effective_workspace or None,
                correlation_id=str(trusted.get("correlationId") or trace_id),
                deadline_seconds=descriptor.task_policy.deadline_tier.value,
                legacy_approval_asserted=None,
                execution_profile=str(trusted.get("profile") or context.execution_profile),
                authority_session_id=context.authority_session_id,
                selected_grant_id=str(trusted.get("grantId") or context.selected_grant_id),
                idempotency_key=effective_key,
                request_state_id=request_state_id,
            ),
        )
        if passive_only:
            denied = passive_gate_reasons(descriptor.effects)
            if denied:
                return FacadeEnvelope(
                    operation=operation,
                    action_id=action_id,
                    outcome_kind="policy_denial",
                    summary=f"{action_id}: passive execution gate rejected canonical effects.",
                    diagnostics={
                        "reasonCode": "passive_gate_effect_denied",
                        "forbiddenEffects": list(denied),
                        "effects": effect_summary(descriptor.effects).model_dump(mode="json", by_alias=True),
                    },
                    trace_id=trace_id,
                )
        try:
            outcome = self.registry.execute(action_id, request)
        except Exception as exc:
            outcome = ExecutionUnknown(
                message=f"{action_id}: dispatch outcome is uncertain ({type(exc).__name__}).",
                legacy_code=-32000,
                reason_code="facade_dispatch_unknown",
            )
        return self._envelope(
            operation=operation,
            action_id=action_id,
            outcome=outcome,
            arguments=canonical_arguments,
            workspace_id=effective_workspace,
            context=context,
            trace_id=trace_id,
            idempotency_key=effective_key,
            effects=self.registry.resolve_effects(action_id, request),
        )

    def resume(self, handle: str, *, context: FacadeCallContext) -> FacadeEnvelope:
        trace_id = _trace_id(context)
        try:
            operation = self.operations.pending(handle, context=context)
            binding = WorkspaceAuthorityRepository(operation.workspace_id).resume_request_binding(
                operation.request_state_id,
                authority_session_id=operation.authority_session_id,
                action_id=operation.action_id,
            )
        except (ResourceAccessError, AuthorityRepositoryError) as exc:
            return _validation_envelope(
                "tasks.control",
                context,
                str(exc),
                reason_code=getattr(exc, "reason_code", "operation_resume_failed"),
                trace_id=trace_id,
            )
        envelope = self.run(
            operation="tasks.control",
            action_id=operation.action_id,
            arguments=operation.arguments,
            context=context,
            passive_only=False,
            idempotency_key=operation.idempotency_key,
            request_state_id=operation.request_state_id,
            correlation_id=operation.correlation_id,
            binding=binding,
        )
        if envelope.outcome_kind != "approval_required":
            self.operations.mark_terminal(handle, envelope.outcome_kind)
        return envelope

    def _envelope(
        self,
        *,
        operation: str,
        action_id: str,
        outcome: Any,
        arguments: dict[str, Any],
        workspace_id: str,
        context: FacadeCallContext,
        trace_id: str,
        idempotency_key: str,
        effects: ActionEffects,
    ) -> FacadeEnvelope:
        effect_data = effect_summary(effects).model_dump(mode="json", by_alias=True)
        if isinstance(outcome, Success):
            payload = outcome.payload
            if isinstance(payload, BaseModel):
                result: Any = payload.model_dump(mode="json", by_alias=True)
            else:
                result = payload
            safe_result, resource_references = self.resources.sanitize_result(
                result,
                workspace_id=workspace_id,
                context=context,
            )
            return FacadeEnvelope(
                operation=operation,
                action_id=action_id,
                outcome_kind=outcome.kind,
                summary=f"{action_id}: completed.",
                result=safe_result,
                evidence_references=_evidence_references(safe_result),
                resource_references=resource_references,
                diagnostics={
                    "payloadSignalsError": outcome.payload_signals_error,
                    "effects": effect_data,
                },
                trace_id=trace_id,
            )
        if isinstance(outcome, ApprovalRequired):
            details = outcome.details or {}
            request_state_id = str(details.get("requestStateId") or "")
            handle = None
            if request_state_id:
                handle = self.operations.register(
                    request_state_id=request_state_id,
                    action_id=action_id,
                    arguments=arguments,
                    workspace_id=workspace_id,
                    context=context,
                    correlation_id=trace_id,
                    idempotency_key=idempotency_key,
                )
            requirement = details.get("requirement")
            requested = requirement if isinstance(requirement, dict) else {"review": "operator_authority"}
            return FacadeEnvelope(
                operation=operation,
                action_id=action_id,
                outcome_kind=outcome.kind,
                summary=outcome.message,
                requested_input=requested,
                diagnostics={
                    "reasonCode": outcome.reason_code or "approval_required",
                    "legacyCode": outcome.legacy_code,
                    "dispatch": "not_started",
                    "effects": effect_data,
                },
                trace_id=trace_id,
                operation_handle=handle,
            )
        if isinstance(outcome, (ValidationFailure, UnavailableCapability, PolicyDenial, ExecutionFailure, ExecutionUnknown)):
            diagnostics: dict[str, Any] = {
                "reasonCode": outcome.reason_code or outcome.kind,
                "legacyCode": outcome.legacy_code,
                "effects": effect_data,
            }
            return FacadeEnvelope(
                operation=operation,
                action_id=action_id,
                outcome_kind=outcome.kind,
                summary=outcome.message,
                diagnostics=diagnostics,
                trace_id=trace_id,
            )
        return FacadeEnvelope(
            operation=operation,
            action_id=action_id,
            outcome_kind="execution_failure",
            summary=f"{action_id}: Registry returned an unknown outcome.",
            diagnostics={"reasonCode": "facade_outcome_invalid", "effects": effect_data},
            trace_id=trace_id,
        )


class CompactFacadeService:
    """Eleven-operation application facade; transport adapters are separate."""

    def __init__(
        self,
        *,
        registry: ActionRegistry = REGISTRY,
        resources: ResourceReferenceService | None = None,
    ) -> None:
        self.resources = resources or ResourceReferenceService()
        self.catalog = ActionCatalogService(registry)
        self.execution = ActionExecutionService(registry=registry, resources=self.resources)

    def invoke(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        context: FacadeCallContext,
    ) -> FacadeEnvelope:
        input_model = COMPACT_INPUT_MODELS.get(operation)
        if input_model is None:
            return _validation_envelope(
                operation,
                context,
                f"Unknown compact operation: {operation}",
                reason_code="compact_operation_unknown",
            )
        try:
            value = input_model.model_validate(payload)
        except ValidationError as exc:
            return _validation_envelope(
                operation,
                context,
                f"{operation}: input validation failed.",
                diagnostics=_model_error_diagnostics(exc),
            )
        if isinstance(value, EngagementOpenInput):
            return self._run_mapped(operation, "project.start", value, context, passive=False)
        if isinstance(value, EngagementInspectInput):
            return self._run_mapped(operation, "workspace.summary", value, context, passive=True)
        if isinstance(value, ContextQueryInput):
            return self._run_mapped(operation, "workspace.prepare_target_context", value, context, passive=True)
        if isinstance(value, CapabilitiesSearchInput):
            try:
                result = self.catalog.search(value)
            except ValueError as exc:
                return _validation_envelope(operation, context, str(exc), reason_code="catalog_cursor_invalid")
            return self._local_success(operation, context, result)
        if isinstance(value, ActionsDescribeInput):
            try:
                result = self.catalog.describe(value.action_id)
            except LookupError as exc:
                return _validation_envelope(operation, context, str(exc), reason_code="action_id_invalid")
            return self._local_success(operation, context, result, action_id=value.action_id)
        if isinstance(value, ActionExecutionInput):
            return self.execution.run(
                operation=operation,
                action_id=value.action_id,
                arguments=value.arguments,
                context=context,
                passive_only=operation == "actions.run_passive",
                idempotency_key=value.idempotency_key,
            )
        if isinstance(value, ReviewsApplyInput):
            return self.execution.run(
                operation=operation,
                action_id=REVIEW_ACTIONS[value.review],
                arguments=value.arguments,
                context=context,
                passive_only=False,
                idempotency_key=value.idempotency_key,
            )
        if isinstance(value, ArtifactsInspectInput):
            try:
                result = self.resources.resolve(value.resource_ref, context=context)
            except ResourceAccessError as exc:
                return FacadeEnvelope(
                    operation=operation,
                    outcome_kind="policy_denial",
                    summary=str(exc),
                    diagnostics={"reasonCode": exc.reason_code},
                    trace_id=_trace_id(context),
                )
            return self._local_success(operation, context, result)
        if isinstance(value, ReportsRenderInput):
            arguments = value.model_dump(
                mode="json",
                by_alias=True,
                exclude={"idempotency_key"},
                exclude_none=True,
            )
            return self.execution.run(
                operation=operation,
                action_id="documentation.render_workspace_report",
                arguments=arguments,
                context=context,
                passive_only=False,
                idempotency_key=value.idempotency_key,
            )
        if isinstance(value, TasksControlInput):
            return self._tasks(value, context=context)
        return _validation_envelope(operation, context, "Compact input type is not implemented")

    def _run_mapped(
        self,
        operation: str,
        action_id: str,
        value: FacadeModel,
        context: FacadeCallContext,
        *,
        passive: bool,
    ) -> FacadeEnvelope:
        arguments = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        return self.execution.run(
            operation=operation,
            action_id=action_id,
            arguments=arguments,
            context=context,
            passive_only=passive,
        )

    def _tasks(self, value: TasksControlInput, *, context: FacadeCallContext) -> FacadeEnvelope:
        if value.operation == "resume":
            return self.execution.resume(str(value.operation_handle), context=context)
        if value.operation == "inspect" and value.operation_handle:
            try:
                result = self.execution.operations.inspect(value.operation_handle, context=context)
            except ResourceAccessError as exc:
                return _validation_envelope(
                    "tasks.control",
                    context,
                    str(exc),
                    reason_code=exc.reason_code,
                )
            return self._local_success("tasks.control", context, result)
        if value.operation == "list":
            arguments = {
                "limit": value.limit,
                "activeOnly": value.active_only,
                "includeResult": value.include_result,
            }
            if value.workspace_id:
                arguments["workspaceId"] = value.workspace_id
            action_id = "jobs.list"
        elif value.operation == "inspect":
            arguments = {"jobId": value.job_id, "includeResult": value.include_result}
            action_id = "jobs.status"
        else:
            arguments = {"jobId": value.job_id}
            action_id = "jobs.cancel"
        return self.execution.run(
            operation="tasks.control",
            action_id=action_id,
            arguments=arguments,
            context=context,
            passive_only=False,
        )

    @staticmethod
    def _local_success(
        operation: str,
        context: FacadeCallContext,
        result: BaseModel | dict[str, Any],
        *,
        action_id: str | None = None,
    ) -> FacadeEnvelope:
        payload = result.model_dump(mode="json", by_alias=True) if isinstance(result, BaseModel) else result
        return FacadeEnvelope(
            operation=operation,
            action_id=action_id,
            outcome_kind="success",
            summary=f"{operation}: completed.",
            result=payload,
            trace_id=_trace_id(context),
        )
