# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registration and policy-routed execution for application actions."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Protocol

from synapse_mcp.core.execution import (
    AuthorizationIntent,
    ContinuationLineage,
    ExecutionPlan,
    ExecutionPlanError,
    empty_target_envelope,
)
from synapse_mcp.core.execution_lifecycle import ExecutionObserver, NoOpExecutionObserver

from .contracts import ActionInput, ActionOutput
from .descriptor import ActionDescriptor, ActionRequest
from .identity import ActionId
from .outcomes import (
    ActionOutcome,
    ApprovalRequired,
    ExecutionFailure,
    ExecutionUnknown,
    Success,
    UnavailableCapability,
    ValidationFailure,
)
from .policies import (
    ActionEffects,
    Availability,
    Enforcement,
    Idempotency,
    IdempotencyPolicy,
    RiskClass,
    ScopeRequirement,
    TrafficDestination,
)


class PolicyEvaluator(Protocol):
    """Policy seam invoked before every registered executor."""

    def evaluate(
        self,
        descriptor: ActionDescriptor[Any, Any],
        request: ActionRequest[Any],
        effects: ActionEffects,
    ) -> bool | "PolicyEvaluationResult": ...


@dataclass(frozen=True, slots=True)
class PolicyEvaluationResult:
    """Application-level authorization result consumed by the Registry."""

    allowed: bool
    outcome: ActionOutcome[Any] | None = None
    receipt: object | None = None


class ProfilePolicyEvaluator:
    """Preserve legacy behavior while lazily routing authority-aware profiles."""

    def __init__(self, observer: ExecutionObserver | None = None) -> None:
        self.observer = observer or NoOpExecutionObserver()

    def evaluate(
        self,
        descriptor: ActionDescriptor[Any, Any],
        request: ActionRequest[Any],
        effects: ActionEffects,
    ) -> bool | PolicyEvaluationResult:
        if request.context.execution_profile == "legacy":
            return True
        # Lazy import avoids coupling application descriptor construction to
        # the Phase 2 repository implementation.
        from synapse_mcp.policy.integration import evaluate_registry_request

        return evaluate_registry_request(descriptor, request, effects)

    def before_dispatch(self, receipt: object) -> None:
        from synapse_mcp.policy.integration import mark_registry_dispatched

        mark_registry_dispatched(receipt)

    def after_dispatch(self, receipt: object, outcome: ActionOutcome[Any]) -> None:
        from synapse_mcp.policy.integration import record_registry_outcome

        record_registry_outcome(receipt, outcome, observer=self.observer)

    def dispatch_unknown(self, receipt: object) -> None:
        from synapse_mcp.policy.integration import record_registry_unknown

        # A failing or inconsistent injected observer cannot prevent the
        # canonical dispatch/run pair from becoming conservatively unknown.
        record_registry_unknown(receipt)


class PassThroughPolicyEvaluator:
    """Phase 1 compatibility evaluator that deliberately enforces nothing."""

    def evaluate(
        self,
        descriptor: ActionDescriptor[Any, Any],
        request: ActionRequest[Any],
        effects: ActionEffects,
    ) -> bool:
        del descriptor, request, effects
        return True


def _is_action_model(value: object, base: type[object]) -> bool:
    return isinstance(value, type) and issubclass(value, base)


class ActionRegistry:
    """Fail-fast descriptor registry and the sole supported execution entry."""

    def __init__(self, policy_evaluator: PolicyEvaluator | None = None) -> None:
        self._descriptors: dict[str, ActionDescriptor[Any, Any]] = {}
        self._legacy_aliases: dict[str, str] = {}
        self._policy_evaluator = policy_evaluator or ProfilePolicyEvaluator()
        self._frozen = False

    @property
    def frozen(self) -> bool:
        """Return whether startup assembly has closed mutation."""

        return self._frozen

    def freeze(self) -> "ActionRegistry":
        """Prevent descriptor or ordering mutation after startup assembly."""

        self._frozen = True
        return self

    def register(
        self,
        descriptor: ActionDescriptor[Any, Any],
        *,
        legacy_compatible: bool = True,
    ) -> None:
        action_id = str(descriptor.id)

        def invalid(reason: str) -> None:
            raise ValueError(f"{action_id}: {reason}")

        if self._frozen:
            invalid("registry is frozen")
        if action_id in self._descriptors:
            invalid("duplicate action id")
        if not descriptor.title.strip() or not descriptor.summary.strip():
            invalid("title and summary must be non-empty")
        if not descriptor.implementation_ref.strip():
            invalid("implementation reference must be non-empty")
        if legacy_compatible and not descriptor.legacy_aliases:
            invalid("at least one legacy alias is required")
        if not legacy_compatible and descriptor.legacy_aliases:
            invalid("modern-only actions cannot declare legacy aliases")
        if descriptor.legacy_serializer not in {"transport", "executor"}:
            invalid("legacy serializer must be transport or executor")
        if len(set(descriptor.legacy_aliases)) != len(descriptor.legacy_aliases):
            invalid("legacy aliases must be unique within a descriptor")
        for alias in descriptor.legacy_aliases:
            if not isinstance(alias, str) or not alias.strip():
                invalid("legacy aliases must be non-empty strings")
            owner = self._legacy_aliases.get(alias)
            if owner is not None:
                invalid(f"legacy alias {alias!r} is already owned by {owner}")
        if descriptor.pack != descriptor.id.pack:
            invalid("descriptor pack does not match action id pack")
        if not _is_action_model(descriptor.input_model, ActionInput):
            invalid("input model must be an ActionInput subclass")
        if not _is_action_model(descriptor.output_model, ActionOutput):
            invalid("output model must be an ActionOutput subclass")
        if not callable(descriptor.executor):
            invalid("executor must be callable")
        if getattr(descriptor.executor, "input_model", None) is not descriptor.input_model:
            invalid("executor input model does not match descriptor input model")
        if getattr(descriptor.executor, "output_model", None) is not descriptor.output_model:
            invalid("executor output model does not match descriptor output model")
        if not isinstance(descriptor.effects, ActionEffects):
            invalid("effects must be an ActionEffects instance")
        if not isinstance(descriptor.idempotency_policy, IdempotencyPolicy):
            invalid("idempotency policy must be explicit")
        if not descriptor.effects.permits(
            ActionEffects(replay_safety=descriptor.idempotency_policy.behaviour)
        ):
            invalid("maximum effects do not cover the idempotency policy")
        if descriptor.effect_resolver is not None and not callable(descriptor.effect_resolver):
            invalid("effect resolver must be callable")
        if descriptor.intent_resolver is not None and not callable(descriptor.intent_resolver):
            invalid("intent resolver must be callable")
        if not isinstance(descriptor.availability, Availability) and not callable(descriptor.availability):
            invalid("availability must be a declaration or resolver")
        contract = descriptor.input_model.contract_document.parsed()
        properties = contract.get("properties", {})
        confirm_declared = isinstance(properties, dict) and "confirm" in properties
        if descriptor.approval_required is not confirm_declared:
            invalid("approval requirement must match the frozen confirm contract")
        if descriptor.scope_policy.requirement is ScopeRequirement.REQUIRED and not descriptor.effects.traffic:
            invalid("read-only and report-build actions cannot require scope")
        if TrafficDestination.AUTHORIZED_TARGET in descriptor.effects.traffic:
            if descriptor.risk_class not in {RiskClass.MODERATE, RiskClass.HIGH}:
                invalid("active probes require moderate or high risk")
            if descriptor.scope_policy.requirement is not ScopeRequirement.REQUIRED:
                invalid("active probes require scope")
            if descriptor.effects.replay_safety is not Idempotency.NON_IDEMPOTENT:
                invalid("active probes must be non-idempotent")
        if descriptor.scope_policy.enforcement is Enforcement.ENFORCED_BY_EXECUTOR:
            invalid("scope enforcement by the executor is forbidden in Phase 1")
        if descriptor.credential_policy.enforcement is Enforcement.ENFORCED_BY_EXECUTOR:
            invalid("credential enforcement by the executor is forbidden in Phase 1")

        self._descriptors[action_id] = descriptor
        for alias in descriptor.legacy_aliases:
            self._legacy_aliases[alias] = action_id

    def get(self, action_id: ActionId | str) -> ActionDescriptor[Any, Any]:
        """Return a descriptor by canonical id."""

        try:
            return self._descriptors[str(action_id)]
        except KeyError as exc:
            raise LookupError(f"Unknown action id: {action_id}") from exc

    def descriptors(self) -> tuple[ActionDescriptor[Any, Any], ...]:
        """Return descriptors in registration order."""

        return tuple(self._descriptors.values())

    def action_id_for_legacy_alias(self, alias: str) -> str:
        """Resolve one frozen legacy name to its canonical action id."""

        try:
            return self._legacy_aliases[alias]
        except KeyError as exc:
            raise LookupError(f"Unknown legacy action alias: {alias}") from exc

    def legacy_aliases(self) -> dict[str, str]:
        """Return a copy of the deterministic alias-to-action mapping."""

        return dict(self._legacy_aliases)

    def set_descriptor_order(self, action_ids: tuple[str, ...]) -> None:
        """Apply one complete deterministic order after batch registration."""

        if self._frozen:
            raise ValueError("registry is frozen")
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("descriptor order contains duplicate action ids")
        if set(action_ids) != set(self._descriptors):
            missing = sorted(set(self._descriptors) - set(action_ids))
            orphaned = sorted(set(action_ids) - set(self._descriptors))
            raise ValueError(f"descriptor order is incomplete: missing={missing}, orphaned={orphaned}")
        self._descriptors = {action_id: self._descriptors[action_id] for action_id in action_ids}

    def packs(self) -> frozenset[str]:
        """Return the canonical packs represented by registered actions."""

        return frozenset(descriptor.pack for descriptor in self._descriptors.values())

    def contract_schema(self, action_id: ActionId | str) -> dict[str, Any]:
        """Return canonical schemas validated at the Registry execution boundary."""

        descriptor = self.get(action_id)
        return {
            "actionId": str(descriptor.id),
            "inputSchema": descriptor.input_model.model_json_schema(mode="validation", by_alias=True),
            "outputSchema": descriptor.output_model.model_json_schema(mode="validation", by_alias=True),
        }

    def resolve_effects(
        self,
        action_id: ActionId | str,
        request: ActionRequest[Any],
    ) -> ActionEffects:
        descriptor = self.get(action_id)
        if descriptor.input_model is not type(request.input):
            raise TypeError(
                f"{descriptor.id}: expected input model {descriptor.input_model.__name__}, "
                f"got {type(request.input).__name__}"
            )
        if descriptor.effect_resolver is None:
            return descriptor.effects
        try:
            effective = descriptor.effect_resolver(request)
        except Exception as exc:
            return descriptor.effects.with_resolution_note(
                f"effect resolver failed conservatively: {type(exc).__name__}"
            )
        if not isinstance(effective, ActionEffects):
            return descriptor.effects.with_resolution_note(
                "effect resolver returned an invalid value; maximum effects applied"
            )
        if not descriptor.effects.permits(effective):
            return descriptor.effects.with_resolution_note(
                "effect resolver exceeded the declared maximum; maximum effects applied"
            )
        return effective

    def execute(
        self,
        action_id: ActionId | str,
        request: ActionRequest[Any],
    ) -> ActionOutcome[Any]:
        """Resolve by canonical action id, then authorize, execute, and validate."""

        descriptor = self.get(action_id)
        if descriptor.input_model is not type(request.input):
            raise TypeError(
                f"{descriptor.id}: expected input model {descriptor.input_model.__name__}, "
                f"got {type(request.input).__name__}"
            )
        availability = descriptor.availability(request) if callable(descriptor.availability) else descriptor.availability
        if not availability.available:
            return UnavailableCapability(
                message=str(availability.reason),
                legacy_code=-32001,
                reason_code=availability.reason_code,
            )
        effects = self.resolve_effects(action_id, request)
        try:
            execution_plan = self.resolve_execution_plan(action_id, request, effects=effects)
        except ExecutionPlanError as exc:
            return ValidationFailure(
                message=str(exc),
                legacy_code=-32602,
                reason_code=exc.reason_code,
            )
        planned_request = replace(
            request,
            context=replace(request.context, execution_plan=execution_plan),
        )
        evaluation = self._policy_evaluator.evaluate(descriptor, planned_request, effects)
        if isinstance(evaluation, PolicyEvaluationResult):
            if not evaluation.allowed:
                if evaluation.outcome is None:
                    raise PermissionError(f"{descriptor.id}: policy evaluator denied execution")
                return evaluation.outcome
            planned_request = replace(
                planned_request,
                context=replace(
                    planned_request.context,
                    authorization_receipt=evaluation.receipt,
                    execution_run_id=str(getattr(evaluation.receipt, "execution_run_id", "")),
                ),
            )
            receipt = evaluation.receipt
        else:
            if not evaluation:
                raise PermissionError(f"{descriptor.id}: policy evaluator denied execution")
            receipt = None
        if receipt is not None and hasattr(self._policy_evaluator, "before_dispatch"):
            try:
                self._policy_evaluator.before_dispatch(receipt)
            except Exception as exc:
                return ApprovalRequired(
                    message=f"{descriptor.id}: authority dispatch commit failed closed: {type(exc).__name__}",
                    legacy_code=-32001,
                    reason_code="authority_dispatch_commit_failed",
                    details={"dispatch": "not_started"},
                )
        try:
            outcome = descriptor.executor(planned_request)
        except Exception:
            if receipt is not None and hasattr(self._policy_evaluator, "dispatch_unknown"):
                self._policy_evaluator.dispatch_unknown(receipt)
            raise
        finalized_outcome = outcome
        if isinstance(outcome, Success):
            raw_payload = outcome.payload
            parsed_payload = raw_payload
            validation_problem = ""
            if isinstance(raw_payload, str):
                try:
                    parsed_payload = json.loads(raw_payload)
                except json.JSONDecodeError:
                    validation_problem = "invalid JSON"
            if not validation_problem:
                try:
                    validated = descriptor.output_model.model_validate(parsed_payload)
                except Exception as exc:
                    validation_problem = type(exc).__name__
            if validation_problem:
                if receipt is not None and hasattr(self._policy_evaluator, "dispatch_unknown"):
                    try:
                        self._policy_evaluator.dispatch_unknown(receipt)
                    except Exception:
                        pass
                    return ExecutionUnknown(
                        message=f"{descriptor.id}: execution completed but output contract validation failed: {validation_problem}",
                        legacy_code=-32000,
                        reason_code="invalid_output_contract_unknown",
                    )
                return ExecutionFailure(
                    message=f"{descriptor.id}: output contract validation failed: {validation_problem}",
                    legacy_code=-32000,
                    reason_code="invalid_output_contract",
                )
            compatibility_payload = outcome.legacy_payload if outcome.legacy_payload is not None else raw_payload
            finalized_outcome = replace(outcome, payload=validated, legacy_payload=compatibility_payload)
        if receipt is not None and hasattr(self._policy_evaluator, "after_dispatch"):
            try:
                self._policy_evaluator.after_dispatch(receipt, finalized_outcome)
            except Exception as exc:
                if hasattr(self._policy_evaluator, "dispatch_unknown"):
                    try:
                        self._policy_evaluator.dispatch_unknown(receipt)
                    except Exception:
                        pass
                return ExecutionUnknown(
                    message=f"{descriptor.id}: execution completed but authority result commit is uncertain: {type(exc).__name__}",
                    legacy_code=-32000,
                    reason_code="authority_result_commit_unknown",
                )
        return finalized_outcome

    def resolve_execution_plan(
        self,
        action_id: ActionId | str,
        request: ActionRequest[Any],
        *,
        effects: ActionEffects | None = None,
    ) -> ExecutionPlan:
        """Resolve the immutable intent consumed by policy and the executor."""

        descriptor = self.get(action_id)
        if descriptor.input_model is not type(request.input):
            raise TypeError(
                f"{descriptor.id}: expected input model {descriptor.input_model.__name__}, "
                f"got {type(request.input).__name__}"
            )
        arguments = request.input.model_dump(by_alias=True, exclude_unset=True)
        if descriptor.intent_resolver is None:
            workspace_id = str(request.context.workspace_id or arguments.get("workspaceId") or "")
            intent = AuthorizationIntent(
                action_id=str(descriptor.id),
                workspace_id=workspace_id,
                target_envelope=empty_target_envelope(workspace_id),
                lineage=ContinuationLineage(
                    origin_action_id=str(descriptor.id),
                    origin_correlation_id=request.context.correlation_id,
                ),
            )
        else:
            intent = descriptor.intent_resolver(request)
        if intent.action_id != str(descriptor.id):
            raise ExecutionPlanError(
                "intent_action_mismatch",
                f"{descriptor.id}: intent resolver returned action {intent.action_id}",
            )
        return ExecutionPlan.create(
            action_id=str(descriptor.id),
            correlation_id=request.context.correlation_id,
            intent=intent,
            effects=effects or self.resolve_effects(action_id, request),
            arguments=arguments,
        )


REGISTRY = ActionRegistry()
