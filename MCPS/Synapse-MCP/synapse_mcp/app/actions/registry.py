# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registration and policy-routed execution for application actions."""

from __future__ import annotations

from dataclasses import replace
import json
from typing import Any, Protocol

from .contracts import ActionInput, ActionOutput
from .descriptor import ActionDescriptor, ActionRequest
from .identity import ActionId
from .outcomes import ActionOutcome, ExecutionFailure, Success, UnavailableCapability
from .policies import (
    ActionEffects,
    Availability,
    Enforcement,
    Idempotency,
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
    ) -> bool: ...


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
        self._policy_evaluator = policy_evaluator or PassThroughPolicyEvaluator()

    def register(self, descriptor: ActionDescriptor[Any, Any]) -> None:
        action_id = str(descriptor.id)

        def invalid(reason: str) -> None:
            raise ValueError(f"{action_id}: {reason}")

        if action_id in self._descriptors:
            invalid("duplicate action id")
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
        if descriptor.effect_resolver is not None and not callable(descriptor.effect_resolver):
            invalid("effect resolver must be callable")
        if not isinstance(descriptor.availability, Availability) and not callable(descriptor.availability):
            invalid("availability must be a declaration or resolver")
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

    def get(self, action_id: ActionId | str) -> ActionDescriptor[Any, Any]:
        """Return a descriptor by canonical id."""

        try:
            return self._descriptors[str(action_id)]
        except KeyError as exc:
            raise LookupError(f"Unknown action id: {action_id}") from exc

    def descriptors(self) -> tuple[ActionDescriptor[Any, Any], ...]:
        """Return descriptors in registration order."""

        return tuple(self._descriptors.values())

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
        if not self._policy_evaluator.evaluate(descriptor, request, effects):
            raise PermissionError(f"{descriptor.id}: policy evaluator denied execution")
        outcome = descriptor.executor(request)
        if not isinstance(outcome, Success):
            return outcome
        raw_payload = outcome.payload
        parsed_payload = raw_payload
        if isinstance(raw_payload, str):
            try:
                parsed_payload = json.loads(raw_payload)
            except json.JSONDecodeError as exc:
                return ExecutionFailure(
                    message=f"{descriptor.id}: output contract validation failed: invalid JSON",
                    legacy_code=-32000,
                    reason_code="invalid_output_contract",
                )
        try:
            validated = descriptor.output_model.model_validate(parsed_payload)
        except Exception as exc:
            return ExecutionFailure(
                message=f"{descriptor.id}: output contract validation failed: {type(exc).__name__}",
                legacy_code=-32000,
                reason_code="invalid_output_contract",
            )
        compatibility_payload = outcome.legacy_payload if outcome.legacy_payload is not None else raw_payload
        return replace(outcome, payload=validated, legacy_payload=compatibility_payload)


REGISTRY = ActionRegistry()
