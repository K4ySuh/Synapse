# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registration and policy-routed execution for application actions."""

from __future__ import annotations

from typing import Any, Protocol

from .contracts import ActionInput, ActionOutput
from .descriptor import ActionDescriptor, ActionRequest
from .identity import ActionId
from .outcomes import ActionOutcome
from .policies import (
    Enforcement,
    Idempotency,
    RiskClass,
    ScopeRequirement,
    SideEffectClass,
)


class PolicyEvaluator(Protocol):
    """Policy seam invoked before every registered executor."""

    def evaluate(
        self,
        descriptor: ActionDescriptor[Any, Any],
        request: ActionRequest[Any],
    ) -> bool: ...


class PassThroughPolicyEvaluator:
    """Phase 1 compatibility evaluator that deliberately enforces nothing."""

    def evaluate(
        self,
        descriptor: ActionDescriptor[Any, Any],
        request: ActionRequest[Any],
    ) -> bool:
        del descriptor, request
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
        if (
            descriptor.scope_policy.requirement is ScopeRequirement.REQUIRED
            and descriptor.side_effect_class
            in {SideEffectClass.READ_ONLY, SideEffectClass.REPORT_BUILD}
        ):
            invalid("read-only and report-build actions cannot require scope")
        if descriptor.side_effect_class is SideEffectClass.ACTIVE_PROBE:
            if descriptor.risk_class not in {RiskClass.MODERATE, RiskClass.HIGH}:
                invalid("active probes require moderate or high risk")
            if descriptor.scope_policy.requirement is not ScopeRequirement.REQUIRED:
                invalid("active probes require scope")
            if descriptor.idempotency_policy.behaviour is not Idempotency.NON_IDEMPOTENT:
                invalid("active probes must be non-idempotent")
        if descriptor.scope_policy.enforcement is Enforcement.ENFORCED_BY_EXECUTOR:
            invalid("scope enforcement by the executor is forbidden in Phase 1")
        if descriptor.credential_policy.enforcement is Enforcement.ENFORCED_BY_EXECUTOR:
            invalid("credential enforcement by the executor is forbidden in Phase 1")

        self._descriptors[action_id] = descriptor

    def get(self, action_id: ActionId | str) -> ActionDescriptor[Any, Any]:
        """Return a descriptor by canonical id."""

        return self._descriptors[str(action_id)]

    def descriptors(self) -> tuple[ActionDescriptor[Any, Any], ...]:
        """Return descriptors in registration order."""

        return tuple(self._descriptors.values())

    def packs(self) -> frozenset[str]:
        """Return the canonical packs represented by registered actions."""

        return frozenset(descriptor.pack for descriptor in self._descriptors.values())

    def execute(self, request: ActionRequest[Any]) -> ActionOutcome[Any]:
        """Resolve the action from its typed input, evaluate policy, and execute."""

        matches = [
            descriptor
            for descriptor in self._descriptors.values()
            if descriptor.input_model is type(request.input)
        ]
        if len(matches) != 1:
            raise LookupError(
                f"Expected one action for input model {type(request.input).__name__}; "
                f"found {len(matches)}"
            )
        descriptor = matches[0]
        if not self._policy_evaluator.evaluate(descriptor, request):
            raise PermissionError(f"{descriptor.id}: policy evaluator denied execution")
        return descriptor.executor(request)


REGISTRY = ActionRegistry()
