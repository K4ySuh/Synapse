# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed application action contracts."""

from .contracts import ActionInput, ActionOutput, InputContractDocument, make_input_model
from .descriptor import (
    ActionDescriptor,
    ActionEffectResolver,
    ActionExecutor,
    ActionRequest,
    AvailabilityResolver,
    ExecutionContext,
)
from .identity import ActionId
from .outcomes import (
    ActionOutcome,
    ApprovalRequired,
    ExecutionFailure,
    ExecutionUnknown,
    PolicyDenial,
    Success,
    UnavailableCapability,
    ValidationFailure,
    legacy_payload_signals_error,
    outcome_from_mcp_error,
    success_from_legacy_payload,
)
from .policies import (
    Availability,
    ActionEffects,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Enforcement,
    Idempotency,
    IdempotencyPolicy,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    SideEffectClass,
    LocalWriteDomain,
    TrafficDestination,
    TaskPolicy,
)
from .registry import ActionRegistry, PassThroughPolicyEvaluator, PolicyEvaluator, REGISTRY
from . import packs as _packs

__all__ = [
    "ActionDescriptor",
    "ActionEffectResolver",
    "ActionEffects",
    "ActionExecutor",
    "ActionId",
    "ActionInput",
    "ActionOutcome",
    "ActionOutput",
    "ActionRequest",
    "ActionRegistry",
    "ApprovalRequired",
    "Availability",
    "AvailabilityResolver",
    "CredentialAccess",
    "CredentialPolicy",
    "CredentialRequirement",
    "DeadlineTier",
    "Enforcement",
    "ExecutionContext",
    "ExecutionFailure",
    "ExecutionUnknown",
    "Idempotency",
    "IdempotencyPolicy",
    "InputContractDocument",
    "LocalWriteDomain",
    "PolicyDenial",
    "PolicyEvaluator",
    "PassThroughPolicyEvaluator",
    "REGISTRY",
    "RiskClass",
    "ScopePolicy",
    "ScopeRequirement",
    "SideEffectClass",
    "Success",
    "TaskPolicy",
    "TrafficDestination",
    "UnavailableCapability",
    "ValidationFailure",
    "legacy_payload_signals_error",
    "make_input_model",
    "outcome_from_mcp_error",
    "success_from_legacy_payload",
]
