# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed application action contracts."""

from .contracts import ActionInput, ActionOutput, InputContractDocument, make_input_model
from .descriptor import ActionDescriptor, ActionExecutor, ActionRequest, ExecutionContext
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
    outcome_from_mcp_error,
)
from .policies import (
    Availability,
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
    TaskPolicy,
)
from .registry import ActionRegistry, PassThroughPolicyEvaluator, PolicyEvaluator, REGISTRY
from . import packs as _packs

__all__ = [
    "ActionDescriptor",
    "ActionExecutor",
    "ActionId",
    "ActionInput",
    "ActionOutcome",
    "ActionOutput",
    "ActionRequest",
    "ActionRegistry",
    "ApprovalRequired",
    "Availability",
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
    "UnavailableCapability",
    "ValidationFailure",
    "make_input_model",
    "outcome_from_mcp_error",
]
