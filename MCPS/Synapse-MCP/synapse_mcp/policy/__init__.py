# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-independent authority policy contracts."""

from .authority import (
    Allow,
    ApprovalRequired,
    AuthorityEvaluation,
    AuthorityGrant,
    AuthorityMode,
    AuthorityReason,
    AuthorityRequirement,
    BudgetDemand,
    BudgetLimits,
    BudgetUsage,
    ContinuationAuthorization,
    PolicyDecision,
    ScopeDenied,
    StateChangePolicy,
    StepUpAuthorization,
    evaluate_authority,
)
from .repository import (
    AuthorizationReceipt,
    AuthorizationResult,
    AuthorityRepository,
    AuthorityRepositoryError,
    AuthorityRevisionConflict,
    DispatchTransitionError,
    WorkspaceAuthorityRepository,
)
from .operator_service import AuthorityOperatorService, OperatorPrincipal

__all__ = [
    "Allow",
    "ApprovalRequired",
    "AuthorityEvaluation",
    "AuthorityGrant",
    "AuthorityMode",
    "AuthorityReason",
    "AuthorityRequirement",
    "BudgetDemand",
    "BudgetLimits",
    "BudgetUsage",
    "ContinuationAuthorization",
    "PolicyDecision",
    "ScopeDenied",
    "StateChangePolicy",
    "StepUpAuthorization",
    "evaluate_authority",
    "AuthorizationReceipt",
    "AuthorizationResult",
    "AuthorityRepository",
    "AuthorityRepositoryError",
    "AuthorityRevisionConflict",
    "DispatchTransitionError",
    "WorkspaceAuthorityRepository",
    "AuthorityOperatorService",
    "OperatorPrincipal",
]
