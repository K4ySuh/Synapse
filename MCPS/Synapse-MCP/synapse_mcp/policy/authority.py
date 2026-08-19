# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Pure Phase 2 Authority Grant coverage and decision model.

This module has no persistence, dispatch, transport, or secret-resolution
behavior. A later repository/evaluator layer will load trusted state and build
``AuthorityEvaluation``; this module only compares it to the immutable
``ExecutionPlan`` produced by the Action Registry.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, TypeAlias, Union

from synapse_mcp.app.actions.policies import (
    Idempotency,
    LocalWriteDomain,
    RiskClass,
    StrEnum,
    TrafficDestination,
)
from synapse_mcp.core.effects import validate_effect_names, validate_replay_safety
from synapse_mcp.core.execution import (
    CanonicalTarget,
    EffectEnvelope,
    ExecutionPlan,
    LocalOutputDestination,
    ProviderRoute,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
)


_GRANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACTION_SEGMENT = r"[a-z][a-z0-9_]*"
_ACTION_PATTERN = re.compile(rf"^(?:\*|{_ACTION_SEGMENT}(?:\.{_ACTION_SEGMENT})*(?:\.\*)?)$")
_RISK_ORDER = {RiskClass.NONE: 0, RiskClass.LOW: 1, RiskClass.MODERATE: 2, RiskClass.HIGH: 3}


class AuthorityMode(StrEnum):
    OBSERVE = "observe"
    SUPERVISED = "supervised"
    FULL_DELEGATED = "full_delegated"


class StateChangePolicy(StrEnum):
    ALLOW = "allow"
    REQUIRE_STEP_UP = "require_step_up"
    DENY = "deny"


class AuthorityReason(StrEnum):
    COVERED = "covered"
    CONTINUATION_COVERED = "continuation_covered"
    CONTINUATION_NOT_COVERED = "continuation_not_covered"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    GRANT_REQUIRED = "grant_required"
    WORKSPACE_NOT_COVERED = "workspace_not_covered"
    GRANT_NOT_ACTIVE = "grant_not_active"
    GRANT_REVOKED = "grant_revoked"
    GRANT_EXPIRED = "grant_expired"
    SCOPE_CHANGED = "scope_changed"
    ACTION_NOT_COVERED = "action_not_covered"
    TARGET_NOT_COVERED = "target_not_covered"
    REDIRECT_NOT_COVERED = "redirect_not_covered"
    PROVIDER_NOT_COVERED = "provider_not_covered"
    PROVIDER_IDENTITY_REQUIRED = "provider_identity_required"
    OUTPUT_NOT_COVERED = "output_not_covered"
    METHOD_NOT_COVERED = "method_not_covered"
    CREDENTIAL_NOT_COVERED = "credential_not_covered"
    CREDENTIAL_IDENTITY_REQUIRED = "credential_identity_required"
    EFFECT_NOT_COVERED = "effect_not_covered"
    RISK_NOT_COVERED = "risk_not_covered"
    OBSERVE_MODE_RESTRICTED = "observe_mode_restricted"
    STATE_CHANGE_NOT_ALLOWED = "state_change_not_allowed"
    STEP_UP_REQUIRED = "step_up_required"
    DISPATCH_BUDGET_EXHAUSTED = "dispatch_budget_exhausted"
    DISPATCH_RATE_BUDGET_EXHAUSTED = "dispatch_rate_budget_exhausted"
    ACTIVE_DISPATCH_BUDGET_EXHAUSTED = "active_dispatch_budget_exhausted"


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    """Operator-selected dispatch ceilings; ``None`` explicitly means unbounded."""

    dispatch_limit: int | None
    dispatch_rate_limit: int | None
    dispatch_rate_window_seconds: int | None
    active_dispatch_limit: int | None

    def __post_init__(self) -> None:
        for name in ("dispatch_limit", "dispatch_rate_limit", "active_dispatch_limit"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.dispatch_rate_limit is None and self.dispatch_rate_window_seconds is not None:
            raise ValueError("dispatch_rate_window_seconds requires dispatch_rate_limit")
        if self.dispatch_rate_limit is not None and (
            self.dispatch_rate_window_seconds is None or self.dispatch_rate_window_seconds <= 0
        ):
            raise ValueError("A positive dispatch_rate_window_seconds is required with dispatch_rate_limit")

    def to_dict(self) -> dict[str, int | None]:
        return {
            "dispatchLimit": self.dispatch_limit,
            "dispatchRateLimit": self.dispatch_rate_limit,
            "dispatchRateWindowSeconds": self.dispatch_rate_window_seconds,
            "activeDispatchLimit": self.active_dispatch_limit,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetLimits":
        return cls(
            _optional_int(value["dispatchLimit"]),
            _optional_int(value["dispatchRateLimit"]),
            _optional_int(value["dispatchRateWindowSeconds"]),
            _optional_int(value["activeDispatchLimit"]),
        )


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    dispatches_used: int = 0
    dispatch_window_used: int = 0
    active_dispatches: int = 0

    def __post_init__(self) -> None:
        if min(self.dispatches_used, self.dispatch_window_used, self.active_dispatches) < 0:
            raise ValueError("Budget usage cannot be negative")

    def to_dict(self) -> dict[str, int]:
        return {
            "dispatchesUsed": self.dispatches_used,
            "dispatchWindowUsed": self.dispatch_window_used,
            "activeDispatches": self.active_dispatches,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetUsage":
        return cls(
            int(value["dispatchesUsed"]),
            int(value["dispatchWindowUsed"]),
            int(value["activeDispatches"]),
        )


@dataclass(frozen=True, slots=True)
class BudgetDemand:
    dispatch_units: int = 1
    dispatch_rate_units: int = 1
    active_dispatch_units: int = 1

    def __post_init__(self) -> None:
        if min(self.dispatch_units, self.dispatch_rate_units, self.active_dispatch_units) < 0:
            raise ValueError("Budget demand cannot be negative")

    @classmethod
    def for_plan(cls, plan: ExecutionPlan) -> "BudgetDemand":
        # Polling/finalization continues an already-dispatched action and does
        # not consume a second dispatch or approval budget.
        if plan.intent.lineage.kind == "job_status":
            return cls(0, 0, 0)
        return cls()

    def to_dict(self) -> dict[str, int]:
        return {
            "dispatchUnits": self.dispatch_units,
            "dispatchRateUnits": self.dispatch_rate_units,
            "activeDispatchUnits": self.active_dispatch_units,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetDemand":
        return cls(
            int(value["dispatchUnits"]),
            int(value["dispatchRateUnits"]),
            int(value["activeDispatchUnits"]),
        )


@dataclass(frozen=True, slots=True)
class StepUpAuthorization:
    grant_id: str
    grant_revision: int
    authorization_fingerprint: str
    idempotency_key: str
    approved_by: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if not _GRANT_ID.fullmatch(self.grant_id):
            raise ValueError("Invalid step-up grant_id")
        if self.grant_revision < 1:
            raise ValueError("Step-up grant_revision must be positive")
        if not self.authorization_fingerprint or not self.idempotency_key or not self.approved_by:
            raise ValueError("Step-up fingerprint, idempotency key, and approver are required")
        _require_aware(self.expires_at, "expires_at")

    def covers(self, grant: "AuthorityGrant", plan: ExecutionPlan, idempotency_key: str, now: datetime) -> bool:
        return (
            self.grant_id == grant.grant_id
            and self.grant_revision == grant.revision
            and self.authorization_fingerprint == plan.authorization_fingerprint
            and bool(idempotency_key)
            and self.idempotency_key == idempotency_key
            and now < self.expires_at
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "grantId": self.grant_id,
            "grantRevision": self.grant_revision,
            "authorizationFingerprint": self.authorization_fingerprint,
            "idempotencyKey": self.idempotency_key,
            "approvedBy": self.approved_by,
            "expiresAt": _format_time(self.expires_at),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StepUpAuthorization":
        return cls(
            grant_id=str(value["grantId"]),
            grant_revision=int(value["grantRevision"]),
            authorization_fingerprint=str(
                value.get("authorizationFingerprint") or value.get("planFingerprint") or ""
            ),
            idempotency_key=str(value["idempotencyKey"]),
            approved_by=str(value["approvedBy"]),
            expires_at=_parse_time(value["expiresAt"]),
        )


@dataclass(frozen=True, slots=True)
class ContinuationAuthorization:
    """Trusted server proof that a job crossed an authorized dispatch boundary."""

    dispatch_id: str
    origin_action_id: str
    workspace_id: str
    grant_id: str
    grant_revision: int
    dispatch_plan_fingerprint: str
    parent_plan_fingerprint: str
    job_id: str
    job_revision: int
    handler: str
    binding_fingerprint: str
    effects: EffectEnvelope
    local_outputs: tuple[LocalOutputDestination, ...]
    lifecycle_state: str

    def __post_init__(self) -> None:
        required = {
            "dispatch_id": self.dispatch_id,
            "origin_action_id": self.origin_action_id,
            "workspace_id": self.workspace_id,
            "grant_id": self.grant_id,
            "dispatch_plan_fingerprint": self.dispatch_plan_fingerprint,
            "parent_plan_fingerprint": self.parent_plan_fingerprint,
            "job_id": self.job_id,
            "handler": self.handler,
            "binding_fingerprint": self.binding_fingerprint,
        }
        missing = sorted(name for name, value in required.items() if not str(value).strip())
        if missing:
            raise ValueError(f"Continuation authorization is missing: {', '.join(missing)}")
        if self.grant_revision < 1 or self.job_revision < 1:
            raise ValueError("Continuation grant and job revisions must be positive")
        if self.lifecycle_state not in {
            "authorized",
            "dispatched",
            "running",
            "succeeded",
            "failed",
            "unknown",
        }:
            raise ValueError(f"Unknown continuation lifecycle state: {self.lifecycle_state}")
        if self.lifecycle_state == "authorized":
            raise ValueError("An authorized-only dispatch has not crossed the continuation boundary")
        if not isinstance(self.effects, EffectEnvelope):
            raise TypeError("Continuation effects must be an EffectEnvelope")
        if any(not isinstance(item, LocalOutputDestination) for item in self.local_outputs):
            raise TypeError("Continuation outputs must be LocalOutputDestination values")

    def covers(self, plan: ExecutionPlan) -> bool:
        lineage = plan.intent.lineage
        return bool(
            lineage.kind == "job_status"
            and plan.action_id == "jobs.status"
            and plan.intent.workspace_id == self.workspace_id
            and lineage.origin_action_id == self.origin_action_id
            and lineage.parent_plan_fingerprint == self.parent_plan_fingerprint
            and lineage.job_id == self.job_id
            and lineage.handler == self.handler
            and lineage.binding_fingerprint == self.binding_fingerprint
            and plan.effects == self.effects
            and plan.intent.local_outputs == self.local_outputs
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispatchId": self.dispatch_id,
            "originActionId": self.origin_action_id,
            "workspaceId": self.workspace_id,
            "grantId": self.grant_id,
            "grantRevision": self.grant_revision,
            "dispatchPlanFingerprint": self.dispatch_plan_fingerprint,
            "parentPlanFingerprint": self.parent_plan_fingerprint,
            "jobId": self.job_id,
            "jobRevision": self.job_revision,
            "handler": self.handler,
            "bindingFingerprint": self.binding_fingerprint,
            "effects": self.effects.to_dict(),
            "localOutputs": [item.to_dict() for item in self.local_outputs],
            "lifecycleState": self.lifecycle_state,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ContinuationAuthorization":
        return cls(
            dispatch_id=str(value["dispatchId"]),
            origin_action_id=str(value["originActionId"]),
            workspace_id=str(value["workspaceId"]),
            grant_id=str(value["grantId"]),
            grant_revision=int(value["grantRevision"]),
            dispatch_plan_fingerprint=str(value["dispatchPlanFingerprint"]),
            parent_plan_fingerprint=str(value["parentPlanFingerprint"]),
            job_id=str(value["jobId"]),
            job_revision=int(value["jobRevision"]),
            handler=str(value["handler"]),
            binding_fingerprint=str(value["bindingFingerprint"]),
            effects=EffectEnvelope.from_dict(value["effects"]),
            local_outputs=tuple(LocalOutputDestination.from_dict(item) for item in value.get("localOutputs", [])),
            lifecycle_state=str(value["lifecycleState"]),
        )


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    grant_id: str
    workspace_id: str
    revision: int
    mode: AuthorityMode
    scope_digest: str
    target_envelope: TargetEnvelope
    allowed_action_patterns: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_effects: EffectEnvelope
    risk_ceiling: RiskClass
    credential_refs: tuple[str, ...]
    provider_routes: tuple[ProviderRoute, ...]
    third_party_providers: tuple[str, ...]
    local_outputs: tuple[LocalOutputDestination, ...]
    budgets: BudgetLimits
    state_change_policy: StateChangePolicy
    created_at: datetime
    expires_at: datetime
    approved_by: str
    revoked_at: datetime | None = None
    observation_write_domains: frozenset[LocalWriteDomain] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", AuthorityMode(str(self.mode)))
        object.__setattr__(self, "risk_ceiling", RiskClass(str(self.risk_ceiling)))
        object.__setattr__(self, "state_change_policy", StateChangePolicy(str(self.state_change_policy)))
        if not isinstance(self.target_envelope, TargetEnvelope):
            raise TypeError("Grant target_envelope must be a TargetEnvelope")
        if not isinstance(self.allowed_effects, EffectEnvelope):
            raise TypeError("Grant allowed_effects must be an EffectEnvelope")
        if not isinstance(self.budgets, BudgetLimits):
            raise TypeError("Grant budgets must be BudgetLimits")
        if any(not isinstance(item, ProviderRoute) for item in self.provider_routes):
            raise TypeError("Grant provider_routes must contain ProviderRoute values")
        if any(not isinstance(item, LocalOutputDestination) for item in self.local_outputs):
            raise TypeError("Grant local_outputs must contain LocalOutputDestination values")
        object.__setattr__(self, "provider_routes", tuple(self.provider_routes))
        object.__setattr__(self, "local_outputs", tuple(self.local_outputs))
        if not _GRANT_ID.fullmatch(self.grant_id):
            raise ValueError("grant_id must be a safe opaque identifier")
        if not self.workspace_id or self.target_envelope.workspace_id != self.workspace_id:
            raise ValueError("Grant workspace and target envelope workspace must match")
        if self.revision < 1:
            raise ValueError("Grant revision must be positive")
        if self.scope_digest != self.target_envelope.scope_digest:
            raise ValueError("Grant scope digest and target envelope digest must match")
        if self.scope_digest != self.target_envelope.scope_snapshot.digest:
            raise ValueError("Grant target envelope snapshot must match its scope digest")
        if any(item.path_mode not in {"exact", "prefix", "any"} for item in self.target_envelope.exact_targets):
            raise ValueError("Grant target selectors must use exact, prefix, or any matching")
        selected_targets = tuple(item.target for item in self.target_envelope.exact_targets)
        if any(not _valid_canonical_target(item) for item in (*selected_targets, *self.target_envelope.seeds)):
            raise ValueError("Grant targets and seeds must be canonical HTTP targets")
        if any(
            not self.target_envelope.scope_snapshot.contains(item)
            for item in (*selected_targets, *self.target_envelope.seeds)
        ):
            raise ValueError("Grant targets and seeds must belong to its frozen scope")
        if self.target_envelope.redirect_policy.max_hops < 0:
            raise ValueError("Grant redirect hop limit cannot be negative")
        if not self.allowed_action_patterns:
            raise ValueError("At least one allowed action pattern is required")
        if any(not _ACTION_PATTERN.fullmatch(item) for item in self.allowed_action_patterns):
            raise ValueError("Action patterns support exact IDs, a trailing .* prefix, or *")
        object.__setattr__(self, "allowed_action_patterns", tuple(sorted(set(self.allowed_action_patterns))))
        normalized_methods = tuple(
            sorted({str(item).strip().upper() for item in self.allowed_methods if str(item).strip()})
        )
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,31}", item) for item in normalized_methods):
            raise ValueError("Grant methods must be normalized HTTP method tokens")
        object.__setattr__(self, "allowed_methods", normalized_methods)
        object.__setattr__(self, "credential_refs", _normalized_unique(self.credential_refs))
        object.__setattr__(self, "third_party_providers", _normalized_unique(self.third_party_providers))
        if any(route.embedded_credentials or route.trust_environment for route in self.provider_routes):
            raise ValueError("Grant provider routes cannot embed credentials or trust environment configuration")
        if any(not _valid_provider_route(route) for route in self.provider_routes):
            raise ValueError("Grant provider routes must be canonical direct, disabled, or proxy routes")
        if any(not Path(item.path).is_absolute() for item in self.local_outputs):
            raise ValueError("Grant local output paths must be absolute")
        if any(item.disposition not in {"create", "overwrite"} for item in self.local_outputs):
            raise ValueError("Grant local output disposition must be create or overwrite")
        if not self.approved_by:
            raise ValueError("approved_by is required")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at < self.created_at:
                raise ValueError("revoked_at cannot precede created_at")
        validate_effect_names(
            traffic=self.allowed_effects.traffic,
            local_writes=self.allowed_effects.local_writes,
        )
        effect_domains = frozenset(LocalWriteDomain(item) for item in self.allowed_effects.local_writes)
        validate_replay_safety(self.allowed_effects.replay_safety)
        observation_domains = frozenset(LocalWriteDomain(item) for item in self.observation_write_domains)
        object.__setattr__(self, "observation_write_domains", observation_domains)
        if not observation_domains.issubset(effect_domains):
            raise ValueError("Observation write domains must be covered by allowed_effects")

    def to_dict(self) -> dict[str, Any]:
        return {
            "grantId": self.grant_id,
            "workspaceId": self.workspace_id,
            "revision": self.revision,
            "mode": str(self.mode),
            "scopeDigest": self.scope_digest,
            "targetEnvelope": self.target_envelope.to_dict(),
            "allowedActionPatterns": list(self.allowed_action_patterns),
            "allowedMethods": list(self.allowed_methods),
            "allowedEffects": self.allowed_effects.to_dict(),
            "riskCeiling": str(self.risk_ceiling),
            "credentialRefs": list(self.credential_refs),
            "providerRoutes": [item.to_dict() for item in self.provider_routes],
            "thirdPartyProviders": list(self.third_party_providers),
            "localOutputs": [item.to_dict() for item in self.local_outputs],
            "budgetSemantics": "dispatch",
            "dispatchBudget": {"limit": self.budgets.dispatch_limit},
            "dispatchRateBudget": {
                "limit": self.budgets.dispatch_rate_limit,
                "windowSeconds": self.budgets.dispatch_rate_window_seconds,
            },
            "activeDispatchBudget": {"limit": self.budgets.active_dispatch_limit},
            "stateChangePolicy": str(self.state_change_policy),
            "createdAt": _format_time(self.created_at),
            "expiresAt": _format_time(self.expires_at),
            "approvedBy": self.approved_by,
            "revokedAt": _format_time(self.revoked_at) if self.revoked_at else None,
            "observationWriteDomains": sorted(str(item) for item in self.observation_write_domains),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorityGrant":
        required_fields = {
            "grantId",
            "workspaceId",
            "revision",
            "mode",
            "scopeDigest",
            "targetEnvelope",
            "allowedActionPatterns",
            "allowedMethods",
            "allowedEffects",
            "riskCeiling",
            "credentialRefs",
            "providerRoutes",
            "thirdPartyProviders",
            "localOutputs",
            "budgetSemantics",
            "dispatchBudget",
            "dispatchRateBudget",
            "activeDispatchBudget",
            "stateChangePolicy",
            "createdAt",
            "expiresAt",
            "approvedBy",
            "revokedAt",
            "observationWriteDomains",
        }
        missing_fields = sorted(required_fields.difference(value))
        if missing_fields:
            raise ValueError(f"Authority Grant is missing required fields: {', '.join(missing_fields)}")
        if value.get("budgetSemantics") != "dispatch":
            raise ValueError("Authority Grant budgetSemantics must be dispatch")
        dispatch_budget = value.get("dispatchBudget", {})
        dispatch_rate_budget = value.get("dispatchRateBudget", {})
        active_dispatch_budget = value.get("activeDispatchBudget", {})
        if not isinstance(dispatch_budget, Mapping) or "limit" not in dispatch_budget:
            raise ValueError("Authority Grant dispatchBudget.limit is required")
        if not isinstance(dispatch_rate_budget, Mapping) or not {"limit", "windowSeconds"}.issubset(dispatch_rate_budget):
            raise ValueError("Authority Grant dispatchRateBudget limit and windowSeconds are required")
        if not isinstance(active_dispatch_budget, Mapping) or "limit" not in active_dispatch_budget:
            raise ValueError("Authority Grant activeDispatchBudget.limit is required")
        return cls(
            grant_id=str(value["grantId"]),
            workspace_id=str(value["workspaceId"]),
            revision=int(value["revision"]),
            mode=AuthorityMode(str(value["mode"])),
            scope_digest=str(value["scopeDigest"]),
            target_envelope=TargetEnvelope.from_dict(value["targetEnvelope"]),
            allowed_action_patterns=tuple(str(item) for item in value.get("allowedActionPatterns", [])),
            allowed_methods=tuple(str(item) for item in value.get("allowedMethods", [])),
            allowed_effects=EffectEnvelope.from_dict(value.get("allowedEffects", {})),
            risk_ceiling=RiskClass(str(value["riskCeiling"])),
            credential_refs=tuple(str(item) for item in value.get("credentialRefs", [])),
            provider_routes=tuple(ProviderRoute.from_dict(item) for item in value.get("providerRoutes", [])),
            third_party_providers=tuple(str(item) for item in value.get("thirdPartyProviders", [])),
            local_outputs=tuple(LocalOutputDestination.from_dict(item) for item in value.get("localOutputs", [])),
            budgets=BudgetLimits(
                _optional_int(dispatch_budget["limit"]),
                _optional_int(dispatch_rate_budget["limit"]),
                _optional_int(dispatch_rate_budget["windowSeconds"]),
                _optional_int(active_dispatch_budget["limit"]),
            ),
            state_change_policy=StateChangePolicy(str(value["stateChangePolicy"])),
            created_at=_parse_time(value["createdAt"]),
            expires_at=_parse_time(value["expiresAt"]),
            approved_by=str(value["approvedBy"]),
            revoked_at=_parse_time(value["revokedAt"]) if value.get("revokedAt") else None,
            observation_write_domains=frozenset(
                LocalWriteDomain(str(item)) for item in value.get("observationWriteDomains", [])
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorityEvaluation:
    plan: ExecutionPlan
    risk_class: RiskClass
    current_scope: ScopeSnapshot
    now: datetime
    budget_usage: BudgetUsage = BudgetUsage()
    budget_demand: BudgetDemand | None = None
    third_party_provider_ids: tuple[str, ...] = ()
    idempotency_key: str = ""
    step_up: StepUpAuthorization | None = None
    continuation: ContinuationAuthorization | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "risk_class", RiskClass(str(self.risk_class)))
        self.plan.verify()
        _require_aware(self.now, "now")
        object.__setattr__(self, "third_party_provider_ids", _normalized_unique(self.third_party_provider_ids))

    @property
    def demand(self) -> BudgetDemand:
        return self.budget_demand or BudgetDemand.for_plan(self.plan)


@dataclass(frozen=True, slots=True)
class AuthorityRequirement:
    dimension: str
    requested: tuple[str, ...] = ()
    granted: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "requested": list(self.requested),
            "granted": list(self.granted),
        }


@dataclass(frozen=True, slots=True)
class Allow:
    grant_id: str
    grant_revision: int
    plan_fingerprint: str
    budget_demand: BudgetDemand
    reason: AuthorityReason = AuthorityReason.COVERED
    kind: str = field(init=False, default="allow")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": str(self.reason),
            "grantId": self.grant_id,
            "grantRevision": self.grant_revision,
            "planFingerprint": self.plan_fingerprint,
            "budgetDemand": self.budget_demand.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ApprovalRequired:
    reason: AuthorityReason
    message: str
    plan_fingerprint: str
    grant_id: str = ""
    requirement: AuthorityRequirement | None = None
    request_state_id: str = ""
    kind: str = field(init=False, default="approval_required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": str(self.reason),
            "message": self.message,
            "planFingerprint": self.plan_fingerprint,
            "grantId": self.grant_id,
            "requestStateId": self.request_state_id,
            "requirement": _requirement_dict(self.requirement),
        }


@dataclass(frozen=True, slots=True)
class ScopeDenied:
    reason: AuthorityReason
    message: str
    plan_fingerprint: str
    requirement: AuthorityRequirement | None = None
    kind: str = field(init=False, default="scope_denied")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": str(self.reason),
            "message": self.message,
            "planFingerprint": self.plan_fingerprint,
            "requirement": _requirement_dict(self.requirement),
        }


PolicyDecision: TypeAlias = Union[Allow, ApprovalRequired, ScopeDenied]


def evaluate_authority(grant: AuthorityGrant | None, evaluation: AuthorityEvaluation) -> PolicyDecision:
    """Return a pure policy decision without reading or mutating external state."""

    plan = evaluation.plan
    intent = plan.intent
    if intent.lineage.kind == "job_status":
        continuation = evaluation.continuation
        if continuation is None or not continuation.covers(plan):
            return _approval(
                AuthorityReason.CONTINUATION_NOT_COVERED,
                "Job polling requires a matching durable dispatch continuation.",
                plan,
                grant,
            )
        return Allow(
            continuation.grant_id,
            continuation.grant_revision,
            plan.plan_fingerprint,
            BudgetDemand(0, 0, 0),
            AuthorityReason.CONTINUATION_COVERED,
        )
    scope_decision = _current_scope_decision(evaluation)
    if scope_decision is not None:
        return scope_decision
    if grant is None:
        return _approval(AuthorityReason.GRANT_REQUIRED, "No Authority Grant is bound to this request.", plan)
    if grant.workspace_id != intent.workspace_id:
        return _approval(
            AuthorityReason.WORKSPACE_NOT_COVERED,
            "The grant does not cover the execution workspace.",
            plan,
            grant,
            AuthorityRequirement("workspace", (intent.workspace_id,), (grant.workspace_id,)),
        )
    if evaluation.now < grant.created_at:
        return _approval(AuthorityReason.GRANT_NOT_ACTIVE, "The grant is not active yet.", plan, grant)
    if grant.revoked_at is not None and evaluation.now >= grant.revoked_at:
        return _approval(AuthorityReason.GRANT_REVOKED, "The grant has been revoked.", plan, grant)
    if evaluation.now >= grant.expires_at:
        return _approval(AuthorityReason.GRANT_EXPIRED, "The grant has expired.", plan, grant)
    if (
        intent.target_envelope.scope_digest != evaluation.current_scope.digest
        or grant.scope_digest != evaluation.current_scope.digest
    ):
        return _approval(
            AuthorityReason.SCOPE_CHANGED,
            "Current workspace scope differs from the scope covered by the grant.",
            plan,
            grant,
            AuthorityRequirement(
                "scope_digest",
                (intent.target_envelope.scope_digest, evaluation.current_scope.digest),
                (grant.scope_digest,),
            ),
        )
    if not any(_action_pattern_matches(pattern, plan.action_id) for pattern in grant.allowed_action_patterns):
        return _approval(
            AuthorityReason.ACTION_NOT_COVERED,
            "The grant does not cover this action.",
            plan,
            grant,
            AuthorityRequirement("action", (plan.action_id,), grant.allowed_action_patterns),
        )
    if "authorized_target" in plan.effects.traffic and not (
        intent.target_envelope.exact_targets or intent.target_envelope.entire_workspace_scope
    ):
        return _approval(
            AuthorityReason.TARGET_NOT_COVERED,
            "Authorized-target traffic has no canonical target selection in the execution intent.",
            plan,
            grant,
            AuthorityRequirement("target_identity"),
        )
    target_gap = _target_coverage_gap(grant.target_envelope, intent.target_envelope)
    if target_gap is not None:
        return _approval(
            AuthorityReason.TARGET_NOT_COVERED,
            "The grant does not cover the requested target selection.",
            plan,
            grant,
            target_gap,
        )
    redirect_gap = _redirect_coverage_gap(grant.target_envelope, intent.target_envelope)
    if redirect_gap is not None:
        return _approval(
            AuthorityReason.REDIRECT_NOT_COVERED,
            "The grant does not cover the redirect policy.",
            plan,
            grant,
            redirect_gap,
        )
    provider_gap = _provider_coverage_gap(grant, evaluation)
    if provider_gap is not None:
        reason = (
            AuthorityReason.PROVIDER_IDENTITY_REQUIRED
            if provider_gap.dimension == "provider_identity"
            else AuthorityReason.PROVIDER_NOT_COVERED
        )
        return _approval(
            reason,
            "The grant does not cover the requested provider infrastructure.",
            plan,
            grant,
            provider_gap,
        )
    output_gap = _output_coverage_gap(grant.local_outputs, intent.local_outputs)
    if output_gap is not None:
        return _approval(
            AuthorityReason.OUTPUT_NOT_COVERED,
            "The grant does not cover an exact local output.",
            plan,
            grant,
            output_gap,
        )
    requested_methods = tuple(sorted(set(intent.methods)))
    missing_methods = tuple(item for item in requested_methods if item not in grant.allowed_methods)
    if missing_methods:
        return _approval(
            AuthorityReason.METHOD_NOT_COVERED,
            "The grant does not cover every requested method.",
            plan,
            grant,
            AuthorityRequirement("methods", missing_methods, grant.allowed_methods),
        )
    if (plan.effects.credential_use or plan.effects.secret_use) and not intent.credential_refs:
        return _approval(
            AuthorityReason.CREDENTIAL_IDENTITY_REQUIRED,
            "Credential use is declared but no credential reference is present in the execution intent.",
            plan,
            grant,
            AuthorityRequirement("credential_identity"),
        )
    missing_credentials = tuple(item for item in intent.credential_refs if item not in grant.credential_refs)
    if missing_credentials:
        return _approval(
            AuthorityReason.CREDENTIAL_NOT_COVERED,
            "The grant does not cover every credential reference.",
            plan,
            grant,
            AuthorityRequirement("credential_refs", missing_credentials, grant.credential_refs),
        )
    if not grant.allowed_effects.permits(plan.effects):
        return _approval(
            AuthorityReason.EFFECT_NOT_COVERED,
            "The grant effect envelope is narrower than the execution effects.",
            plan,
            grant,
            AuthorityRequirement(
                "effects",
                (_effect_summary(plan.effects),),
                (_effect_summary(grant.allowed_effects),),
            ),
        )
    if _RISK_ORDER[evaluation.risk_class] > _RISK_ORDER[grant.risk_ceiling]:
        return _approval(
            AuthorityReason.RISK_NOT_COVERED,
            "The action risk exceeds the grant ceiling.",
            plan,
            grant,
            AuthorityRequirement("risk", (str(evaluation.risk_class),), (str(grant.risk_ceiling),)),
        )
    if grant.mode is AuthorityMode.OBSERVE and not _observe_mode_covers(grant, plan.effects):
        return _approval(
            AuthorityReason.OBSERVE_MODE_RESTRICTED,
            "Observe mode does not cover this operational effect set.",
            plan,
            grant,
        )
    sensitive = _requires_step_up(evaluation.risk_class, plan.effects)
    if sensitive and grant.state_change_policy is StateChangePolicy.DENY:
        return _approval(
            AuthorityReason.STATE_CHANGE_NOT_ALLOWED,
            "The grant does not allow this state-changing or sensitive execution.",
            plan,
            grant,
        )
    step_up_required = sensitive and (
        grant.mode is AuthorityMode.SUPERVISED or grant.state_change_policy is StateChangePolicy.REQUIRE_STEP_UP
    )
    if step_up_required and not _step_up_covers(grant, evaluation):
        return _approval(
            AuthorityReason.STEP_UP_REQUIRED,
            "An exact, unexpired step-up authorization is required.",
            plan,
            grant,
            AuthorityRequirement("step_up", (plan.authorization_fingerprint, evaluation.idempotency_key), ()),
        )
    budget_decision = _budget_decision(grant, evaluation)
    if budget_decision is not None:
        return budget_decision
    return Allow(grant.grant_id, grant.revision, plan.plan_fingerprint, evaluation.demand)


def _current_scope_decision(evaluation: AuthorityEvaluation) -> ScopeDenied | None:
    envelope = evaluation.plan.intent.target_envelope
    for selector in envelope.exact_targets:
        if not evaluation.current_scope.contains(selector.target):
            return ScopeDenied(
                AuthorityReason.TARGET_OUT_OF_SCOPE,
                "An exact execution target is outside current workspace scope.",
                evaluation.plan.plan_fingerprint,
                AuthorityRequirement("target", (_target_text(selector.target),), ()),
            )
    for seed in envelope.seeds:
        if not evaluation.current_scope.contains(seed):
            return ScopeDenied(
                AuthorityReason.TARGET_OUT_OF_SCOPE,
                "An execution seed is outside current workspace scope.",
                evaluation.plan.plan_fingerprint,
                AuthorityRequirement("seed", (_target_text(seed),), ()),
            )
    return None


def _target_coverage_gap(granted: TargetEnvelope, requested: TargetEnvelope) -> AuthorityRequirement | None:
    if requested.entire_workspace_scope and not granted.entire_workspace_scope:
        return AuthorityRequirement("entire_workspace_scope", ("true",), ("false",))
    for selector in requested.exact_targets:
        if not _target_selector_covered(granted, selector):
            return AuthorityRequirement(
                "exact_target",
                (_selector_text(selector),),
                tuple(_selector_text(item) for item in granted.exact_targets),
            )
    for seed in requested.seeds:
        if not _canonical_target_covered(granted, seed):
            return AuthorityRequirement(
                "seed",
                (_target_text(seed),),
                tuple(_selector_text(item) for item in granted.exact_targets),
            )
    return None


def _redirect_coverage_gap(granted: TargetEnvelope, requested: TargetEnvelope) -> AuthorityRequirement | None:
    requested_policy = requested.redirect_policy
    granted_policy = granted.redirect_policy
    if requested_policy.follow and not granted_policy.follow:
        return AuthorityRequirement("redirect_follow", ("true",), ("false",))
    if requested_policy.follow and requested_policy.max_hops > granted_policy.max_hops:
        return AuthorityRequirement(
            "redirect_hops",
            (str(requested_policy.max_hops),),
            (str(granted_policy.max_hops),),
        )
    return None


def _provider_coverage_gap(grant: AuthorityGrant, evaluation: AuthorityEvaluation) -> AuthorityRequirement | None:
    for requested in evaluation.plan.intent.providers:
        if not any(_provider_route_covers(item, requested) for item in grant.provider_routes):
            return AuthorityRequirement(
                "provider_route",
                (_provider_text(requested),),
                tuple(_provider_text(item) for item in grant.provider_routes),
            )
    if "third_party" in evaluation.plan.effects.traffic and not evaluation.third_party_provider_ids:
        return AuthorityRequirement("provider_identity")
    missing = tuple(item for item in evaluation.third_party_provider_ids if item not in grant.third_party_providers)
    if missing:
        return AuthorityRequirement("provider_ids", missing, grant.third_party_providers)
    return None


def _output_coverage_gap(
    granted: tuple[LocalOutputDestination, ...],
    requested: tuple[LocalOutputDestination, ...],
) -> AuthorityRequirement | None:
    for output in requested:
        if not any(_output_covers(candidate, output) for candidate in granted):
            return AuthorityRequirement(
                "local_output",
                (_output_text(output),),
                tuple(_output_text(item) for item in granted),
            )
    return None


def _budget_decision(grant: AuthorityGrant, evaluation: AuthorityEvaluation) -> ApprovalRequired | None:
    limits = grant.budgets
    usage = evaluation.budget_usage
    demand = evaluation.demand
    if (
        demand.dispatch_units
        and limits.dispatch_limit is not None
        and usage.dispatches_used + demand.dispatch_units > limits.dispatch_limit
    ):
        return _approval(
            AuthorityReason.DISPATCH_BUDGET_EXHAUSTED,
            "The grant dispatch budget would be exceeded.",
            evaluation.plan,
            grant,
            AuthorityRequirement(
                "dispatch_budget",
                (str(usage.dispatches_used + demand.dispatch_units),),
                (str(limits.dispatch_limit),),
            ),
        )
    if (
        demand.dispatch_rate_units
        and limits.dispatch_rate_limit is not None
        and usage.dispatch_window_used + demand.dispatch_rate_units > limits.dispatch_rate_limit
    ):
        return _approval(
            AuthorityReason.DISPATCH_RATE_BUDGET_EXHAUSTED,
            "The grant dispatch-rate budget would be exceeded.",
            evaluation.plan,
            grant,
            AuthorityRequirement(
                "dispatch_rate_budget",
                (str(usage.dispatch_window_used + demand.dispatch_rate_units),),
                (str(limits.dispatch_rate_limit),),
            ),
        )
    if (
        demand.active_dispatch_units
        and limits.active_dispatch_limit is not None
        and usage.active_dispatches + demand.active_dispatch_units > limits.active_dispatch_limit
    ):
        return _approval(
            AuthorityReason.ACTIVE_DISPATCH_BUDGET_EXHAUSTED,
            "The grant active-dispatch budget would be exceeded.",
            evaluation.plan,
            grant,
            AuthorityRequirement(
                "active_dispatch_budget",
                (str(usage.active_dispatches + demand.active_dispatch_units),),
                (str(limits.active_dispatch_limit),),
            ),
        )
    return None


def _target_selector_covered(granted: TargetEnvelope, requested: TargetSelector) -> bool:
    if granted.entire_workspace_scope and granted.scope_snapshot.contains(requested.target):
        return True
    return any(_selector_covers(candidate, requested) for candidate in granted.exact_targets)


def _canonical_target_covered(granted: TargetEnvelope, requested: CanonicalTarget) -> bool:
    if granted.entire_workspace_scope and granted.scope_snapshot.contains(requested):
        return True
    return any(candidate.matches(requested) for candidate in granted.exact_targets)


def _selector_covers(granted: TargetSelector, requested: TargetSelector) -> bool:
    if granted.target.origin != requested.target.origin:
        return False
    if granted.path_mode == "any":
        return True
    if requested.path_mode == "any":
        return False
    if granted.path_mode == "exact":
        return requested.path_mode == "exact" and granted.target.path == requested.target.path
    # A prefix grant covers an exact descendant or a narrower prefix subtree.
    return granted.matches(requested.target)


def _provider_route_covers(granted: ProviderRoute, requested: ProviderRoute) -> bool:
    return (
        granted.backend == requested.backend
        and granted.proxy_endpoint == requested.proxy_endpoint
        and granted.credential_ref == requested.credential_ref
        and not requested.embedded_credentials
        and not requested.trust_environment
    )


def _valid_provider_route(route: ProviderRoute) -> bool:
    if route.backend == "proxy":
        return bool(
            route.proxy_endpoint
            and _valid_canonical_target(route.proxy_endpoint)
            and route.proxy_endpoint.path == "/"
        )
    return route.backend in {"direct", "disabled"} and route.proxy_endpoint is None and route.credential_ref is None


def _valid_canonical_target(target: CanonicalTarget) -> bool:
    return (
        target.scheme in {"http", "https"}
        and bool(target.host)
        and 1 <= target.port <= 65535
        and target.path.startswith("/")
    )


def _output_covers(granted: LocalOutputDestination, requested: LocalOutputDestination) -> bool:
    if granted.path != requested.path or granted.within_workspace != requested.within_workspace:
        return False
    if requested.disposition == "overwrite" and granted.disposition != "overwrite":
        return False
    if requested.may_prune and not granted.may_prune:
        return False
    return True


def _observe_mode_covers(grant: AuthorityGrant, effects: EffectEnvelope) -> bool:
    writes = {LocalWriteDomain(item) for item in effects.local_writes}
    return (
        not effects.traffic
        and not effects.local_destruction
        and not effects.remote_state_change
        and not effects.credential_use
        and not effects.secret_use
        and writes.issubset(grant.observation_write_domains)
        and (not effects.local_change or bool(writes))
    )


def _requires_step_up(risk: RiskClass, effects: EffectEnvelope) -> bool:
    return (
        risk is RiskClass.HIGH
        or effects.local_change
        or effects.local_destruction
        or effects.remote_state_change
        or effects.credential_use
        or effects.secret_use
        or effects.replay_safety in {str(Idempotency.NON_IDEMPOTENT), str(Idempotency.CONDITIONAL)}
    )


def _step_up_covers(grant: AuthorityGrant, evaluation: AuthorityEvaluation) -> bool:
    return bool(
        evaluation.step_up
        and evaluation.step_up.covers(grant, evaluation.plan, evaluation.idempotency_key, evaluation.now)
    )


def _action_pattern_matches(pattern: str, action_id: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return action_id.startswith(pattern[:-1])
    return pattern == action_id


def _approval(
    reason: AuthorityReason,
    message: str,
    plan: ExecutionPlan,
    grant: AuthorityGrant | None = None,
    requirement: AuthorityRequirement | None = None,
) -> ApprovalRequired:
    return ApprovalRequired(reason, message, plan.plan_fingerprint, grant.grant_id if grant else "", requirement)


def _effect_summary(effects: EffectEnvelope) -> str:
    return ",".join(
        (
            f"traffic={'|'.join(effects.traffic) or '-'}",
            f"writes={'|'.join(effects.local_writes) or '-'}",
            f"local_change={effects.local_change}",
            f"local_destruction={effects.local_destruction}",
            f"remote_change={effects.remote_state_change}",
            f"credential={effects.credential_use}",
            f"secret={effects.secret_use}",
            f"replay={effects.replay_safety}",
        )
    )


def _target_text(target: CanonicalTarget) -> str:
    return f"{target.scheme}://{target.host}:{target.port}{target.path}"


def _selector_text(selector: TargetSelector) -> str:
    return f"{_target_text(selector.target)}#{selector.path_mode}"


def _provider_text(route: ProviderRoute) -> str:
    endpoint = _target_text(route.proxy_endpoint) if route.proxy_endpoint else "-"
    return f"{route.backend}:{endpoint}:credential={route.credential_ref or '-'}"


def _output_text(output: LocalOutputDestination) -> str:
    return f"{output.path}:{output.disposition}:prune={output.may_prune}"


def _normalized_unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({str(item).strip() for item in values if str(item).strip()}))


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime:
    text = str(value)
    return datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)


def _requirement_dict(value: AuthorityRequirement | None) -> dict[str, Any] | None:
    return value.to_dict() if value is not None else None
