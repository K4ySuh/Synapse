# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed action policy declarations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet

try:
    from enum import StrEnum
except ImportError:  # pragma: no cover - exercised by the Python 3.10 CI job
    class StrEnum(str, Enum):
        """Python 3.10-compatible subset of :class:`enum.StrEnum`."""

        def __str__(self) -> str:
            return str(self.value)


class Enforcement(StrEnum):
    DECLARED_NOT_ENFORCED = "declared_not_enforced"
    ENFORCED_BY_EXECUTOR = "enforced_by_executor"


class SideEffectClass(StrEnum):
    """Legacy compatibility projection; not an authorization contract."""
    READ_ONLY = "read_only"
    PASSIVE_ANALYSIS = "passive_analysis"
    WORKSPACE_WRITE = "workspace_write"
    ACTIVE_PROBE = "active_probe"
    REPORT_BUILD = "report_build"
    THIRD_PARTY_READ = "third_party_read"
    CREDENTIAL_WRITE = "credential_write"
    LOCAL_DESTRUCTIVE = "local_destructive"
    RUNTIME_CONFIG_WRITE = "runtime_config_write"
    JOB_CONTROL = "job_control"
    AUTHORIZATION_CONFIG_WRITE = "authorization_config_write"


class RiskClass(StrEnum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class ScopeRequirement(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    CHECKED_DOWNSTREAM = "checked_downstream"
    REQUIRED = "required"


class CredentialRequirement(StrEnum):
    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class CredentialAccess(StrEnum):
    NONE = "none"
    REDACTED_METADATA_READ = "redacted_metadata_read"
    CREDENTIAL_USE = "credential_use"
    SECRET_STATE_WRITE = "secret_state_write"


class Idempotency(StrEnum):
    PURE_READ = "pure_read"
    IDEMPOTENT_WRITE = "idempotent_write"
    NON_IDEMPOTENT = "non_idempotent"
    IDEMPOTENT_CONTROL = "idempotent_control"
    CONDITIONAL = "conditional"


class TrafficDestination(StrEnum):
    AUTHORIZED_TARGET = "authorized_target"
    THIRD_PARTY = "third_party"


class LocalWriteDomain(StrEnum):
    WORKSPACE = "workspace"
    EVIDENCE = "evidence"
    CREDENTIALS = "credentials"
    JOBS = "jobs"
    RUNTIME_CONFIG = "runtime_config"
    REPORTS_ARTIFACTS = "reports_artifacts"


class DeadlineTier(Enum):
    FAST = 15.0
    STATUS = 30.0
    DEFAULT = 45.0


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    requirement: ScopeRequirement
    enforcement: Enforcement = Enforcement.DECLARED_NOT_ENFORCED


@dataclass(frozen=True, slots=True)
class CredentialPolicy:
    requirement: CredentialRequirement
    access: CredentialAccess
    enforcement: Enforcement = Enforcement.DECLARED_NOT_ENFORCED


@dataclass(frozen=True, slots=True)
class IdempotencyPolicy:
    behaviour: Idempotency
    condition: str | None = None

    def __post_init__(self) -> None:
        if self.behaviour is Idempotency.CONDITIONAL and self.condition is None:
            raise ValueError("Conditional idempotency requires a condition")
        if self.behaviour is not Idempotency.CONDITIONAL and self.condition is not None:
            raise ValueError("A condition is valid only for conditional idempotency")


@dataclass(frozen=True, slots=True)
class TaskPolicy:
    deadline_tier: DeadlineTier
    background_capable: bool
    passive_recordable: bool


@dataclass(frozen=True, slots=True)
class Availability:
    available: bool
    reason: str | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not self.available and self.reason is None:
            raise ValueError("An unavailable action requires a reason")
        if not self.available and self.reason_code is None:
            object.__setattr__(self, "reason_code", "capability_unavailable")


@dataclass(frozen=True, slots=True)
class ActionEffects:
    """Potential or request-effective operational effects for one action."""

    traffic: FrozenSet[TrafficDestination] = frozenset()
    local_writes: FrozenSet[LocalWriteDomain] = frozenset()
    local_change: bool = False
    local_destruction: bool = False
    remote_state_change: bool = False
    credential_use: bool = False
    secret_use: bool = False
    replay_safety: Idempotency = Idempotency.PURE_READ
    resolution_notes: tuple[str, ...] = ()

    def permits(self, effective: "ActionEffects") -> bool:
        """Return whether effective effects stay within this maximum envelope."""

        boolean_dimensions = (
            (self.local_change, effective.local_change),
            (self.local_destruction, effective.local_destruction),
            (self.remote_state_change, effective.remote_state_change),
            (self.credential_use, effective.credential_use),
            (self.secret_use, effective.secret_use),
        )
        if any(actual and not maximum for maximum, actual in boolean_dimensions):
            return False
        if not effective.traffic.issubset(self.traffic):
            return False
        if not effective.local_writes.issubset(self.local_writes):
            return False
        if self.replay_safety is Idempotency.PURE_READ:
            return effective.replay_safety is Idempotency.PURE_READ
        if self.replay_safety in {Idempotency.IDEMPOTENT_WRITE, Idempotency.IDEMPOTENT_CONTROL}:
            return effective.replay_safety in {
                Idempotency.PURE_READ,
                Idempotency.IDEMPOTENT_WRITE,
                Idempotency.IDEMPOTENT_CONTROL,
            }
        return True

    def with_resolution_note(self, note: str) -> "ActionEffects":
        return ActionEffects(
            traffic=self.traffic,
            local_writes=self.local_writes,
            local_change=self.local_change,
            local_destruction=self.local_destruction,
            remote_state_change=self.remote_state_change,
            credential_use=self.credential_use,
            secret_use=self.secret_use,
            replay_safety=self.replay_safety,
            resolution_notes=(*self.resolution_notes, note),
        )
