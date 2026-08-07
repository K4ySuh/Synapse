# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed action policy declarations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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

    def __post_init__(self) -> None:
        if not self.available and self.reason is None:
            raise ValueError("An unavailable action requires a reason")
