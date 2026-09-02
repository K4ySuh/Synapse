# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Versioned, protocol-independent execution lifecycle contracts.

``ExecutionPlan`` remains the compatibility carrier used by Registry actions
and workers.  The contracts here bind that sealed plan to one durable dispatch
run and describe observations and validation without creating another
executor or authority path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from .execution import EffectEnvelope, ExecutionPlan, ExecutionPlanError


LIFECYCLE_CONTRACT_VERSION = 1
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_DETAIL_KEYS = frozenset(
    {"authorizationsessionid", "idempotencykey", "principalid", "requeststateid", "stepupid", "token"}
)
_SECRET_DETAIL_KEYS = frozenset(
    {"authorization", "bearer", "cookie", "password", "privatekey", "secret", "secretvalue"}
)


try:
    from enum import StrEnum
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return str(self.value)


class LifecycleContractError(ValueError):
    """A lifecycle record is invalid, mismatched, or has been altered."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ExecutionRunState(StrEnum):
    AUTHORIZED = "authorized"
    DISPATCH_STARTED = "dispatch_started"
    OBSERVING = "observing"
    VALIDATION_PENDING = "validation_pending"
    OUTCOME_COMMITTED = "outcome_committed"
    EXECUTION_UNKNOWN = "execution_unknown"
    NOT_DISPATCHED = "not_dispatched"


class ObservationTrustClass(StrEnum):
    RUNTIME_OBSERVED = "runtime_observed"
    RUNTIME_ENFORCED = "runtime_enforced"
    PROVIDER_REPORTED = "provider_reported"
    CONSUMER_REPORTED = "consumer_reported"
    MODEL_REPORTED = "model_reported"
    LEGACY_UNKNOWN = "legacy_unknown"


class ObservationCoverageStatus(StrEnum):
    OBSERVED = "observed"
    ENFORCED = "enforced"
    PARTIAL = "partial"
    UNOBSERVABLE = "unobservable"
    NOT_INSTRUMENTED = "not_instrumented"


class EffectValidationVerdict(StrEnum):
    NOT_DISPATCHED = "not_dispatched"
    WITHIN_ENVELOPE = "within_envelope"
    OUTSIDE_ENVELOPE = "outside_envelope"
    INCOMPLETE = "incomplete"
    UNOBSERVABLE = "unobservable"
    INDETERMINATE = "indeterminate"


_RUN_TRANSITIONS = {
    ExecutionRunState.AUTHORIZED: frozenset(
        {
            ExecutionRunState.DISPATCH_STARTED,
            ExecutionRunState.NOT_DISPATCHED,
            ExecutionRunState.EXECUTION_UNKNOWN,
        }
    ),
    ExecutionRunState.DISPATCH_STARTED: frozenset(
        {
            ExecutionRunState.OBSERVING,
            ExecutionRunState.VALIDATION_PENDING,
            ExecutionRunState.EXECUTION_UNKNOWN,
        }
    ),
    ExecutionRunState.OBSERVING: frozenset(
        {ExecutionRunState.VALIDATION_PENDING, ExecutionRunState.EXECUTION_UNKNOWN}
    ),
    ExecutionRunState.VALIDATION_PENDING: frozenset(
        {ExecutionRunState.OUTCOME_COMMITTED, ExecutionRunState.EXECUTION_UNKNOWN}
    ),
    ExecutionRunState.OUTCOME_COMMITTED: frozenset(),
    ExecutionRunState.EXECUTION_UNKNOWN: frozenset(
        {ExecutionRunState.OBSERVING, ExecutionRunState.VALIDATION_PENDING}
    ),
    ExecutionRunState.NOT_DISPATCHED: frozenset(),
}


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _fingerprint(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_id(value: str, name: str) -> None:
    if not _OPAQUE_ID.fullmatch(value):
        raise LifecycleContractError("lifecycle_identity_invalid", f"{name} is not a safe opaque identity.")


def _require_digest(value: str, name: str) -> None:
    if not _DIGEST.fullmatch(value):
        raise LifecycleContractError("lifecycle_fingerprint_invalid", f"{name} must be a SHA-256 digest.")


def _freeze_detail(value: Any, *, key: str = "") -> Any:
    marker = re.sub(r"[^a-z0-9]", "", key.lower())
    if marker in _SECRET_DETAIL_KEYS or marker.endswith(("password", "secret", "privatekey")):
        raise LifecycleContractError(
            "observation_secret_forbidden",
            "Execution observation detail cannot contain secret-bearing fields.",
        )
    if marker in _OPAQUE_DETAIL_KEYS and value is not None and value != "":
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise LifecycleContractError(
                "observation_opaque_identity_forbidden",
                "Execution observation detail must use hashed opaque identity references.",
            )
    if isinstance(value, Mapping):
        return MappingProxyType({str(name): _freeze_detail(item, key=str(name)) for name, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_detail(item) for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise LifecycleContractError("observation_detail_invalid", "Execution observation detail must contain finite JSON values.")


def _thaw_detail(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(name): _thaw_detail(item) for name, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_detail(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ExecutionIntent:
    """Versioned semantic lifecycle wrapper over one sealed ExecutionPlan."""

    intent_id: str
    plan_version: int
    plan_fingerprint: str
    authorization_fingerprint: str
    execution_plan: ExecutionPlan
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    intent_fingerprint: str = ""

    @classmethod
    def from_plan(cls, plan: ExecutionPlan) -> "ExecutionIntent":
        plan.verify()
        value = cls(
            intent_id=f"intent-{plan.authorization_fingerprint}",
            plan_version=plan.version,
            plan_fingerprint=plan.plan_fingerprint,
            authorization_fingerprint=plan.authorization_fingerprint,
            execution_plan=plan,
        )
        return value._sealed()

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "intentId": self.intent_id,
            "planVersion": self.plan_version,
            "planFingerprint": self.plan_fingerprint,
            "authorizationFingerprint": self.authorization_fingerprint,
            "executionPlan": self.execution_plan.to_dict(),
        }

    def _sealed(self) -> "ExecutionIntent":
        return replace(self, intent_fingerprint=_fingerprint(self._unsigned()))

    def verify(self) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION:
            raise LifecycleContractError("lifecycle_version_unsupported", "Execution intent version is unsupported.")
        _require_id(self.intent_id, "intent_id")
        self.execution_plan.verify()
        expected_id = f"intent-{self.execution_plan.authorization_fingerprint}"
        if (
            self.intent_id != expected_id
            or self.plan_version != self.execution_plan.version
            or self.plan_fingerprint != self.execution_plan.plan_fingerprint
            or self.authorization_fingerprint != self.execution_plan.authorization_fingerprint
        ):
            raise LifecycleContractError(
                "execution_intent_mismatch",
                "Execution intent does not match its sealed execution plan.",
            )
        if self._sealed().intent_fingerprint != self.intent_fingerprint:
            raise LifecycleContractError("execution_intent_tampered", "Execution intent fingerprint validation failed.")

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "intentFingerprint": self.intent_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionIntent":
        result = cls(
            intent_id=str(value["intentId"]),
            plan_version=int(value["planVersion"]),
            plan_fingerprint=str(value["planFingerprint"]),
            authorization_fingerprint=str(value["authorizationFingerprint"]),
            execution_plan=ExecutionPlan.from_dict(value["executionPlan"]),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            intent_fingerprint=str(value.get("intentFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True)
class ExecutionRunIdentity:
    execution_run_id: str
    workspace_id: str
    action_id: str
    correlation_id: str
    dispatch_id: str
    intent_id: str
    idempotency_key_ref: str
    created_at: str
    work_item_id: str = ""
    work_execution_attempt_id: str = ""
    parent_execution_run_id: str = ""
    job_id: str = ""
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    identity_fingerprint: str = ""

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "executionRunId": self.execution_run_id,
            "workspaceId": self.workspace_id,
            "actionId": self.action_id,
            "correlationId": self.correlation_id,
            "dispatchId": self.dispatch_id,
            "intentId": self.intent_id,
            "idempotencyKeyRef": self.idempotency_key_ref,
            "workItemId": self.work_item_id,
            "workExecutionAttemptId": self.work_execution_attempt_id,
            "parentExecutionRunId": self.parent_execution_run_id,
            "jobId": self.job_id,
            "createdAt": self.created_at,
        }

    def sealed(self) -> "ExecutionRunIdentity":
        return replace(self, identity_fingerprint=_fingerprint(self._unsigned()))

    def verify(self) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION:
            raise LifecycleContractError("lifecycle_version_unsupported", "Execution run identity version is unsupported.")
        for name in ("execution_run_id", "workspace_id", "action_id", "dispatch_id", "intent_id"):
            _require_id(str(getattr(self, name)), name)
        if len(self.work_item_id.encode("utf-8")) > 512:
            raise LifecycleContractError("lifecycle_identity_invalid", "work_item_id is too long.")
        if self.work_execution_attempt_id:
            _require_id(self.work_execution_attempt_id, "work_execution_attempt_id")
            if not self.work_item_id:
                raise LifecycleContractError(
                    "lifecycle_identity_invalid",
                    "A work execution attempt requires its work item identity.",
                )
        if self.parent_execution_run_id:
            _require_id(self.parent_execution_run_id, "parent_execution_run_id")
        if self.job_id:
            _require_id(self.job_id, "job_id")
        if not self.correlation_id or not self.created_at:
            raise LifecycleContractError("lifecycle_identity_invalid", "Run correlation and creation time are required.")
        if not self.idempotency_key_ref.startswith("sha256:") or len(self.idempotency_key_ref) != 71:
            raise LifecycleContractError(
                "lifecycle_identity_invalid",
                "Run idempotency identity must be an opaque SHA-256 reference.",
            )
        if self.sealed().identity_fingerprint != self.identity_fingerprint:
            raise LifecycleContractError("execution_run_identity_tampered", "Execution run identity was altered.")

    def with_job(self, job_id: str) -> "ExecutionRunIdentity":
        if self.job_id and self.job_id != job_id:
            raise LifecycleContractError("execution_run_job_mismatch", "Execution run is already bound to another job.")
        return replace(self, job_id=job_id, identity_fingerprint="").sealed()

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "identityFingerprint": self.identity_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionRunIdentity":
        result = cls(
            execution_run_id=str(value["executionRunId"]),
            workspace_id=str(value["workspaceId"]),
            action_id=str(value["actionId"]),
            correlation_id=str(value["correlationId"]),
            dispatch_id=str(value["dispatchId"]),
            intent_id=str(value["intentId"]),
            idempotency_key_ref=str(value["idempotencyKeyRef"]),
            work_item_id=str(value.get("workItemId") or ""),
            work_execution_attempt_id=str(value.get("workExecutionAttemptId") or ""),
            parent_execution_run_id=str(value.get("parentExecutionRunId") or ""),
            job_id=str(value.get("jobId") or ""),
            created_at=str(value["createdAt"]),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            identity_fingerprint=str(value.get("identityFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    execution_run_id: str
    dispatch_id: str
    plan_fingerprint: str
    authorization_fingerprint: str
    authority_source: str
    profile: str
    authority_session_ref: str
    grant_id: str
    grant_revision: int
    decision_reason: str
    authorized_at: str
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    binding_fingerprint: str = ""

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "executionRunId": self.execution_run_id,
            "dispatchId": self.dispatch_id,
            "planFingerprint": self.plan_fingerprint,
            "authorizationFingerprint": self.authorization_fingerprint,
            "authoritySource": self.authority_source,
            "profile": self.profile,
            "authoritySessionRef": self.authority_session_ref,
            "grantId": self.grant_id,
            "grantRevision": self.grant_revision,
            "decisionReason": self.decision_reason,
            "authorizedAt": self.authorized_at,
        }

    def sealed(self) -> "ExecutionAuthorization":
        return replace(self, binding_fingerprint=_fingerprint(self._unsigned()))

    def verify(self, intent: ExecutionIntent | None = None) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION:
            raise LifecycleContractError("lifecycle_version_unsupported", "Execution authorization version is unsupported.")
        _require_id(self.execution_run_id, "execution_run_id")
        _require_id(self.dispatch_id, "dispatch_id")
        _require_digest(self.plan_fingerprint, "plan_fingerprint")
        _require_digest(self.authorization_fingerprint, "authorization_fingerprint")
        if not self.authority_session_ref.startswith("sha256:") or len(self.authority_session_ref) != 71:
            raise LifecycleContractError(
                "execution_authorization_invalid",
                "Authorization session identity must be an opaque SHA-256 reference.",
            )
        if (
            not self.authority_source
            or not self.profile
            or not self.grant_id
            or self.grant_revision < 1
            or not self.decision_reason
            or not self.authorized_at
        ):
            raise LifecycleContractError("execution_authorization_invalid", "Authorization binding is incomplete.")
        if intent is not None and (
            self.plan_fingerprint != intent.plan_fingerprint
            or self.authorization_fingerprint != intent.authorization_fingerprint
        ):
            raise LifecycleContractError(
                "execution_authorization_mismatch",
                "Authorization binding does not match the exact execution intent.",
            )
        if self.sealed().binding_fingerprint != self.binding_fingerprint:
            raise LifecycleContractError("execution_authorization_tampered", "Authorization binding was altered.")

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "bindingFingerprint": self.binding_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionAuthorization":
        result = cls(
            execution_run_id=str(value["executionRunId"]),
            dispatch_id=str(value["dispatchId"]),
            plan_fingerprint=str(value["planFingerprint"]),
            authorization_fingerprint=str(value["authorizationFingerprint"]),
            authority_source=str(value["authoritySource"]),
            profile=str(value["profile"]),
            authority_session_ref=str(value["authoritySessionRef"]),
            grant_id=str(value["grantId"]),
            grant_revision=int(value["grantRevision"]),
            decision_reason=str(value["decisionReason"]),
            authorized_at=str(value["authorizedAt"]),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            binding_fingerprint=str(value.get("bindingFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True, order=True)
class ObservationSource:
    trust_class: ObservationTrustClass
    observer_id: str
    provider: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "trust_class", ObservationTrustClass(str(self.trust_class)))
        if not self.observer_id:
            raise LifecycleContractError("observation_source_invalid", "Observation source requires an observer identity.")

    @property
    def trusted(self) -> bool:
        return self.trust_class in {
            ObservationTrustClass.RUNTIME_OBSERVED,
            ObservationTrustClass.RUNTIME_ENFORCED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"trustClass": str(self.trust_class), "observerId": self.observer_id, "provider": self.provider}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationSource":
        return cls(
            ObservationTrustClass(str(value["trustClass"])),
            str(value["observerId"]),
            str(value.get("provider") or ""),
        )


@dataclass(frozen=True, slots=True, order=True)
class ObservationCoverage:
    effect_class: str
    status: ObservationCoverageStatus
    observer_id: str
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", ObservationCoverageStatus(str(self.status)))
        if not self.effect_class or not self.observer_id:
            raise LifecycleContractError("observation_coverage_invalid", "Coverage requires effect and observer identity.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "effectClass": self.effect_class,
            "status": str(self.status),
            "observerId": self.observer_id,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationCoverage":
        return cls(
            str(value["effectClass"]),
            ObservationCoverageStatus(str(value["status"])),
            str(value["observerId"]),
            str(value.get("detail") or ""),
        )


@dataclass(frozen=True, slots=True)
class NormalizedEffectObservation:
    observation_id: str
    execution_run_id: str
    sequence: int
    source: ObservationSource
    effect_class: str
    observed_effects: EffectEnvelope
    observed_at: str
    detail: Mapping[str, Any]
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    observation_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", _freeze_detail(self.detail))

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "observationId": self.observation_id,
            "executionRunId": self.execution_run_id,
            "sequence": self.sequence,
            "source": self.source.to_dict(),
            "effectClass": self.effect_class,
            "observedEffects": self.observed_effects.to_dict(),
            "observedAt": self.observed_at,
            "detail": _thaw_detail(self.detail),
        }

    def sealed(self) -> "NormalizedEffectObservation":
        return replace(self, observation_fingerprint=_fingerprint(self._unsigned()))

    def verify(self) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION or self.sequence < 1:
            raise LifecycleContractError("observation_invalid", "Observation version or sequence is invalid.")
        _require_id(self.observation_id, "observation_id")
        _require_id(self.execution_run_id, "execution_run_id")
        if not self.effect_class or not self.observed_at:
            raise LifecycleContractError("observation_invalid", "Observation effect class and timestamp are required.")
        if self.sealed().observation_fingerprint != self.observation_fingerprint:
            raise LifecycleContractError("observation_tampered", "Observation fingerprint validation failed.")

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "observationFingerprint": self.observation_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NormalizedEffectObservation":
        result = cls(
            observation_id=str(value["observationId"]),
            execution_run_id=str(value["executionRunId"]),
            sequence=int(value["sequence"]),
            source=ObservationSource.from_dict(value["source"]),
            effect_class=str(value["effectClass"]),
            observed_effects=EffectEnvelope.from_dict(value["observedEffects"]),
            observed_at=str(value["observedAt"]),
            detail=dict(value.get("detail") or {}),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            observation_fingerprint=str(value.get("observationFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True, order=True)
class EffectDiscrepancy:
    dimension: str
    reason: str
    authorized: str = ""
    observed: str = ""

    def __post_init__(self) -> None:
        if not self.dimension or not self.reason:
            raise LifecycleContractError(
                "effect_discrepancy_invalid",
                "Effect discrepancy requires a dimension and reason.",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "reason": self.reason,
            "authorized": self.authorized,
            "observed": self.observed,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectDiscrepancy":
        return cls(
            str(value["dimension"]),
            str(value["reason"]),
            str(value.get("authorized") or ""),
            str(value.get("observed") or ""),
        )


@dataclass(frozen=True, slots=True)
class EffectValidation:
    validation_id: str
    execution_run_id: str
    verdict: EffectValidationVerdict
    authorized_effects: EffectEnvelope
    observed_effects: EffectEnvelope
    observation_fingerprints: tuple[str, ...]
    coverage: tuple[ObservationCoverage, ...]
    discrepancies: tuple[EffectDiscrepancy, ...]
    validated_at: str
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    validation_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", EffectValidationVerdict(str(self.verdict)))
        object.__setattr__(self, "observation_fingerprints", tuple(self.observation_fingerprints))
        object.__setattr__(self, "coverage", tuple(self.coverage))
        object.__setattr__(self, "discrepancies", tuple(self.discrepancies))

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "validationId": self.validation_id,
            "executionRunId": self.execution_run_id,
            "verdict": str(self.verdict),
            "authorizedEffects": self.authorized_effects.to_dict(),
            "observedEffects": self.observed_effects.to_dict(),
            "observationFingerprints": list(self.observation_fingerprints),
            "coverage": [item.to_dict() for item in self.coverage],
            "discrepancies": [item.to_dict() for item in self.discrepancies],
            "validatedAt": self.validated_at,
        }

    def sealed(self) -> "EffectValidation":
        return replace(self, validation_fingerprint=_fingerprint(self._unsigned()))

    def verify(self) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION:
            raise LifecycleContractError("lifecycle_version_unsupported", "Effect validation version is unsupported.")
        _require_id(self.validation_id, "validation_id")
        _require_id(self.execution_run_id, "execution_run_id")
        if not self.validated_at:
            raise LifecycleContractError("effect_validation_invalid", "Effect validation requires a timestamp.")
        for value in self.observation_fingerprints:
            _require_digest(value, "observation_fingerprint")
        if self.verdict is EffectValidationVerdict.OUTSIDE_ENVELOPE and not self.discrepancies:
            raise LifecycleContractError("effect_validation_invalid", "Outside-envelope validation needs a discrepancy.")
        if self.verdict is EffectValidationVerdict.INDETERMINATE and not self.discrepancies:
            raise LifecycleContractError("effect_validation_invalid", "Indeterminate validation needs a discrepancy.")
        if self.verdict is EffectValidationVerdict.WITHIN_ENVELOPE and not self.authorized_effects.permits(
            self.observed_effects
        ):
            raise LifecycleContractError("effect_validation_invalid", "Within-envelope verdict exceeds authorization.")
        if self.sealed().validation_fingerprint != self.validation_fingerprint:
            raise LifecycleContractError("effect_validation_tampered", "Effect validation fingerprint failed.")

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "validationFingerprint": self.validation_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectValidation":
        result = cls(
            validation_id=str(value["validationId"]),
            execution_run_id=str(value["executionRunId"]),
            verdict=EffectValidationVerdict(str(value["verdict"])),
            authorized_effects=EffectEnvelope.from_dict(value["authorizedEffects"]),
            observed_effects=EffectEnvelope.from_dict(value["observedEffects"]),
            observation_fingerprints=tuple(str(item) for item in value.get("observationFingerprints", [])),
            coverage=tuple(ObservationCoverage.from_dict(item) for item in value.get("coverage", [])),
            discrepancies=tuple(EffectDiscrepancy.from_dict(item) for item in value.get("discrepancies", [])),
            validated_at=str(value["validatedAt"]),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            validation_fingerprint=str(value.get("validationFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True)
class ExecutionRun:
    identity: ExecutionRunIdentity
    intent: ExecutionIntent
    authorization: ExecutionAuthorization
    state: ExecutionRunState
    updated_at: str
    outcome_kind: str = ""
    observation_ids: tuple[str, ...] = ()
    coverage: tuple[ObservationCoverage, ...] = ()
    final_validation_id: str = ""
    contract_version: int = LIFECYCLE_CONTRACT_VERSION
    run_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", ExecutionRunState(str(self.state)))
        object.__setattr__(self, "observation_ids", tuple(self.observation_ids))
        object.__setattr__(self, "coverage", tuple(self.coverage))

    def _unsigned(self) -> dict[str, Any]:
        return {
            "contractVersion": self.contract_version,
            "identity": self.identity.to_dict(),
            "intent": self.intent.to_dict(),
            "authorizationBinding": self.authorization.to_dict(),
            "state": str(self.state),
            "outcomeKind": self.outcome_kind,
            "observationIds": list(self.observation_ids),
            "coverage": [item.to_dict() for item in self.coverage],
            "finalValidationId": self.final_validation_id,
            "updatedAt": self.updated_at,
        }

    def sealed(self) -> "ExecutionRun":
        return replace(self, run_fingerprint=_fingerprint(self._unsigned()))

    def verify(self) -> None:
        if self.contract_version != LIFECYCLE_CONTRACT_VERSION:
            raise LifecycleContractError("lifecycle_version_unsupported", "Execution run version is unsupported.")
        self.identity.verify()
        self.intent.verify()
        self.authorization.verify(self.intent)
        if (
            self.identity.execution_run_id != self.authorization.execution_run_id
            or self.identity.dispatch_id != self.authorization.dispatch_id
            or self.identity.intent_id != self.intent.intent_id
            or self.identity.workspace_id != self.intent.execution_plan.intent.workspace_id
            or self.identity.action_id != self.intent.execution_plan.action_id
        ):
            raise LifecycleContractError("execution_run_binding_mismatch", "Run identity, intent, and authorization diverge.")
        if self.final_validation_id:
            _require_id(self.final_validation_id, "final_validation_id")
        if not self.updated_at or len(set(self.observation_ids)) != len(self.observation_ids):
            raise LifecycleContractError(
                "execution_run_incomplete",
                "Execution run timestamp and observation identities must be complete and unique.",
            )
        for observation_id in self.observation_ids:
            _require_id(observation_id, "observation_id")
        if self.state in {
            ExecutionRunState.VALIDATION_PENDING,
            ExecutionRunState.OUTCOME_COMMITTED,
            ExecutionRunState.EXECUTION_UNKNOWN,
            ExecutionRunState.NOT_DISPATCHED,
        } and not self.final_validation_id:
            raise LifecycleContractError("execution_run_incomplete", "Final execution state lacks effect validation.")
        if self.sealed().run_fingerprint != self.run_fingerprint:
            raise LifecycleContractError("execution_run_tampered", "Execution run fingerprint validation failed.")

    def transition(
        self,
        requested: ExecutionRunState | str,
        *,
        updated_at: str,
        outcome_kind: str | None = None,
        observations: Sequence[NormalizedEffectObservation] = (),
        coverage: Sequence[ObservationCoverage] | None = None,
        validation: EffectValidation | None = None,
    ) -> "ExecutionRun":
        requested_state = ExecutionRunState(str(requested))
        if requested_state != self.state and requested_state not in _RUN_TRANSITIONS[self.state]:
            raise LifecycleContractError(
                "execution_run_transition_invalid",
                f"Execution run cannot transition from {self.state} to {requested_state}.",
            )
        for item in observations:
            item.verify()
            if item.execution_run_id != self.identity.execution_run_id:
                raise LifecycleContractError("observation_run_mismatch", "Observation belongs to another execution run.")
        appended_observation_ids = tuple(item.observation_id for item in observations)
        if (
            len(set(appended_observation_ids)) != len(appended_observation_ids)
            or any(item in self.observation_ids for item in appended_observation_ids)
        ):
            raise LifecycleContractError(
                "observation_duplicate",
                "Execution observations are append-only and may be recorded once.",
            )
        if validation is not None:
            validation.verify()
            if validation.execution_run_id != self.identity.execution_run_id:
                raise LifecycleContractError("validation_run_mismatch", "Validation belongs to another execution run.")
        result = replace(
            self,
            state=requested_state,
            outcome_kind=self.outcome_kind if outcome_kind is None else outcome_kind,
            observation_ids=tuple((*self.observation_ids, *appended_observation_ids)),
            coverage=self.coverage if coverage is None else tuple(coverage),
            final_validation_id=(validation.validation_id if validation is not None else self.final_validation_id),
            updated_at=updated_at,
            run_fingerprint="",
        ).sealed()
        result.verify()
        return result

    def bind_job(self, job_id: str, *, updated_at: str) -> "ExecutionRun":
        result = replace(
            self,
            identity=self.identity.with_job(job_id),
            state=(ExecutionRunState.OBSERVING if self.state is ExecutionRunState.DISPATCH_STARTED else self.state),
            updated_at=updated_at,
            run_fingerprint="",
        ).sealed()
        result.verify()
        return result

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "runFingerprint": self.run_fingerprint}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionRun":
        result = cls(
            identity=ExecutionRunIdentity.from_dict(value["identity"]),
            intent=ExecutionIntent.from_dict(value["intent"]),
            authorization=ExecutionAuthorization.from_dict(
                value.get("authorizationBinding") or value["authorization"]
            ),
            state=ExecutionRunState(str(value["state"])),
            outcome_kind=str(value.get("outcomeKind") or ""),
            observation_ids=tuple(str(item) for item in value.get("observationIds", [])),
            coverage=tuple(ObservationCoverage.from_dict(item) for item in value.get("coverage", [])),
            final_validation_id=str(value.get("finalValidationId") or ""),
            updated_at=str(value["updatedAt"]),
            contract_version=int(value.get("contractVersion", LIFECYCLE_CONTRACT_VERSION)),
            run_fingerprint=str(value.get("runFingerprint") or ""),
        )
        result.verify()
        return result


@dataclass(frozen=True, slots=True)
class ObserverResult:
    observations: tuple[NormalizedEffectObservation, ...]
    validation: EffectValidation

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(self.observations))


class ExecutionObserver(Protocol):
    """Injectable observation seam; it never dispatches or grants authority."""

    def finalize(
        self,
        run: ExecutionRun,
        *,
        outcome_kind: str,
        observed_at: str,
    ) -> ObserverResult: ...


class NoOpExecutionObserver:
    """6C baseline observer that makes missing effect coverage explicit."""

    observer_id = "synapse.lifecycle.noop-v1"

    def finalize(
        self,
        run: ExecutionRun,
        *,
        outcome_kind: str,
        observed_at: str,
    ) -> ObserverResult:
        del outcome_kind
        coverage = (
            ObservationCoverage(
                "execution_effects",
                ObservationCoverageStatus.NOT_INSTRUMENTED,
                self.observer_id,
                "Task 6C records lifecycle state; effect-boundary instrumentation begins in Task 6D.",
            ),
        )
        validation = EffectValidation(
            validation_id=f"validation-{hashlib.sha256(f'{run.identity.execution_run_id}:{observed_at}'.encode()).hexdigest()[:32]}",
            execution_run_id=run.identity.execution_run_id,
            verdict=EffectValidationVerdict.UNOBSERVABLE,
            authorized_effects=run.intent.execution_plan.effects,
            observed_effects=EffectEnvelope(),
            observation_fingerprints=(),
            coverage=coverage,
            discrepancies=(),
            validated_at=observed_at,
        ).sealed()
        return ObserverResult((), validation)


def validate_observed_effects(
    run: ExecutionRun,
    observations: Sequence[NormalizedEffectObservation],
    coverage: Sequence[ObservationCoverage],
    *,
    validation_id: str,
    validated_at: str,
) -> EffectValidation:
    """Validate only trusted runtime observations against the sealed maximum."""

    run.verify()
    for item in observations:
        item.verify()
        if item.execution_run_id != run.identity.execution_run_id:
            raise LifecycleContractError("observation_run_mismatch", "Observation belongs to another execution run.")
    trusted = tuple(item for item in observations if item.source.trusted)
    traffic: set[str] = set()
    writes: set[str] = set()
    local_change = local_destruction = remote_change = credential_use = secret_use = False
    replay_safety = "pure_read"
    replay_order = {
        "pure_read": 0,
        "idempotent_write": 1,
        "idempotent_control": 1,
        "conditional": 2,
        "non_idempotent": 3,
    }
    for item in trusted:
        effects = item.observed_effects
        traffic.update(effects.traffic)
        writes.update(effects.local_writes)
        local_change = local_change or effects.local_change
        local_destruction = local_destruction or effects.local_destruction
        remote_change = remote_change or effects.remote_state_change
        credential_use = credential_use or effects.credential_use
        secret_use = secret_use or effects.secret_use
        if replay_order.get(effects.replay_safety, 99) > replay_order.get(replay_safety, 99):
            replay_safety = effects.replay_safety
    observed = EffectEnvelope(
        tuple(sorted(traffic)),
        tuple(sorted(writes)),
        local_change,
        local_destruction,
        remote_change,
        credential_use,
        secret_use,
        replay_safety,
    )
    coverage_tuple = tuple(coverage)
    discrepancies: tuple[EffectDiscrepancy, ...] = ()
    if not run.intent.execution_plan.effects.permits(observed):
        verdict = EffectValidationVerdict.OUTSIDE_ENVELOPE
        discrepancies = (
            EffectDiscrepancy(
                "effect_envelope",
                "Trusted runtime observations exceed the authorized effect envelope.",
                json.dumps(run.intent.execution_plan.effects.to_dict(), sort_keys=True),
                json.dumps(observed.to_dict(), sort_keys=True),
            ),
        )
    elif any(
        item.status in {
            ObservationCoverageStatus.PARTIAL,
            ObservationCoverageStatus.UNOBSERVABLE,
            ObservationCoverageStatus.NOT_INSTRUMENTED,
        }
        for item in coverage_tuple
    ):
        verdict = EffectValidationVerdict.UNOBSERVABLE
    elif not coverage_tuple:
        verdict = EffectValidationVerdict.INCOMPLETE
    else:
        verdict = EffectValidationVerdict.WITHIN_ENVELOPE
    return EffectValidation(
        validation_id=validation_id,
        execution_run_id=run.identity.execution_run_id,
        verdict=verdict,
        authorized_effects=run.intent.execution_plan.effects,
        observed_effects=observed,
        observation_fingerprints=tuple(item.observation_fingerprint for item in trusted),
        coverage=coverage_tuple,
        discrepancies=discrepancies,
        validated_at=validated_at,
    ).sealed()


def verify_effect_validation_binding(
    run: ExecutionRun,
    observations: Sequence[NormalizedEffectObservation],
    validation: EffectValidation,
) -> None:
    """Reject a verdict that is not derived from this run's trusted observations."""

    validation.verify()
    ordered = tuple(sorted(observations, key=lambda item: (item.sequence, item.observation_id)))
    if len({item.sequence for item in ordered}) != len(ordered):
        raise LifecycleContractError(
            "effect_validation_binding_mismatch",
            "Execution observations contain duplicate sequence identities.",
        )
    expected = validate_observed_effects(
        run,
        ordered,
        validation.coverage,
        validation_id=validation.validation_id,
        validated_at=validation.validated_at,
    )
    conservative_verdict = (
        expected.verdict is not EffectValidationVerdict.OUTSIDE_ENVELOPE
        and validation.verdict
        in {EffectValidationVerdict.INCOMPLETE, EffectValidationVerdict.INDETERMINATE}
    )
    if (
        (validation.verdict != expected.verdict and not conservative_verdict)
        or validation.authorized_effects != expected.authorized_effects
        or validation.observed_effects != expected.observed_effects
        or validation.observation_fingerprints != expected.observation_fingerprints
        or validation.coverage != expected.coverage
        or (not conservative_verdict and validation.discrepancies != expected.discrepancies)
    ):
        raise LifecycleContractError(
            "effect_validation_binding_mismatch",
            "Effect validation does not match the run's trusted observations and authorized envelope.",
        )


__all__ = [
    "EffectDiscrepancy",
    "EffectValidation",
    "EffectValidationVerdict",
    "ExecutionAuthorization",
    "ExecutionIntent",
    "ExecutionObserver",
    "ExecutionRun",
    "ExecutionRunIdentity",
    "ExecutionRunState",
    "LIFECYCLE_CONTRACT_VERSION",
    "LifecycleContractError",
    "NoOpExecutionObserver",
    "NormalizedEffectObservation",
    "ObservationCoverage",
    "ObservationCoverageStatus",
    "ObservationSource",
    "ObservationTrustClass",
    "ObserverResult",
    "validate_observed_effects",
    "verify_effect_validation_binding",
]
