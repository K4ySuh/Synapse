# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-independent application action outcomes."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Generic, Literal, TypeAlias, TypeVar, Union

from synapse_mcp.core.errors import McpError


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Success(Generic[T]):
    payload: T
    payload_signals_error: bool = False
    legacy_code: int | None = None
    kind: Literal["success"] = field(init=False, default="success")


@dataclass(frozen=True, slots=True)
class ValidationFailure:
    message: str
    legacy_code: int | None = None
    kind: Literal["validation_failure"] = field(init=False, default="validation_failure")


@dataclass(frozen=True, slots=True)
class UnavailableCapability:
    message: str
    legacy_code: int | None = None
    kind: Literal["unavailable_capability"] = field(init=False, default="unavailable_capability")


@dataclass(frozen=True, slots=True)
class PolicyDenial:
    message: str
    legacy_code: int | None = None
    kind: Literal["policy_denial"] = field(init=False, default="policy_denial")


@dataclass(frozen=True, slots=True)
class ApprovalRequired:
    message: str
    legacy_code: int | None = None
    kind: Literal["approval_required"] = field(init=False, default="approval_required")


@dataclass(frozen=True, slots=True)
class ExecutionFailure:
    message: str
    legacy_code: int | None = None
    kind: Literal["execution_failure"] = field(init=False, default="execution_failure")


@dataclass(frozen=True, slots=True)
class ExecutionUnknown:
    message: str
    legacy_code: int | None = None
    kind: Literal["execution_unknown"] = field(init=False, default="execution_unknown")


ActionOutcome: TypeAlias = Union[
    Success[T],
    ValidationFailure,
    UnavailableCapability,
    PolicyDenial,
    ApprovalRequired,
    ExecutionFailure,
    ExecutionUnknown,
]


def legacy_payload_signals_error(payload: object) -> bool:
    """Return the legacy error-within-success signal for a raw payload."""

    parsed = payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except Exception:
            return False
    return isinstance(parsed, dict) and bool(parsed.get("error"))


def success_from_legacy_payload(payload: T) -> Success[T]:
    """Build a truthful typed success outcome from an unmodified legacy result."""

    return Success(
        payload=payload,
        payload_signals_error=legacy_payload_signals_error(payload),
    )


def outcome_from_mcp_error(
    exc: McpError,
    *,
    confirm_declared: bool = False,
    confirm_value: object = None,
) -> ActionOutcome[Any]:
    """Translate a legacy application error without losing its wire contract."""

    common = {"message": exc.message, "legacy_code": exc.code}
    if exc.code == -32602:
        return ValidationFailure(**common)
    if exc.code == -32002:
        return PolicyDenial(**common)
    if exc.code in {-32000, -32003}:
        return ExecutionFailure(**common)
    if exc.code == -32001:
        if confirm_declared and confirm_value is not True:
            return ApprovalRequired(**common)
        return UnavailableCapability(**common)
    return ExecutionFailure(**common)
