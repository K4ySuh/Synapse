# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""The typed application action descriptor contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, runtime_checkable

from .contracts import ActionInput, ActionOutput
from .identity import ActionId
from .outcomes import ActionOutcome
from .policies import (
    Availability,
    CredentialPolicy,
    IdempotencyPolicy,
    RiskClass,
    ScopePolicy,
    SideEffectClass,
    TaskPolicy,
)


TInput = TypeVar("TInput", bound=ActionInput)
TOutput = TypeVar("TOutput", bound=ActionOutput)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    workspace_id: str | None
    correlation_id: str
    deadline_seconds: float
    legacy_approval_asserted: bool | None


@dataclass(frozen=True, slots=True)
class ActionRequest(Generic[TInput]):
    input: TInput
    context: ExecutionContext


@runtime_checkable
class ActionExecutor(Protocol[TInput, TOutput]):
    @property
    def input_model(self) -> type[TInput]: ...

    @property
    def output_model(self) -> type[TOutput]: ...

    def __call__(self, request: ActionRequest[TInput]) -> ActionOutcome[TOutput]: ...


@dataclass(frozen=True, slots=True)
class ActionDescriptor(Generic[TInput, TOutput]):
    id: ActionId
    pack: str
    title: str
    summary: str
    input_model: type[TInput]
    output_model: type[TOutput]
    side_effect_class: SideEffectClass
    risk_class: RiskClass
    scope_policy: ScopePolicy
    credential_policy: CredentialPolicy
    idempotency_policy: IdempotencyPolicy
    task_policy: TaskPolicy
    executor: ActionExecutor[TInput, TOutput]
    availability: Availability
