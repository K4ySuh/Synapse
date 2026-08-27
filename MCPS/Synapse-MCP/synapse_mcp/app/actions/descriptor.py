# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""The typed application action descriptor contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, runtime_checkable

from synapse_mcp.core.execution import AuthorizationIntent, ExecutionPlan

from .contracts import ActionInput, ActionOutput
from .identity import ActionId
from .outcomes import ActionOutcome
from .policies import (
    Availability,
    ActionEffects,
    CredentialPolicy,
    IdempotencyPolicy,
    RiskClass,
    ScopePolicy,
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
    execution_plan: ExecutionPlan | None = None
    execution_profile: str = "legacy"
    authority_session_id: str = ""
    selected_grant_id: str = ""
    idempotency_key: str = ""
    request_state_id: str = ""
    continuation_dispatch_id: str = ""
    work_item_id: str = ""
    work_item_claim_id: str = ""
    authorization_receipt: object | None = None


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


@runtime_checkable
class ActionEffectResolver(Protocol[TInput]):
    def __call__(self, request: ActionRequest[TInput]) -> ActionEffects: ...


@runtime_checkable
class ActionIntentResolver(Protocol[TInput]):
    def __call__(self, request: ActionRequest[TInput]) -> AuthorizationIntent: ...


@runtime_checkable
class AvailabilityResolver(Protocol[TInput]):
    def __call__(self, request: ActionRequest[TInput]) -> Availability: ...


@dataclass(frozen=True, slots=True)
class ActionDescriptor(Generic[TInput, TOutput]):
    id: ActionId
    pack: str
    title: str
    summary: str
    input_model: type[TInput]
    output_model: type[TOutput]
    effects: ActionEffects
    effect_resolver: ActionEffectResolver[TInput] | None
    risk_class: RiskClass
    scope_policy: ScopePolicy
    credential_policy: CredentialPolicy
    task_policy: TaskPolicy
    executor: ActionExecutor[TInput, TOutput]
    availability: Availability | AvailabilityResolver[TInput]
    intent_resolver: ActionIntentResolver[TInput] | None = None
    legacy_aliases: tuple[str, ...] = ()
    legacy_serializer: str = ""
    implementation_ref: str = ""
    approval_required: bool = False
    idempotency_policy: IdempotencyPolicy | None = None
