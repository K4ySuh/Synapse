# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered background-job actions."""

from __future__ import annotations

from pydantic import ConfigDict, JsonValue

from synapse_mcp.core import background_jobs
from synapse_mcp.core.errors import McpError

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import outcome_from_mcp_error, success_from_legacy_payload
from ..policies import (
    ActionEffects,
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Idempotency,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    TaskPolicy,
)
from ..registry import REGISTRY


JOBS_STATUS_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"jobId":{"type":"string"},"includeResult":{"type":"boolean","default":false}},"required":["jobId"]}'
)
JobsStatusInput = make_input_model("JobsStatusInput", JOBS_STATUS_INPUT_DOCUMENT)


class JobsStatusOutput(ActionOutput):
    jobId: str
    tool: str
    workspaceId: str
    target: str
    status: str
    pid: int | None
    createdAt: str
    startedAt: str
    lastObservedAt: str
    completedAt: str
    timeoutSeconds: int
    timedOut: bool
    finalized: bool
    error: str
    resultSummary: dict[str, JsonValue] | None = None
    resultDisposition: str | None = None
    model_config = ConfigDict(strict=True, extra="allow")


class JobsStatusExecutor:
    input_model = JobsStatusInput
    output_model = JobsStatusOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = background_jobs.status(
                args["jobId"],
                bool(args.get("includeResult", False)),
            )
        except McpError as exc:
            return outcome_from_mcp_error(exc)
        return success_from_legacy_payload(result)


JOBS_STATUS = ActionDescriptor(
    id=ActionId.parse("jobs.status"),
    pack="jobs",
    title="Background job status",
    summary="Return status and final result metadata for a Synapse background job.",
    input_model=JobsStatusInput,
    output_model=JobsStatusOutput,
    effects=ActionEffects(replay_safety=Idempotency.PURE_READ),
    effect_resolver=None,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    task_policy=TaskPolicy(DeadlineTier.STATUS, False, False),
    executor=JobsStatusExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(JOBS_STATUS)
