# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered background-job actions."""

from __future__ import annotations

from pydantic import ConfigDict

from synapse_mcp.core import background_jobs
from synapse_mcp.core.errors import McpError

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import Success, outcome_from_mcp_error
from ..policies import (
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Idempotency,
    IdempotencyPolicy,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    SideEffectClass,
    TaskPolicy,
)
from ..registry import REGISTRY


JOBS_STATUS_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"jobId":{"type":"string"},"includeResult":{"type":"boolean","default":false}},"required":["jobId"]}'
)
JobsStatusInput = make_input_model("JobsStatusInput", JOBS_STATUS_INPUT_DOCUMENT)


class JobsStatusOutput(ActionOutput):
    model_config = ConfigDict(extra="allow")


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
        return Success(payload=result)


JOBS_STATUS = ActionDescriptor(
    id=ActionId.parse("jobs.status"),
    pack="jobs",
    title="Background job status",
    summary="Return status and final result metadata for a Synapse background job.",
    input_model=JobsStatusInput,
    output_model=JobsStatusOutput,
    side_effect_class=SideEffectClass.READ_ONLY,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
    task_policy=TaskPolicy(DeadlineTier.STATUS, False, False),
    executor=JobsStatusExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(JOBS_STATUS)
