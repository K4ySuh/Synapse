# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered background-job actions."""

from __future__ import annotations

from dataclasses import replace

from pydantic import ConfigDict, JsonValue

from synapse_mcp.core import background_jobs
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import (
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    ExecutionPlan,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
    empty_target_envelope,
)

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
    IdempotencyPolicy,
    LocalWriteDomain,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    TaskPolicy,
)


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


JOBS_STATUS_MAX_EFFECTS = ActionEffects(
    local_writes=frozenset(
        {
            LocalWriteDomain.WORKSPACE,
            LocalWriteDomain.EVIDENCE,
            LocalWriteDomain.JOBS,
            LocalWriteDomain.REPORTS_ARTIFACTS,
        }
    ),
    local_change=True,
    local_destruction=True,
    replay_safety=Idempotency.NON_IDEMPOTENT,
)


def resolve_jobs_status_effects(request: ActionRequest) -> ActionEffects:
    job_id = str(request.input.jobId)
    try:
        record = background_jobs.snapshot_record(job_id)
    except McpError:
        return JOBS_STATUS_MAX_EFFECTS.with_resolution_note("unknown_job_uses_maximum")
    sidecars = any(str(record.get(key) or "") for key in ("stdoutPath", "stderrPath", "returnCodePath"))
    if record.get("finalized") and not sidecars:
        return ActionEffects(
            replay_safety=Idempotency.PURE_READ,
            resolution_notes=("terminal_finalized_snapshot_only",),
        )
    return JOBS_STATUS_MAX_EFFECTS.with_resolution_note(
        f"status={record.get('status', 'unknown')}; refresh/finalizer/cleanup may run"
    )


def resolve_jobs_status_intent(request: ActionRequest) -> AuthorizationIntent:
    job_id = str(request.input.jobId)
    try:
        record = background_jobs.snapshot_record(job_id)
    except McpError:
        workspace_id = str(request.context.workspace_id or "")
        return AuthorizationIntent(
            "jobs.status",
            workspace_id,
            empty_target_envelope(workspace_id),
            lineage=ContinuationLineage(
                kind="job_status",
                origin_action_id="unknown",
                origin_correlation_id=request.context.correlation_id,
                job_id=job_id,
            ),
        )
    workspace_id = str(record.get("workspaceId") or request.context.workspace_id or "")
    serialized_plan = record.get("executionPlan")
    if isinstance(serialized_plan, dict):
        origin = ExecutionPlan.from_dict(serialized_plan)
        lineage = ContinuationLineage(
            kind="job_status",
            origin_action_id=origin.intent.lineage.origin_action_id or origin.action_id,
            origin_correlation_id=origin.intent.lineage.origin_correlation_id or origin.correlation_id,
            parent_plan_fingerprint=origin.plan_fingerprint,
            job_id=job_id,
            handler=origin.intent.lineage.handler,
            binding_fingerprint=origin.intent.lineage.binding_fingerprint,
        )
        return replace(origin.intent, action_id="jobs.status", lineage=lineage)
    target = str(record.get("target") or "")
    snapshot = ScopeSnapshot.for_workspace(workspace_id)
    exact: tuple[TargetSelector, ...] = ()
    seeds: tuple[CanonicalTarget, ...] = ()
    if target:
        canonical = CanonicalTarget.from_url(target)
        exact = (TargetSelector(canonical, "any", "legacy_job_target"),)
        seeds = (canonical,)
    return AuthorizationIntent(
        "jobs.status",
        workspace_id,
        TargetEnvelope(workspace_id, snapshot.digest, snapshot, exact, seeds),
        lineage=ContinuationLineage(
            kind="job_status",
            origin_action_id=str(record.get("tool") or "unknown"),
            origin_correlation_id=str(record.get("correlationId") or ""),
            job_id=job_id,
        ),
    )


JOBS_STATUS = ActionDescriptor(
    id=ActionId.parse("jobs.status"),
    pack="jobs",
    title="Background job status",
    summary="Return status and final result metadata for a Synapse background job.",
    input_model=JobsStatusInput,
    output_model=JobsStatusOutput,
    effects=JOBS_STATUS_MAX_EFFECTS,
    effect_resolver=resolve_jobs_status_effects,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    task_policy=TaskPolicy(DeadlineTier.STATUS, False, False),
    executor=JobsStatusExecutor(),
    availability=Availability(available=True),
    intent_resolver=resolve_jobs_status_intent,
    legacy_aliases=("jobs.status",),
    legacy_serializer="transport",
    implementation_ref="background_jobs.status",
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
)

DESCRIPTORS = (JOBS_STATUS,)
