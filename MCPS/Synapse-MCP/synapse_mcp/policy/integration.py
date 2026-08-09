# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Authority-aware Registry policy adapter and dispatch lifecycle hooks."""

from __future__ import annotations

from typing import Any

from synapse_mcp.app.actions.outcomes import (
    ApprovalRequired as ApplicationApprovalRequired,
    ExecutionFailure,
    ExecutionUnknown,
    PolicyDenial,
    Success,
)
from synapse_mcp.app.actions.registry import PolicyEvaluationResult
from synapse_mcp.core import evidence
from synapse_mcp.core import workspace

from .authority import Allow, ApprovalRequired, ScopeDenied
from .repository import AuthorizationReceipt, AuthorityRepositoryError, WorkspaceAuthorityRepository


def evaluate_registry_request(descriptor: Any, request: Any, effects: Any) -> PolicyEvaluationResult:
    """Evaluate exact Registry truth and fail closed on repository errors."""

    del effects  # The sealed plan already contains request-effective effects.
    context = request.context
    plan = context.execution_plan
    if plan is None:
        return _approval_failure("execution_plan_missing", "Authority evaluation requires a sealed execution plan.")
    workspace_id = str(plan.intent.workspace_id or context.workspace_id or "")
    if not workspace_id:
        return _approval_failure("authority_workspace_missing", "Authority execution requires a workspace binding.")
    if context.workspace_id and workspace.normalize_workspace_id(context.workspace_id) != workspace.normalize_workspace_id(workspace_id):
        _log(
            "authority.decision",
            workspace_id,
            plan.action_id,
            plan.plan_fingerprint,
            reason="authority_workspace_mismatch",
        )
        return PolicyEvaluationResult(
            False,
            PolicyDenial(
                "Trusted execution context workspace differs from the execution plan.",
                legacy_code=-32002,
                reason_code="authority_workspace_mismatch",
                details={"kind": "scope_denied", "reason": "authority_workspace_mismatch"},
            ),
        )
    try:
        result = WorkspaceAuthorityRepository(workspace_id).authorize(
            plan,
            risk_class=descriptor.risk_class,
            profile=context.execution_profile,
            authority_session_id=context.authority_session_id,
            selected_grant_id=context.selected_grant_id,
            idempotency_key=context.idempotency_key,
            request_state_id=context.request_state_id,
        )
    except AuthorityRepositoryError as exc:
        _log(
            "authority.evaluation_failed",
            workspace_id,
            plan.action_id,
            plan.plan_fingerprint,
            reason=exc.reason_code,
        )
        return _approval_failure(exc.reason_code, str(exc))
    except Exception as exc:
        _log(
            "authority.evaluation_failed",
            workspace_id,
            plan.action_id,
            plan.plan_fingerprint,
            reason="authority_evaluator_failed",
        )
        return _approval_failure(
            "authority_evaluator_failed",
            f"Authority evaluation failed closed: {type(exc).__name__}",
        )
    decision = result.decision
    _log(
        "authority.decision",
        workspace_id,
        plan.action_id,
        plan.plan_fingerprint,
        reason=str(decision.reason),
        grant_id=str(getattr(decision, "grant_id", "")),
        dispatch_id=result.receipt.dispatch_id if result.receipt else "",
    )
    if isinstance(decision, Allow):
        return PolicyEvaluationResult(True, receipt=result.receipt)
    details = decision.to_dict()
    if isinstance(decision, ScopeDenied):
        return PolicyEvaluationResult(
            False,
            PolicyDenial(
                decision.message,
                legacy_code=-32002,
                reason_code=str(decision.reason),
                details=details,
            ),
        )
    if isinstance(decision, ApprovalRequired):
        return PolicyEvaluationResult(
            False,
            ApplicationApprovalRequired(
                decision.message,
                legacy_code=-32001,
                reason_code=str(decision.reason),
                details=details,
            ),
        )
    return _approval_failure("authority_decision_invalid", "Authority evaluator returned an unknown decision.")


def mark_registry_dispatched(value: object) -> None:
    receipt = _receipt(value)
    WorkspaceAuthorityRepository(receipt.workspace_id).mark_dispatched(receipt)
    _log(
        "authority.dispatch",
        receipt.workspace_id,
        receipt.action_id,
        receipt.plan_fingerprint,
        reason="dispatched" if not receipt.continuation else "continuation",
        grant_id=receipt.grant_id,
        dispatch_id=receipt.dispatch_id,
    )


def record_registry_outcome(value: object, outcome: Any) -> None:
    receipt = _receipt(value)
    repository = WorkspaceAuthorityRepository(receipt.workspace_id)
    if receipt.continuation:
        state = _terminal_job_state(outcome)
        if state:
            try:
                current = repository.inspect_dispatch(receipt.dispatch_id)
                if current["state"] == "dispatched":
                    repository.transition_dispatch(receipt.dispatch_id, state)
            except AuthorityRepositoryError:
                raise
        _log(
            "authority.result",
            receipt.workspace_id,
            receipt.action_id,
            receipt.plan_fingerprint,
            reason=state or "continuation_observed",
            grant_id=receipt.grant_id,
            dispatch_id=receipt.dispatch_id,
        )
        return
    if isinstance(outcome, Success):
        job_id = _background_job_id(outcome.payload)
        if job_id:
            repository.bind_background_job(receipt, job_id)
            final_state = "dispatched"
        else:
            repository.transition_dispatch(receipt.dispatch_id, "succeeded")
            final_state = "succeeded"
    elif isinstance(outcome, ExecutionUnknown):
        repository.transition_dispatch(receipt.dispatch_id, "unknown")
        final_state = "unknown"
    else:
        repository.transition_dispatch(receipt.dispatch_id, "failed")
        final_state = "failed"
    _log(
        "authority.result",
        receipt.workspace_id,
        receipt.action_id,
        receipt.plan_fingerprint,
        reason=final_state,
        grant_id=receipt.grant_id,
        dispatch_id=receipt.dispatch_id,
    )


def record_registry_unknown(value: object) -> None:
    receipt = _receipt(value)
    if receipt.continuation:
        return
    repository = WorkspaceAuthorityRepository(receipt.workspace_id)
    try:
        current = repository.inspect_dispatch(receipt.dispatch_id)
        if current["state"] == "dispatched":
            repository.transition_dispatch(receipt.dispatch_id, "unknown")
    finally:
        _log(
            "authority.result",
            receipt.workspace_id,
            receipt.action_id,
            receipt.plan_fingerprint,
            reason="unknown",
            grant_id=receipt.grant_id,
            dispatch_id=receipt.dispatch_id,
        )


def _receipt(value: object) -> AuthorizationReceipt:
    if not isinstance(value, AuthorizationReceipt):
        raise TypeError("Registry authority hook requires an AuthorizationReceipt")
    return value


def _approval_failure(reason: str, message: str) -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        False,
        ApplicationApprovalRequired(
            message,
            legacy_code=-32001,
            reason_code=reason,
            details={"kind": "approval_required", "reason": reason, "dispatch": "not_started"},
        ),
    )


def _payload_dict(payload: object) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    dump = getattr(payload, "model_dump", None)
    if callable(dump):
        value = dump(mode="json", by_alias=True)
        return value if isinstance(value, dict) else {}
    return {}


def _background_job_id(payload: object) -> str:
    value = _payload_dict(payload)
    if not value.get("background"):
        return ""
    job = value.get("job")
    return str(job.get("jobId") or "") if isinstance(job, dict) else ""


def _terminal_job_state(outcome: object) -> str:
    if not isinstance(outcome, Success):
        return ""
    status = str(_payload_dict(outcome.payload).get("status") or "")
    if status == "completed":
        return "succeeded"
    if status in {"failed", "timed_out", "canceled"}:
        return "failed"
    return ""


def _log(
    event_type: str,
    workspace_id: str,
    action_id: str,
    plan_fingerprint: str,
    *,
    reason: str,
    grant_id: str = "",
    dispatch_id: str = "",
) -> None:
    try:
        evidence.log_event(
            event_type,
            f"Authority {reason} for {action_id}.",
            {
                "workspaceId": workspace_id,
                "actionId": action_id,
                "planFingerprint": plan_fingerprint,
                "reason": reason,
                "grantId": grant_id,
                "dispatchId": dispatch_id,
            },
        )
    except Exception:
        # The authority repository already holds the canonical audit. Evidence
        # mirroring must not rewrite known dispatch truth or trigger replay.
        return
