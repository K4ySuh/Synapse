# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Workspace-local durable authority state and dispatch truth.

The policy model is deliberately storage agnostic.  This module is the Phase 2
file-backed implementation of the repository interface; callers never read or
edit its JSON shape directly.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from synapse_mcp.core import atomic_io, background_jobs, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import EffectEnvelope, ExecutionPlan

from .authority import (
    Allow,
    ApprovalRequired,
    AuthorityEvaluation,
    AuthorityGrant,
    AuthorityMode,
    AuthorityReason,
    BudgetUsage,
    BudgetDemand,
    ContinuationAuthorization,
    PolicyDecision,
    ScopeDenied,
    StepUpAuthorization,
    evaluate_authority,
)


SCHEMA_VERSION = 1
DEFAULT_REQUEST_STATE_TTL = timedelta(minutes=15)
DEFAULT_DECISION_RETENTION = 500
DISPATCH_STATES = frozenset({"authorized", "dispatched", "succeeded", "failed", "unknown", "cancelled"})
_TERMINAL_DISPATCH_STATES = frozenset({"succeeded", "failed", "unknown", "cancelled"})
_TRANSITIONS = {
    "authorized": frozenset({"dispatched", "cancelled"}),
    "dispatched": frozenset({"succeeded", "failed", "unknown"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "unknown": frozenset(),
    "cancelled": frozenset(),
}


class AuthorityRepositoryError(RuntimeError):
    """Recoverable, operator-facing durable authority failure."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class AuthorityRevisionConflict(AuthorityRepositoryError):
    def __init__(self, expected: int, actual: int):
        super().__init__(
            "authority_revision_conflict",
            f"Authority repository revision changed (expected {expected}, actual {actual}).",
        )
        self.expected = expected
        self.actual = actual


class DispatchTransitionError(AuthorityRepositoryError):
    def __init__(self, dispatch_id: str, current: str, requested: str):
        super().__init__(
            "illegal_dispatch_transition",
            f"Dispatch {dispatch_id} cannot transition from {current} to {requested}.",
        )


@dataclass(frozen=True, slots=True)
class AuthorizationReceipt:
    authority_source: str
    profile: str
    authority_session_id: str
    workspace_id: str
    action_id: str
    plan_fingerprint: str
    grant_id: str
    grant_revision: int
    dispatch_id: str
    decision_reason: str
    continuation: bool = False

    def __post_init__(self) -> None:
        required = (
            self.authority_source,
            self.profile,
            self.authority_session_id,
            self.workspace_id,
            self.action_id,
            self.plan_fingerprint,
            self.grant_id,
            self.dispatch_id,
            self.decision_reason,
        )
        if any(not str(item).strip() for item in required) or self.grant_revision < 1:
            raise ValueError("Authorization receipt requires durable grant and dispatch identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authoritySource": self.authority_source,
            "profile": self.profile,
            "authoritySessionId": self.authority_session_id,
            "workspaceId": self.workspace_id,
            "actionId": self.action_id,
            "planFingerprint": self.plan_fingerprint,
            "grantId": self.grant_id,
            "grantRevision": self.grant_revision,
            "dispatchId": self.dispatch_id,
            "decisionReason": self.decision_reason,
            "continuation": self.continuation,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationReceipt":
        return cls(
            authority_source=str(value["authoritySource"]),
            profile=str(value["profile"]),
            authority_session_id=str(value["authoritySessionId"]),
            workspace_id=str(value["workspaceId"]),
            action_id=str(value["actionId"]),
            plan_fingerprint=str(value["planFingerprint"]),
            grant_id=str(value["grantId"]),
            grant_revision=int(value["grantRevision"]),
            dispatch_id=str(value["dispatchId"]),
            decision_reason=str(value["decisionReason"]),
            continuation=bool(value.get("continuation")),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    decision: PolicyDecision
    receipt: AuthorizationReceipt | None = None


class AuthorityRepository(Protocol):
    """Storage-neutral operations consumed by policy and operator services."""

    def authorize(
        self,
        plan: ExecutionPlan,
        *,
        risk_class: Any,
        profile: str,
        authority_session_id: str,
        selected_grant_id: str = "",
        idempotency_key: str = "",
        request_state_id: str = "",
        third_party_provider_ids: tuple[str, ...] = (),
    ) -> AuthorizationResult: ...

    def transition_dispatch(self, dispatch_id: str, requested: str) -> dict[str, Any]: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected a UTC timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Expected a timezone-aware timestamp")
    return parsed.astimezone(timezone.utc)


def _initial_state() -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "revision": 0,
        "grants": {},
        "stepUps": {},
        "requestStates": {},
        "budgetWindows": {},
        "decisions": [],
        "dispatches": {},
        "reconciliations": {},
    }


class WorkspaceAuthorityRepository:
    """Crash-atomic JSON authority repository under one workspace lock."""

    def __init__(
        self,
        workspace_id: str,
        *,
        clock: Callable[[], datetime] = _utc_now,
        decision_retention: int = DEFAULT_DECISION_RETENTION,
        request_state_ttl: timedelta = DEFAULT_REQUEST_STATE_TTL,
    ) -> None:
        self.workspace_id = workspace.normalize_workspace_id(workspace_id)
        self._clock = clock
        self._decision_retention = max(int(decision_retention), 1)
        self._request_state_ttl = request_state_ttl

    @property
    def path(self) -> Path:
        return workspace.workspace_path(self.workspace_id) / "authority" / "state.json"

    def snapshot(self) -> dict[str, Any]:
        with workspace.workspace_lock(self.workspace_id):
            return json.loads(json.dumps(self._read_locked()))

    def create_grant(
        self,
        grant: AuthorityGrant,
        *,
        expected_repository_revision: int | None = None,
    ) -> AuthorityGrant:
        if grant.workspace_id != self.workspace_id:
            raise AuthorityRepositoryError("grant_workspace_mismatch", "Grant workspace does not match repository.")
        if grant.revision != 1:
            raise AuthorityRepositoryError("grant_revision_invalid", "A new grant must begin at revision 1.")
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            self._check_revision(state, expected_repository_revision)
            if grant.grant_id in state["grants"]:
                raise AuthorityRepositoryError("grant_already_exists", f"Grant already exists: {grant.grant_id}")
            state["grants"][grant.grant_id] = {
                "currentRevision": grant.revision,
                "revisions": {str(grant.revision): grant.to_dict()},
            }
            self._append_management_audit_locked(state, "grant_created", grant, self._clock())
            self._commit_locked(state)
        return grant

    def inspect_grant(self, grant_id: str, revision: int | None = None) -> AuthorityGrant:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            return self._grant_from_state(state, grant_id, revision)

    def list_grants(self) -> tuple[AuthorityGrant, ...]:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            return tuple(
                self._grant_from_state(state, grant_id)
                for grant_id in sorted(state["grants"])
            )

    def revise_grant(
        self,
        replacement: AuthorityGrant,
        *,
        expected_grant_revision: int,
        expected_repository_revision: int | None = None,
    ) -> AuthorityGrant:
        if replacement.workspace_id != self.workspace_id:
            raise AuthorityRepositoryError("grant_workspace_mismatch", "Grant workspace does not match repository.")
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            self._check_revision(state, expected_repository_revision)
            current = self._grant_from_state(state, replacement.grant_id)
            if current.revision != expected_grant_revision:
                raise AuthorityRevisionConflict(expected_grant_revision, current.revision)
            if replacement.revision != current.revision + 1:
                raise AuthorityRepositoryError(
                    "grant_revision_invalid",
                    "A revised grant must increment the current grant revision exactly once.",
                )
            entry = state["grants"][replacement.grant_id]
            entry["currentRevision"] = replacement.revision
            entry["revisions"][str(replacement.revision)] = replacement.to_dict()
            self._append_management_audit_locked(state, "grant_revised", replacement, self._clock())
            self._commit_locked(state)
        return replacement

    def revoke_grant(
        self,
        grant_id: str,
        *,
        expected_grant_revision: int,
        revoked_at: datetime | None = None,
    ) -> AuthorityGrant:
        now = revoked_at or self._clock()
        current = self.inspect_grant(grant_id)
        revoked = replace(current, revision=current.revision + 1, revoked_at=now)
        return self.revise_grant(revoked, expected_grant_revision=expected_grant_revision)

    def issue_step_up(self, authorization: StepUpAuthorization) -> str:
        step_up_id = f"stepup-{uuid4().hex}"
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            if self._grant_from_state(state, authorization.grant_id).revision != authorization.grant_revision:
                raise AuthorityRepositoryError("step_up_grant_stale", "Step-up grant revision is not current.")
            state["stepUps"][step_up_id] = authorization.to_dict()
            self._append_decision_locked(
                state,
                {
                    "auditId": f"audit-{uuid4().hex}",
                    "at": _format_time(self._clock()),
                    "kind": "step_up_issued",
                    "reason": "exact_step_up",
                    "actionId": "",
                    "authorizationFingerprint": authorization.authorization_fingerprint,
                    "planFingerprint": "",
                    "grantId": authorization.grant_id,
                    "grantRevision": authorization.grant_revision,
                    "dispatchId": "",
                },
            )
            self._commit_locked(state)
        return step_up_id

    def issue_request_step_up(
        self,
        request_state_id: str,
        *,
        approved_by: str,
        expires_at: datetime,
    ) -> str:
        """Issue one exact step-up using only trusted pending-request state."""

        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            now = self._clock()
            request_state = self._pending_request_state_locked(state, request_state_id, now)
            grant_id = str(request_state.get("grantId") or "")
            grant_revision = int(request_state.get("grantRevision") or 0)
            if not grant_id or grant_revision < 1:
                raise AuthorityRepositoryError(
                    "request_state_grant_missing",
                    "Pending request state has no exact grant revision for step-up.",
                )
            grant = self._grant_from_state(state, grant_id)
            if grant.revision != grant_revision:
                raise AuthorityRepositoryError("request_state_grant_revised", "Pending request grant was revised.")
            if grant.revoked_at is not None and grant.revoked_at <= now:
                raise AuthorityRepositoryError("request_state_grant_revoked", "Pending request grant was revoked.")
            if now >= grant.expires_at:
                raise AuthorityRepositoryError("request_state_grant_expired", "Pending request grant expired.")
            authorization = StepUpAuthorization(
                grant_id,
                grant_revision,
                str(request_state.get("authorizationFingerprint") or ""),
                str(request_state.get("idempotencyKey") or ""),
                approved_by,
                expires_at,
            )
            step_up_id = f"stepup-{uuid4().hex}"
            state["stepUps"][step_up_id] = authorization.to_dict()
            request_state["stepUpId"] = step_up_id
            request_state["status"] = "step_up_issued"
            self._append_decision_locked(
                state,
                {
                    "auditId": f"audit-{uuid4().hex}",
                    "at": _format_time(now),
                    "kind": "step_up_issued",
                    "reason": "exact_request_step_up",
                    "actionId": request_state["actionId"],
                    "authorizationFingerprint": authorization.authorization_fingerprint,
                    "planFingerprint": request_state["planFingerprint"],
                    "grantId": grant_id,
                    "grantRevision": grant_revision,
                    "dispatchId": "",
                    "requestStateId": request_state_id,
                },
            )
            self._commit_locked(state)
            return step_up_id

    def authorize(
        self,
        plan: ExecutionPlan,
        *,
        risk_class: Any,
        profile: str,
        authority_session_id: str,
        selected_grant_id: str = "",
        idempotency_key: str = "",
        request_state_id: str = "",
        third_party_provider_ids: tuple[str, ...] = (),
    ) -> AuthorizationResult:
        """Reload, evaluate, reserve, audit, and write as one transaction."""

        plan.verify()
        if not authority_session_id.strip():
            raise AuthorityRepositoryError(
                "authority_session_missing",
                "Authority execution requires a trusted session binding.",
            )
        if plan.intent.workspace_id != self.workspace_id:
            raise AuthorityRepositoryError(
                "authority_workspace_mismatch",
                "Execution plan workspace does not match the authority repository.",
            )
        try:
            selected_mode = AuthorityMode(profile)
        except ValueError as exc:
            raise AuthorityRepositoryError("authority_profile_invalid", f"Unknown authority profile: {profile}") from exc
        now = self._clock()
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            resumed = (
                self._request_state_locked(
                    state,
                    request_state_id,
                    plan,
                    authority_session_id,
                    profile,
                    selected_grant_id,
                    idempotency_key,
                    now,
                )
                if request_state_id
                else None
            )
            self._compact_locked(state, now)
            self._validate_idempotency_locked(state, plan, idempotency_key, request_state_id)
            grant_id = str(resumed.get("grantId") or "") if resumed else selected_grant_id
            grant = self._grant_from_state(state, grant_id) if grant_id else None
            if grant is not None and grant.mode is not selected_mode:
                grant = None
            continuation = self._continuation_locked(state, plan, authority_session_id)
            usage = self._budget_usage_locked(state, grant, now) if grant is not None else BudgetUsage()
            step_up = self._matching_step_up_locked(state, grant, plan, idempotency_key, now, resumed)
            evaluation = AuthorityEvaluation(
                plan=plan,
                risk_class=risk_class,
                current_scope=plan.intent.target_envelope.scope_snapshot.for_workspace(self.workspace_id),
                now=now,
                budget_usage=usage,
                third_party_provider_ids=third_party_provider_ids,
                idempotency_key=idempotency_key,
                step_up=step_up,
                continuation=continuation,
            )
            decision = evaluate_authority(grant, evaluation)
            if isinstance(decision, Allow):
                result = self._reserve_allow_locked(
                    state,
                    decision,
                    plan,
                    grant,
                    profile,
                    authority_session_id,
                    idempotency_key,
                    continuation,
                    request_state_id,
                    now,
                )
            else:
                result = self._record_denial_locked(
                    state,
                    decision,
                    plan,
                    grant,
                    profile,
                    authority_session_id,
                    idempotency_key,
                    resumed,
                    now,
                )
            self._compact_locked(state, now)
            self._commit_locked(state)
            return result

    def mark_dispatched(self, receipt: AuthorizationReceipt) -> dict[str, Any]:
        if receipt.continuation:
            return self.inspect_dispatch(receipt.dispatch_id)
        return self.transition_dispatch(receipt.dispatch_id, "dispatched")

    def transition_dispatch(self, dispatch_id: str, requested: str) -> dict[str, Any]:
        if requested not in DISPATCH_STATES:
            raise AuthorityRepositoryError("dispatch_state_invalid", f"Unknown dispatch state: {requested}")
        now = self._clock()
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            dispatch = self._dispatch_locked(state, dispatch_id)
            current = str(dispatch["state"])
            if current == requested:
                return json.loads(json.dumps(dispatch))
            if requested not in _TRANSITIONS[current]:
                raise DispatchTransitionError(dispatch_id, current, requested)
            dispatch["state"] = requested
            dispatch["updatedAt"] = _format_time(now)
            dispatch["revision"] = int(dispatch.get("revision", 0)) + 1
            if requested in _TERMINAL_DISPATCH_STATES:
                dispatch["completedAt"] = _format_time(now)
                self._release_active_locked(state, dispatch)
            self._append_decision_locked(
                state,
                {
                    "auditId": f"audit-{uuid4().hex}",
                    "at": _format_time(now),
                    "kind": "dispatch_transition",
                    "reason": requested,
                    "actionId": dispatch["actionId"],
                    "planFingerprint": dispatch["planFingerprint"],
                    "grantId": dispatch["grantId"],
                    "grantRevision": dispatch["grantRevision"],
                    "dispatchId": dispatch_id,
                },
            )
            self._commit_locked(state)
            return json.loads(json.dumps(dispatch))

    def bind_background_job(self, receipt: AuthorizationReceipt, job_id: str) -> dict[str, Any]:
        """Bind a dispatched ledger entry to the sealed durable job record."""

        record = background_jobs.snapshot_record(job_id)
        if str(record.get("workspaceId") or "") != self.workspace_id:
            raise AuthorityRepositoryError("job_workspace_mismatch", "Job workspace differs from dispatch workspace.")
        serialized_plan = record.get("executionPlan")
        if not isinstance(serialized_plan, Mapping):
            raise AuthorityRepositoryError("job_plan_missing", "Background job has no sealed execution plan.")
        job_plan = ExecutionPlan.from_dict(serialized_plan)
        lineage = job_plan.intent.lineage
        if lineage.parent_plan_fingerprint != receipt.plan_fingerprint:
            raise AuthorityRepositoryError(
                "job_parent_plan_mismatch",
                "Background job does not descend from the authorized dispatch plan.",
            )
        finalizer_effects = record.get("finalizerEffects")
        if not isinstance(finalizer_effects, Mapping):
            raise AuthorityRepositoryError("job_effects_missing", "Background job has no sealed finalizer effects.")
        binding = {
            "jobId": job_id,
            "jobRevision": int(record.get("revision") or 1),
            "parentPlanFingerprint": job_plan.plan_fingerprint,
            "handler": lineage.handler,
            "bindingFingerprint": lineage.binding_fingerprint,
            "effects": EffectEnvelope.from_dict(finalizer_effects).to_dict(),
            "localOutputs": [item.to_dict() for item in job_plan.intent.local_outputs],
        }
        if not binding["handler"] or not binding["bindingFingerprint"]:
            raise AuthorityRepositoryError("job_binding_missing", "Background job continuation is not sealed.")
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            dispatch = self._dispatch_locked(state, receipt.dispatch_id)
            if dispatch["state"] != "dispatched":
                raise DispatchTransitionError(receipt.dispatch_id, str(dispatch["state"]), "bind_job")
            if dispatch["planFingerprint"] != receipt.plan_fingerprint:
                raise AuthorityRepositoryError("dispatch_plan_mismatch", "Receipt plan differs from dispatch truth.")
            dispatch["continuation"] = binding
            dispatch["updatedAt"] = _format_time(self._clock())
            dispatch["revision"] = int(dispatch.get("revision", 0)) + 1
            self._commit_locked(state)
        return binding

    def adopt_legacy_job(
        self,
        job_id: str,
        grant_id: str,
        *,
        operator_id: str,
        authority_session_id: str,
    ) -> dict[str, Any]:
        """Explicitly adopt one pre-Phase-2 job without inventing a new dispatch."""

        now = self._clock()
        if not authority_session_id.strip():
            raise AuthorityRepositoryError("authority_session_missing", "Legacy adoption requires a session binding.")
        record = background_jobs.snapshot_record(job_id)
        if str(record.get("workspaceId") or "") != self.workspace_id:
            raise AuthorityRepositoryError("job_workspace_mismatch", "Legacy job belongs to another workspace.")
        serialized_plan = record.get("executionPlan")
        if not isinstance(serialized_plan, Mapping):
            raise AuthorityRepositoryError("job_plan_missing", "Legacy job has no execution plan to adopt.")
        job_plan = ExecutionPlan.from_dict(serialized_plan)
        finalizer_effects = record.get("finalizerEffects")
        if not isinstance(finalizer_effects, Mapping):
            raise AuthorityRepositoryError("job_effects_missing", "Legacy job has no finalizer effect envelope.")
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            if any(
                isinstance(item.get("continuation"), Mapping)
                and item["continuation"].get("jobId") == job_id
                for item in state["dispatches"].values()
            ):
                raise AuthorityRepositoryError("job_already_adopted", "Legacy job already has authority dispatch truth.")
            grant = self._grant_from_state(state, grant_id)
            decision = evaluate_authority(
                grant,
                AuthorityEvaluation(
                    plan=job_plan,
                    risk_class="high",
                    current_scope=job_plan.intent.target_envelope.scope_snapshot.for_workspace(self.workspace_id),
                    now=now,
                    budget_usage=self._budget_usage_locked(state, grant, now),
                    budget_demand=BudgetDemand(0, 0, 0),
                ),
            )
            if not isinstance(decision, Allow):
                raise AuthorityRepositoryError(
                    "legacy_job_not_covered",
                    f"Legacy job adoption is not covered: {decision.reason}",
                )
            lifecycle = {
                "queued": "dispatched",
                "running": "dispatched",
                "completed": "succeeded",
                "failed": "failed",
                "timed_out": "failed",
                "canceled": "failed",
            }.get(str(record.get("status")), "unknown")
            dispatch_id = f"dispatch-{uuid4().hex}"
            lineage = job_plan.intent.lineage
            state["dispatches"][dispatch_id] = {
                "dispatchId": dispatch_id,
                "revision": 1,
                "workspaceId": self.workspace_id,
                "actionId": job_plan.action_id,
                "planFingerprint": job_plan.plan_fingerprint,
                "grantId": grant.grant_id,
                "grantRevision": grant.revision,
                "profile": str(grant.mode),
                "authoritySessionId": authority_session_id,
                "state": lifecycle,
                "idempotencyKey": "",
                "priorDispatchId": "",
                "createdAt": _format_time(now),
                "updatedAt": _format_time(now),
                "completedAt": _format_time(now) if lifecycle in _TERMINAL_DISPATCH_STATES else "",
                "budgetDemand": BudgetDemand(0, 0, 0).to_dict(),
                "activeReleased": True,
                "continuation": {
                    "jobId": job_id,
                    "jobRevision": int(record.get("revision") or 1),
                    "parentPlanFingerprint": job_plan.plan_fingerprint,
                    "handler": lineage.handler,
                    "bindingFingerprint": lineage.binding_fingerprint,
                    "effects": EffectEnvelope.from_dict(finalizer_effects).to_dict(),
                    "localOutputs": [item.to_dict() for item in job_plan.intent.local_outputs],
                },
                "reconciliation": {
                    "resolution": "legacy_job_adopted",
                    "operatorId": operator_id,
                    "at": _format_time(now),
                },
                "adoptedLegacy": True,
            }
            self._append_decision_locked(
                state,
                {
                    "auditId": f"audit-{uuid4().hex}",
                    "at": _format_time(now),
                    "kind": "legacy_job_adopted",
                    "reason": "explicit_operator_adoption",
                    "actionId": job_plan.action_id,
                    "planFingerprint": job_plan.plan_fingerprint,
                    "grantId": grant.grant_id,
                    "grantRevision": grant.revision,
                    "dispatchId": dispatch_id,
                },
            )
            self._commit_locked(state)
            return json.loads(json.dumps(state["dispatches"][dispatch_id]))

    def inspect_dispatch(self, dispatch_id: str) -> dict[str, Any]:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            return json.loads(json.dumps(self._dispatch_locked(state, dispatch_id)))

    def inspect_request_state(self, request_state_id: str) -> dict[str, Any]:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            request_state = self._pending_request_state_locked(state, request_state_id, self._clock())
            return json.loads(json.dumps(request_state))

    def list_request_states(self) -> tuple[dict[str, Any], ...]:
        """List unexpired pending authority requests for the trusted operator plane."""

        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            now = self._clock()
            values = [
                json.loads(json.dumps(value))
                for value in state["requestStates"].values()
                if _parse_time(value["expiresAt"]) > now and not value.get("resumedDispatchId")
            ]
            return tuple(sorted(values, key=lambda item: str(item.get("createdAt") or "")))

    def resume_request_binding(
        self,
        request_state_id: str,
        *,
        authority_session_id: str,
        action_id: str,
    ) -> dict[str, Any]:
        """Return trusted execution identity before a protocol retry is planned."""

        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            request_state = self._pending_request_state_locked(state, request_state_id, self._clock())
            required = {
                "authorizationFingerprint",
                "correlationId",
                "idempotencyKey",
                "profile",
                "grantRevision",
            }
            if not required.issubset(request_state):
                raise AuthorityRepositoryError(
                    "request_state_legacy_unbound",
                    "Opaque request state predates canonical authorization binding and cannot be resumed.",
                )
            if (
                request_state.get("workspaceId") != self.workspace_id
                or request_state.get("authoritySessionId") != authority_session_id
                or request_state.get("actionId") != action_id
            ):
                raise AuthorityRepositoryError(
                    "request_state_mismatch",
                    "Opaque request state does not match this workspace, session, and action.",
                )
            return {
                "requestStateId": request_state_id,
                "workspaceId": request_state["workspaceId"],
                "actionId": request_state["actionId"],
                "correlationId": request_state["correlationId"],
                "idempotencyKey": request_state["idempotencyKey"],
                "profile": request_state["profile"],
                "grantId": request_state["grantId"],
                "grantRevision": request_state["grantRevision"],
                "authorizationFingerprint": request_state["authorizationFingerprint"],
                "planFingerprint": request_state["planFingerprint"],
                "expiresAt": request_state["expiresAt"],
            }

    def list_dispatches(self) -> tuple[dict[str, Any], ...]:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            return tuple(json.loads(json.dumps(item)) for item in state["dispatches"].values())

    def reconcile_unknown(self, dispatch_id: str, resolution: str, *, operator_id: str) -> dict[str, Any]:
        if resolution not in {"succeeded", "failed", "cancelled"}:
            raise AuthorityRepositoryError("reconciliation_invalid", "Resolution must be succeeded, failed, or cancelled.")
        now = self._clock()
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            dispatch = self._dispatch_locked(state, dispatch_id)
            if dispatch["state"] != "unknown":
                raise AuthorityRepositoryError("reconciliation_not_required", "Dispatch is not in unknown state.")
            dispatch["reconciliation"] = {
                "resolution": resolution,
                "operatorId": operator_id,
                "at": _format_time(now),
            }
            dispatch["updatedAt"] = _format_time(now)
            dispatch["revision"] = int(dispatch.get("revision", 0)) + 1
            state["reconciliations"][dispatch_id] = dispatch["reconciliation"]
            self._append_decision_locked(
                state,
                {
                    "auditId": f"audit-{uuid4().hex}",
                    "at": _format_time(now),
                    "kind": "dispatch_reconciled",
                    "reason": resolution,
                    "actionId": dispatch["actionId"],
                    "planFingerprint": dispatch["planFingerprint"],
                    "grantId": dispatch["grantId"],
                    "grantRevision": dispatch["grantRevision"],
                    "dispatchId": dispatch_id,
                },
            )
            self._commit_locked(state)
            return json.loads(json.dumps(dispatch))

    def budget_usage(self, grant_id: str) -> BudgetUsage:
        with workspace.workspace_lock(self.workspace_id):
            state = self._read_locked()
            grant = self._grant_from_state(state, grant_id)
            return self._budget_usage_locked(state, grant, self._clock())

    def _state_from_bytes(self, raw: str) -> dict[str, Any]:
        try:
            state = json.loads(raw)
        except (TypeError, json.JSONDecodeError) as exc:
            raise AuthorityRepositoryError(
                "authority_state_corrupt",
                f"Authority state is corrupt and was preserved at {self.path}.",
            ) from exc
        if not isinstance(state, dict) or state.get("schemaVersion") != SCHEMA_VERSION:
            raise AuthorityRepositoryError(
                "authority_schema_unsupported",
                f"Authority state schema is unsupported and was preserved at {self.path}.",
            )
        expected = {"revision", "grants", "stepUps", "requestStates", "budgetWindows", "decisions", "dispatches", "reconciliations"}
        if not expected.issubset(state) or not all(isinstance(state[key], dict) for key in expected - {"revision", "decisions"}):
            raise AuthorityRepositoryError(
                "authority_state_corrupt",
                f"Authority state structure is invalid and was preserved at {self.path}.",
            )
        if not isinstance(state["revision"], int) or not isinstance(state["decisions"], list):
            raise AuthorityRepositoryError(
                "authority_state_corrupt",
                f"Authority state structure is invalid and was preserved at {self.path}.",
            )
        return state

    def _read_locked(self) -> dict[str, Any]:
        if not self.path.exists():
            return _initial_state()
        try:
            return self._state_from_bytes(self.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AuthorityRepositoryError("authority_state_unreadable", f"Cannot read authority state: {self.path}") from exc

    def _commit_locked(self, state: dict[str, Any]) -> None:
        state["revision"] = int(state["revision"]) + 1
        atomic_io.atomic_write_text(
            self.path,
            json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            mode=0o600,
            fsync=True,
        )

    @staticmethod
    def _check_revision(state: Mapping[str, Any], expected: int | None) -> None:
        if expected is not None and int(state["revision"]) != expected:
            raise AuthorityRevisionConflict(expected, int(state["revision"]))

    @staticmethod
    def _grant_from_state(state: Mapping[str, Any], grant_id: str, revision: int | None = None) -> AuthorityGrant:
        try:
            entry = state["grants"][grant_id]
            selected = int(entry["currentRevision"]) if revision is None else int(revision)
            return AuthorityGrant.from_dict(entry["revisions"][str(selected)])
        except KeyError as exc:
            raise AuthorityRepositoryError("grant_not_found", f"Unknown Authority Grant: {grant_id}") from exc

    @staticmethod
    def _dispatch_locked(state: Mapping[str, Any], dispatch_id: str) -> dict[str, Any]:
        try:
            dispatch = state["dispatches"][dispatch_id]
        except KeyError as exc:
            raise AuthorityRepositoryError("dispatch_not_found", f"Unknown dispatch: {dispatch_id}") from exc
        if not isinstance(dispatch, dict) or dispatch.get("state") not in DISPATCH_STATES:
            raise AuthorityRepositoryError("dispatch_state_corrupt", f"Dispatch state is invalid: {dispatch_id}")
        return dispatch

    @staticmethod
    def _pending_request_state_locked(
        state: Mapping[str, Any],
        request_state_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        try:
            request_state = state["requestStates"][request_state_id]
        except KeyError as exc:
            raise AuthorityRepositoryError("request_state_not_found", "Opaque request state is unknown.") from exc
        if not isinstance(request_state, dict):
            raise AuthorityRepositoryError("request_state_corrupt", "Opaque request state is invalid.")
        if _parse_time(request_state["expiresAt"]) <= now:
            raise AuthorityRepositoryError("request_state_expired", "Opaque request state has expired.")
        if request_state.get("resumedDispatchId"):
            raise AuthorityRepositoryError("request_state_replayed", "Opaque request state was already consumed.")
        return request_state

    def _request_state_locked(
        self,
        state: Mapping[str, Any],
        request_state_id: str,
        plan: ExecutionPlan,
        authority_session_id: str,
        profile: str,
        selected_grant_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> Mapping[str, Any]:
        request_state = self._pending_request_state_locked(state, request_state_id, now)
        required = {
            "authorizationFingerprint",
            "correlationId",
            "idempotencyKey",
            "profile",
            "grantRevision",
        }
        if not required.issubset(request_state):
            raise AuthorityRepositoryError(
                "request_state_legacy_unbound",
                "Opaque request state predates canonical authorization binding and cannot be resumed.",
            )
        if (
            request_state.get("workspaceId") != self.workspace_id
            or request_state.get("authoritySessionId") != authority_session_id
            or request_state.get("actionId") != plan.action_id
            or request_state.get("authorizationFingerprint") != plan.authorization_fingerprint
            or request_state.get("planFingerprint") != plan.plan_fingerprint
            or request_state.get("correlationId") != plan.correlation_id
            or request_state.get("idempotencyKey") != idempotency_key
            or request_state.get("profile") != profile
            or (selected_grant_id and request_state.get("grantId") != selected_grant_id)
        ):
            raise AuthorityRepositoryError("request_state_mismatch", "Opaque request state does not match this exact plan.")
        grant_id = str(request_state.get("grantId") or "")
        if grant_id:
            grant = self._grant_from_state(state, grant_id)
            if grant.revoked_at is not None and grant.revoked_at <= now:
                raise AuthorityRepositoryError("request_state_grant_revoked", "Opaque request state grant was revoked.")
            if grant.revision != int(request_state.get("grantRevision") or 0):
                raise AuthorityRepositoryError("request_state_grant_revised", "Opaque request state grant was revised.")
        return request_state

    def _matching_step_up_locked(
        self,
        state: Mapping[str, Any],
        grant: AuthorityGrant | None,
        plan: ExecutionPlan,
        idempotency_key: str,
        now: datetime,
        request_state: Mapping[str, Any] | None = None,
    ) -> StepUpAuthorization | None:
        if grant is None:
            return None
        step_up_id = str((request_state or {}).get("stepUpId") or "")
        candidates = (
            (state["stepUps"].get(step_up_id),)
            if request_state is not None
            else tuple(state["stepUps"].values())
        )
        for value in candidates:
            if not isinstance(value, Mapping):
                continue
            try:
                candidate = StepUpAuthorization.from_dict(value)
            except (KeyError, TypeError, ValueError):
                continue
            if candidate.covers(grant, plan, idempotency_key, now):
                return candidate
        return None

    def _budget_usage_locked(self, state: dict[str, Any], grant: AuthorityGrant, now: datetime) -> BudgetUsage:
        window = state["budgetWindows"].setdefault(
            grant.grant_id,
            {
                "grantRevision": grant.revision,
                "dispatchesUsed": 0,
                "windowStartedAt": _format_time(now),
                "dispatchWindowUsed": 0,
                "activeDispatches": 0,
            },
        )
        if int(window.get("grantRevision", 0)) != grant.revision:
            # Grant revision changes authority dimensions, not already consumed
            # dispatch truth. Carry usage forward so revision cannot reset a
            # ceiling or forget an active dispatch.
            window["grantRevision"] = grant.revision
        seconds = grant.budgets.dispatch_rate_window_seconds
        if seconds is not None and now >= _parse_time(window["windowStartedAt"]) + timedelta(seconds=seconds):
            window["windowStartedAt"] = _format_time(now)
            window["dispatchWindowUsed"] = 0
        return BudgetUsage(
            int(window["dispatchesUsed"]),
            int(window["dispatchWindowUsed"]),
            int(window["activeDispatches"]),
        )

    def _continuation_locked(
        self,
        state: Mapping[str, Any],
        plan: ExecutionPlan,
        authority_session_id: str,
    ) -> ContinuationAuthorization | None:
        if plan.intent.lineage.kind != "job_status":
            return None
        lineage = plan.intent.lineage
        matches = [
            item
            for item in state["dispatches"].values()
            if isinstance(item, Mapping)
            and item.get("workspaceId") == self.workspace_id
            and item.get("authoritySessionId") == authority_session_id
            and isinstance(item.get("continuation"), Mapping)
            and item["continuation"].get("jobId") == lineage.job_id
        ]
        if len(matches) != 1:
            return None
        dispatch = matches[0]
        if dispatch.get("state") not in {"dispatched", "succeeded", "failed", "unknown"}:
            return None
        binding = dispatch["continuation"]
        try:
            job = background_jobs.snapshot_record(lineage.job_id)
            job_plan = ExecutionPlan.from_dict(job["executionPlan"])
            if (
                str(job.get("workspaceId") or "") != self.workspace_id
                or job_plan.plan_fingerprint != binding["parentPlanFingerprint"]
                or (
                    not dispatch.get("adoptedLegacy")
                    and job_plan.intent.lineage.parent_plan_fingerprint != dispatch["planFingerprint"]
                )
                or job_plan.intent.lineage.handler != binding["handler"]
                or job_plan.intent.lineage.binding_fingerprint != binding["bindingFingerprint"]
            ):
                return None
            sealed_finalizer_effects = EffectEnvelope.from_dict(binding["effects"])
            if not sealed_finalizer_effects.permits(plan.effects):
                return None
            lifecycle = {
                "queued": "running",
                "running": "running",
                "completed": "succeeded",
                "failed": "failed",
                "timed_out": "failed",
                "canceled": "failed",
            }.get(str(job.get("status")), "unknown")
            return ContinuationAuthorization(
                dispatch_id=str(dispatch["dispatchId"]),
                origin_action_id=str(dispatch["actionId"]),
                workspace_id=self.workspace_id,
                grant_id=str(dispatch["grantId"]),
                grant_revision=int(dispatch["grantRevision"]),
                dispatch_plan_fingerprint=str(dispatch["planFingerprint"]),
                parent_plan_fingerprint=str(binding["parentPlanFingerprint"]),
                job_id=lineage.job_id,
                job_revision=int(job.get("revision") or 1),
                handler=str(binding["handler"]),
                binding_fingerprint=str(binding["bindingFingerprint"]),
                effects=plan.effects,
                local_outputs=tuple(job_plan.intent.local_outputs),
                lifecycle_state=lifecycle,
            )
        except (KeyError, TypeError, ValueError, McpError, AuthorityRepositoryError):
            return None

    def _reserve_allow_locked(
        self,
        state: dict[str, Any],
        decision: Allow,
        plan: ExecutionPlan,
        grant: AuthorityGrant | None,
        profile: str,
        authority_session_id: str,
        idempotency_key: str,
        continuation: ContinuationAuthorization | None,
        request_state_id: str,
        now: datetime,
    ) -> AuthorizationResult:
        if not decision.grant_id or decision.grant_revision < 1:
            raise AuthorityRepositoryError("authority_identity_missing", "Allow lacks durable grant identity.")
        if continuation is not None:
            dispatch_id = continuation.dispatch_id
            receipt = AuthorizationReceipt(
                "grant",
                profile,
                authority_session_id,
                self.workspace_id,
                plan.action_id,
                plan.plan_fingerprint,
                decision.grant_id,
                decision.grant_revision,
                dispatch_id,
                str(decision.reason),
                True,
            )
        else:
            if grant is None:
                raise AuthorityRepositoryError("grant_not_found", "A new dispatch requires an active grant.")
            prior = self._prior_idempotent_dispatch_locked(state, plan, idempotency_key)
            if prior is not None and prior["state"] in {"authorized", "dispatched", "unknown"}:
                raise AuthorityRepositoryError(
                    "dispatch_reconciliation_required",
                    "An existing dispatch with this idempotency key is unresolved and will not be replayed.",
                )
            if prior is not None and plan.effects.replay_safety not in {
                "pure_read",
                "idempotent_write",
                "idempotent_control",
            }:
                raise AuthorityRepositoryError(
                    "dispatch_not_idempotent",
                    "This action is not explicitly idempotent and cannot use automatic retry.",
                )
            dispatch_id = f"dispatch-{uuid4().hex}"
            dispatch = {
                "dispatchId": dispatch_id,
                "revision": 1,
                "workspaceId": self.workspace_id,
                "actionId": plan.action_id,
                "authorizationFingerprint": plan.authorization_fingerprint,
                "planFingerprint": plan.plan_fingerprint,
                "correlationId": plan.correlation_id,
                "grantId": decision.grant_id,
                "grantRevision": decision.grant_revision,
                "profile": profile,
                "authoritySessionId": authority_session_id,
                "state": "authorized",
                "idempotencyKey": idempotency_key,
                "priorDispatchId": str(prior["dispatchId"]) if prior is not None else "",
                "createdAt": _format_time(now),
                "updatedAt": _format_time(now),
                "completedAt": "",
                "budgetDemand": decision.budget_demand.to_dict(),
                "activeReleased": False,
                "continuation": None,
                "reconciliation": None,
            }
            state["dispatches"][dispatch_id] = dispatch
            if request_state_id:
                request_state = state["requestStates"][request_state_id]
                request_state["status"] = "consumed"
                request_state["resumedDispatchId"] = dispatch_id
                request_state["consumedAt"] = _format_time(now)
            window = state["budgetWindows"][grant.grant_id]
            window["dispatchesUsed"] += decision.budget_demand.dispatch_units
            window["dispatchWindowUsed"] += decision.budget_demand.dispatch_rate_units
            window["activeDispatches"] += decision.budget_demand.active_dispatch_units
            receipt = AuthorizationReceipt(
                "grant",
                profile,
                authority_session_id,
                self.workspace_id,
                plan.action_id,
                plan.plan_fingerprint,
                decision.grant_id,
                decision.grant_revision,
                dispatch_id,
                str(decision.reason),
                False,
            )
        self._append_decision_locked(
            state,
            {
                "auditId": f"audit-{uuid4().hex}",
                "at": _format_time(now),
                "kind": decision.kind,
                "reason": str(decision.reason),
                "actionId": plan.action_id,
                "authorizationFingerprint": plan.authorization_fingerprint,
                "planFingerprint": plan.plan_fingerprint,
                "correlationId": plan.correlation_id,
                "idempotencyKey": idempotency_key,
                "grantId": decision.grant_id,
                "grantRevision": decision.grant_revision,
                "dispatchId": receipt.dispatch_id,
            },
        )
        return AuthorizationResult(decision, receipt)

    def _record_denial_locked(
        self,
        state: dict[str, Any],
        decision: ApprovalRequired | ScopeDenied,
        plan: ExecutionPlan,
        grant: AuthorityGrant | None,
        profile: str,
        authority_session_id: str,
        idempotency_key: str,
        resumed: Mapping[str, Any] | None,
        now: datetime,
    ) -> AuthorizationResult:
        request_state_id = ""
        grant_id = grant.grant_id if grant is not None else ""
        grant_revision = grant.revision if grant is not None else 0
        if isinstance(decision, ApprovalRequired):
            if resumed is not None:
                request_state_id = str(resumed["requestStateId"])
                resumed["reason"] = str(decision.reason)
                resumed["lastEvaluatedAt"] = _format_time(now)
            else:
                request_state_id = f"request-{uuid4().hex}"
                state["requestStates"][request_state_id] = {
                    "requestStateId": request_state_id,
                    "workspaceId": self.workspace_id,
                    "authoritySessionId": authority_session_id,
                    "actionId": plan.action_id,
                    "authorizationFingerprint": plan.authorization_fingerprint,
                    "planFingerprint": plan.plan_fingerprint,
                    "correlationId": plan.correlation_id,
                    "idempotencyKey": idempotency_key,
                    "profile": profile,
                    "grantId": grant_id,
                    "grantRevision": grant_revision,
                    "stepUpId": "",
                    "status": "pending",
                    "resumedDispatchId": "",
                    "reason": str(decision.reason),
                    "createdAt": _format_time(now),
                    "expiresAt": _format_time(now + self._request_state_ttl),
                }
            decision = replace(decision, request_state_id=request_state_id)
        audit = {
            "auditId": f"audit-{uuid4().hex}",
            "at": _format_time(now),
            "kind": decision.kind,
            "reason": str(decision.reason),
            "actionId": plan.action_id,
            "authorizationFingerprint": plan.authorization_fingerprint,
            "planFingerprint": plan.plan_fingerprint,
            "correlationId": plan.correlation_id,
            "idempotencyKey": idempotency_key,
            "grantId": grant_id,
            "grantRevision": grant_revision,
            "dispatchId": "",
            "requestStateId": request_state_id,
            "requirement": decision.requirement.to_dict() if decision.requirement else None,
        }
        self._append_decision_locked(state, audit)
        return AuthorizationResult(decision)

    @staticmethod
    def _validate_idempotency_locked(
        state: Mapping[str, Any],
        plan: ExecutionPlan,
        idempotency_key: str,
        request_state_id: str,
    ) -> None:
        if not idempotency_key:
            return
        authorization_fingerprint = plan.authorization_fingerprint
        for item in state["dispatches"].values():
            if item.get("idempotencyKey") != idempotency_key:
                continue
            stored = str(item.get("authorizationFingerprint") or "")
            if not stored or stored != authorization_fingerprint:
                raise AuthorityRepositoryError(
                    "idempotency_conflict",
                    "Idempotency key is already bound to a different logical request.",
                )
        for key, item in state["requestStates"].items():
            if item.get("idempotencyKey") != idempotency_key:
                continue
            stored = str(item.get("authorizationFingerprint") or "")
            if not stored or stored != authorization_fingerprint:
                raise AuthorityRepositoryError(
                    "idempotency_conflict",
                    "Idempotency key is already bound to a different pending request.",
                )
            if not item.get("resumedDispatchId") and key != request_state_id:
                raise AuthorityRepositoryError(
                    "request_state_required",
                    "This logical request already has pending server-held state and must resume through it.",
                )

    @staticmethod
    def _prior_idempotent_dispatch_locked(
        state: Mapping[str, Any],
        plan: ExecutionPlan,
        idempotency_key: str,
    ) -> Mapping[str, Any] | None:
        if not idempotency_key:
            return None
        matches = [
            item
            for item in state["dispatches"].values()
            if item.get("idempotencyKey") == idempotency_key
            and item.get("authorizationFingerprint") == plan.authorization_fingerprint
        ]
        if not matches:
            return None
        return sorted(matches, key=lambda item: str(item.get("createdAt")))[-1]

    @staticmethod
    def _release_active_locked(state: dict[str, Any], dispatch: dict[str, Any]) -> None:
        if dispatch.get("activeReleased"):
            return
        demand = int((dispatch.get("budgetDemand") or {}).get("activeDispatchUnits", 0))
        window = state["budgetWindows"].get(dispatch.get("grantId"))
        if isinstance(window, dict):
            window["activeDispatches"] = max(int(window.get("activeDispatches", 0)) - demand, 0)
        dispatch["activeReleased"] = True

    def _compact_locked(self, state: dict[str, Any], now: datetime) -> None:
        state["requestStates"] = {
            key: value
            for key, value in state["requestStates"].items()
            if _parse_time(value["expiresAt"]) > now
        }
        state["stepUps"] = {
            key: value
            for key, value in state["stepUps"].items()
            if _parse_time(value["expiresAt"]) > now
        }
        if len(state["requestStates"]) > self._decision_retention:
            newest = sorted(
                state["requestStates"].items(),
                key=lambda item: str(item[1].get("createdAt", "")),
            )[-self._decision_retention :]
            state["requestStates"] = dict(newest)
        if len(state["decisions"]) > self._decision_retention:
            protected = {
                item["dispatchId"]
                for item in state["dispatches"].values()
                if item.get("state") in {"authorized", "dispatched", "unknown"}
            }
            removable = [item for item in state["decisions"] if item.get("dispatchId") not in protected]
            retained = [item for item in state["decisions"] if item.get("dispatchId") in protected]
            state["decisions"] = (removable[-self._decision_retention :] + retained)[-max(self._decision_retention, len(retained)) :]

    @staticmethod
    def _append_decision_locked(state: dict[str, Any], audit: dict[str, Any]) -> None:
        state["decisions"].append(audit)

    @staticmethod
    def _append_management_audit_locked(
        state: dict[str, Any],
        kind: str,
        grant: AuthorityGrant,
        now: datetime,
    ) -> None:
        state["decisions"].append(
            {
                "auditId": f"audit-{uuid4().hex}",
                "at": _format_time(now),
                "kind": kind,
                "reason": kind,
                "actionId": "",
                "planFingerprint": "",
                "grantId": grant.grant_id,
                "grantRevision": grant.revision,
                "dispatchId": "",
            }
        )
