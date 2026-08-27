# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed, protocol-independent operational work-item application service."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from synapse_mcp.core import workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository
from synapse_mcp.state.errors import StateSelectionError, StateStoreError
from synapse_mcp.state.selector import selected_store_version

if TYPE_CHECKING:
    from synapse_mcp.app.facade.contracts import FacadeCallContext


def _camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


class WorkItemModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        populate_by_name=True,
        alias_generator=_camel_case,
    )


class WorkItemReference(WorkItemModel):
    type: Literal[
        "action",
        "authority_decision",
        "dispatch",
        "job",
        "evidence",
        "artifact",
        "observation",
        "candidate",
        "finding",
        "operation",
    ]
    id: str = Field(min_length=1, max_length=512)
    state: str = ""
    replay_safety: str = ""
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class WorkItemCreateInput(WorkItemModel):
    work_item_id: str | None = Field(default=None, min_length=1, max_length=512)
    objective: str = Field(min_length=1, max_length=4000)
    role: str = Field(default="", max_length=256)
    parent_work_item_id: str | None = Field(default=None, min_length=1, max_length=512)
    dependency_ids: list[str] = Field(default_factory=list, max_length=100)
    exclusive: bool = True
    required_packs: list[str] = Field(default_factory=list, max_length=100)
    selected_packs: list[str] = Field(default_factory=list, max_length=100)
    targets: list[str] = Field(default_factory=list, max_length=100)
    context_query: dict[str, JsonValue] = Field(default_factory=dict)
    assignee: dict[str, JsonValue] = Field(default_factory=dict)
    completion_contract: dict[str, JsonValue] = Field(default_factory=dict)
    base_workspace_revision: int | None = Field(default=None, ge=0)
    last_seen_workspace_revision: int | None = Field(default=None, ge=0)
    next_recommended_work: str = Field(default="", max_length=4000)
    unresolved_gaps: list[str] = Field(default_factory=list, max_length=100)


class WorkItemClaimInput(WorkItemModel):
    worker: str = Field(default="", max_length=256)
    lease_seconds: int = Field(default=300, ge=15, le=86400)
    reclaim_blocked: bool = False


class WorkItemUpdateInput(WorkItemModel):
    progress_summary: str | None = Field(default=None, max_length=8000)
    selected_packs: list[str] | None = Field(default=None, max_length=100)
    references: list[WorkItemReference] = Field(default_factory=list, max_length=500)
    next_recommended_work: str | None = Field(default=None, max_length=4000)
    unresolved_gaps: list[str] | None = Field(default=None, max_length=100)
    last_seen_workspace_revision: int | None = Field(default=None, ge=0)


class WorkItemTransitionInput(WorkItemModel):
    reason: str = Field(default="", max_length=4000)
    progress_summary: str | None = Field(default=None, max_length=8000)
    result_summary: str | None = Field(default=None, max_length=8000)
    completed_work: str = Field(default="", max_length=8000)
    outstanding_work: str = Field(default="", max_length=8000)
    references: list[WorkItemReference] = Field(default_factory=list, max_length=500)
    next_recommended_work: str | None = Field(default=None, max_length=4000)
    unresolved_gaps: list[str] | None = Field(default=None, max_length=100)
    assignee: dict[str, JsonValue] | None = None
    last_seen_workspace_revision: int | None = Field(default=None, ge=0)
    status: Literal["completed", "failed", "cancelled"] = "completed"


class WorkItemListInput(WorkItemModel):
    statuses: list[
        Literal["planned", "available", "claimed", "running", "blocked", "completed", "failed", "cancelled"]
    ] = Field(default_factory=list)
    role: str = Field(default="", max_length=256)
    worker: str = Field(default="", max_length=256)
    parent_work_item_id: str = Field(default="", max_length=512)
    limit: int = Field(default=50, ge=1, le=100)


class WorkItemExecutionInput(WorkItemModel):
    """Non-authoritative linkage metadata carried beside canonical action input."""

    work_item_id: str = Field(min_length=1, max_length=512)
    claim_id: str = Field(min_length=1, max_length=512)


class WorkItemService:
    """Coordinate shared work without planning, scheduling, or granting authority."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        repository_factory: Callable[[str], SQLiteWorkItemRepository] | None = None,
    ) -> None:
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.repository_factory = repository_factory or self._repository

    def execute(
        self,
        operation: str,
        *,
        context: FacadeCallContext,
        workspace_id: str,
        work_item_id: str,
        claim_id: str,
        expected_version: int | None,
        worker: str,
        lease_seconds: int,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        trusted_workspace = self._trusted_workspace(context, workspace_id)
        repository = self.repository_factory(trusted_workspace)
        now = self.clock()
        if operation == "work.create":
            value = WorkItemCreateInput.model_validate(payload)
            data = value.model_dump(mode="json", by_alias=True, exclude_none=True)
            return repository.create(data, principal_id=context.principal_id, now=now)
        if operation == "work.list":
            value = WorkItemListInput.model_validate({**dict(payload), **({"worker": worker} if worker else {})})
            items = repository.list(
                statuses=value.statuses,
                role=value.role,
                worker=value.worker,
                parent_work_item_id=value.parent_work_item_id,
                limit=value.limit,
            )
            return {"workItems": items, "count": len(items), "workspaceId": trusted_workspace}
        if operation == "work.inspect":
            self._require_work_item_id(work_item_id)
            return repository.inspect(work_item_id)
        if operation == "work.recover":
            return repository.recover(
                principal_id=context.principal_id,
                work_item_id=work_item_id,
                now=now,
            )
        self._require_work_item_id(work_item_id)
        self._require_version(expected_version)
        if operation == "work.claim":
            value = WorkItemClaimInput.model_validate(
                {**dict(payload), **({"worker": worker} if worker else {}), "leaseSeconds": lease_seconds}
            )
            if not value.worker and not context.agent_run_id:
                raise StateStoreError(
                    "work_item_worker_required",
                    "A worker label is required when the trusted adapter has no agent-run identity.",
                )
            return repository.claim(
                work_item_id,
                expected_version=int(expected_version),
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                agent_run_id=context.agent_run_id,
                worker=value.worker,
                lease_seconds=value.lease_seconds,
                reclaim_blocked=value.reclaim_blocked,
                now=now,
            )
        self._require_claim_id(claim_id)
        if operation == "work.heartbeat":
            return repository.heartbeat(
                work_item_id,
                claim_id=claim_id,
                expected_version=int(expected_version),
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                agent_run_id=context.agent_run_id,
                lease_seconds=lease_seconds,
                now=now,
            )
        if operation == "work.update":
            value = WorkItemUpdateInput.model_validate(payload)
            return repository.update(
                work_item_id,
                value.model_dump(mode="json", by_alias=True, exclude_none=True),
                claim_id=claim_id,
                expected_version=int(expected_version),
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                agent_run_id=context.agent_run_id,
                now=now,
            )
        if operation in {"work.handoff", "work.release", "work.complete", "work.block"}:
            value = WorkItemTransitionInput.model_validate(payload)
            if operation == "work.block" and not value.reason:
                raise StateStoreError("work_item_blocker_required", "Blocking a work item requires a concrete reason.")
            if operation == "work.complete" and not value.result_summary:
                raise StateStoreError("work_item_result_required", "Completing a work item requires a result summary.")
            return repository.transition(
                work_item_id,
                value.model_dump(mode="json", by_alias=True, exclude_none=True),
                operation=operation.removeprefix("work."),
                claim_id=claim_id,
                expected_version=int(expected_version),
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                agent_run_id=context.agent_run_id,
                now=now,
            )
        raise StateStoreError("work_item_operation_invalid", "Unknown operational work-item operation.")

    def inspect_for_context(
        self,
        work_item_id: str,
        *,
        claim_id: str,
        context: FacadeCallContext,
        workspace_id: str,
    ) -> dict[str, Any]:
        trusted_workspace = self._trusted_workspace(context, workspace_id)
        repository = self.repository_factory(trusted_workspace)
        if claim_id:
            return repository.validate_claim(
                work_item_id,
                claim_id,
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                agent_run_id=context.agent_run_id,
                now=self.clock(),
            )
        return repository.inspect(work_item_id)

    def link_execution(
        self,
        value: WorkItemExecutionInput,
        *,
        context: FacadeCallContext,
        action_id: str,
        replay_safety: str,
        idempotency_key: str,
        result: Any = None,
        outcome_kind: str = "planned",
        operation_handle: str = "",
    ) -> dict[str, Any]:
        trusted_workspace = self._trusted_workspace(context, context.workspace_id)
        repository = self.repository_factory(trusted_workspace)
        references: list[dict[str, Any]] = [
            {"type": "action", "id": action_id, "state": outcome_kind, "replaySafety": replay_safety}
        ]
        event_type = "work_item.execution_planned"
        if outcome_kind != "planned":
            references.extend(repository.execution_references(idempotency_key=idempotency_key, result=result))
            if operation_handle:
                references.append({"type": "operation", "id": operation_handle, "state": outcome_kind})
            event_type = "work_item.execution_result"
        return repository.link_execution(
            value.work_item_id,
            claim_id=value.claim_id,
            principal_id=context.principal_id,
            authority_session_id=context.authority_session_id,
            agent_run_id=context.agent_run_id,
            references=references,
            event_type=event_type,
            now=self.clock(),
        )

    @staticmethod
    def _trusted_workspace(context: FacadeCallContext, workspace_id: str) -> str:
        trusted = workspace.normalize_workspace_id(context.workspace_id or workspace_id)
        requested = workspace.normalize_workspace_id(workspace_id or trusted)
        if not trusted or requested != trusted:
            raise StateSelectionError(
                "work_item_workspace_mismatch",
                "Work-item workspace does not match the trusted facade binding.",
            )
        return trusted

    @staticmethod
    def _repository(workspace_id: str) -> SQLiteWorkItemRepository:
        root = workspace.WORKSPACES_DIR / workspace_id
        if selected_store_version(root) != "sqlite-v2":
            raise StateSelectionError(
                "work_items_require_sqlite_v2",
                "Operational work items require an activated SQLite-v2 workspace.",
            )
        return SQLiteWorkItemRepository(ActivatedWorkspaceRepository(workspace_id, root))

    @staticmethod
    def _require_work_item_id(work_item_id: str) -> None:
        if not work_item_id:
            raise StateStoreError("work_item_id_required", "This operation requires workItemId.")

    @staticmethod
    def _require_claim_id(claim_id: str) -> None:
        if not claim_id:
            raise StateStoreError("work_item_claim_required", "This operation requires claimId.")

    @staticmethod
    def _require_version(expected_version: int | None) -> None:
        if expected_version is None:
            raise StateStoreError("work_item_version_required", "This mutation requires expectedVersion.")
