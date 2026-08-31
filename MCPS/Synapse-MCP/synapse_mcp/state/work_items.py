# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""SQLite-v2 repository for shared operational work items and claim leases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import json
from typing import Any
from uuid import uuid4

from .errors import StateConflictError, StateStoreError
from .migrations import apply_migrations
from .runtime import ActivatedWorkspaceRepository, opaque_matches, opaque_ref


WORK_ITEM_STATUSES = frozenset(
    {"planned", "available", "claimed", "running", "blocked", "completed", "failed", "cancelled"}
)
TERMINAL_WORK_ITEM_STATUSES = frozenset({"completed", "failed", "cancelled"})
ACTIVE_EXECUTION_STATES = frozenset(
    {"planned", "started", "active", "authorized", "dispatched", "pending", "queued", "running", "unknown"}
)
RECONCILIATION_ATTEMPT_STATES = frozenset(
    {"planned", "started", "awaiting_approval", "unknown"}
)
EXECUTION_ATTEMPT_STATES = frozenset(
    {*RECONCILIATION_ATTEMPT_STATES, "succeeded", "failed", "denied"}
)
REFERENCE_TYPES = frozenset(
    {
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
    }
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _decode(value: Any) -> Any:
    return json.loads(str(value))


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    return _utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def _actor_ref(principal_id: str) -> str:
    return opaque_ref(principal_id)


class SQLiteWorkItemRepository:
    """Atomic work-item transitions over one activated workspace repository."""

    def __init__(self, workspace: ActivatedWorkspaceRepository) -> None:
        self.workspace = workspace
        self.workspace_id = workspace.workspace_id

    def create(
        self,
        value: Mapping[str, Any],
        *,
        principal_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        work_item_id = str(value.get("workItemId") or f"work-{uuid4().hex}")
        dependencies = tuple(dict.fromkeys(str(item) for item in value.get("dependencyIds", []) if str(item)))
        parent_id = str(value.get("parentWorkItemId") or "")
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            base_revision = int(value.get("baseWorkspaceRevision", current))
            last_seen_revision = int(value.get("lastSeenWorkspaceRevision", base_revision))
            if base_revision > current or last_seen_revision > current:
                raise StateConflictError(
                    "work_item_revision_future",
                    "Work-item base and last-seen revisions cannot be newer than workspace truth.",
                    details={"currentWorkspaceRevision": current},
                )
            if connection.execute(
                "SELECT 1 FROM work_items WHERE workspace_id=? AND work_item_id=?",
                (self.workspace_id, work_item_id),
            ).fetchone():
                raise StateConflictError(
                    "work_item_identity_conflict",
                    "Work-item identity already exists in this workspace.",
                    details={"workItemId": work_item_id, "workspaceRevision": current},
                )
            self._require_related_items(connection, (*dependencies, parent_id) if parent_id else dependencies)
            dependency_states = self._dependency_states(connection, dependencies)
            status = "available" if all(state == "completed" for state in dependency_states.values()) else "planned"
            revision = current + 1
            connection.execute(
                "INSERT INTO work_items("
                "work_item_id, workspace_id, parent_work_item_id, objective, role, status, exclusive_claim, "
                "required_packs_json, selected_packs_json, target_selectors_json, context_query_json, assignee_json, "
                "completion_contract_json, progress_summary, result_summary, blocker_reason, handoff_reason, "
                "next_recommended_work, unresolved_gaps_json, version, created_workspace_revision, "
                "base_workspace_revision, current_workspace_revision, last_seen_workspace_revision, created_at, updated_at"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    work_item_id,
                    self.workspace_id,
                    parent_id or None,
                    str(value.get("objective") or ""),
                    str(value.get("role") or ""),
                    status,
                    1 if bool(value.get("exclusive", True)) else 0,
                    _json(list(value.get("requiredPacks", []))),
                    _json(list(value.get("selectedPacks", []))),
                    _json(list(value.get("targets", []))),
                    _json(dict(value.get("contextQuery") or {})),
                    _json(dict(value.get("assignee") or {})),
                    _json(dict(value.get("completionContract") or {})),
                    str(value.get("nextRecommendedWork") or ""),
                    _json(list(value.get("unresolvedGaps", []))),
                    revision,
                    base_revision,
                    revision,
                    last_seen_revision,
                    timestamp,
                    timestamp,
                ),
            )
            connection.executemany(
                "INSERT INTO work_item_dependencies(workspace_id, work_item_id, depends_on_work_item_id, created_revision) "
                "VALUES(?, ?, ?, ?)",
                tuple((self.workspace_id, work_item_id, dependency_id, revision) for dependency_id in dependencies),
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.created",
                version=1,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={"dependencies": list(dependencies), "parentWorkItemId": parent_id or None, "status": status},
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "create", {"status": status, "version": 1}),),
                event_type="work_item.created",
                summary=f"Created operational work item {work_item_id}.",
                payload={"workItemId": work_item_id, "status": status, "version": 1},
                actor_ref=_actor_ref(principal_id),
            )
        return self.inspect(work_item_id)

    def inspect(self, work_item_id: str) -> dict[str, Any]:
        with self.workspace.connection_factory.connect() as connection:
            apply_migrations(connection)
            return self._record(connection, work_item_id)

    def list(
        self,
        *,
        statuses: Sequence[str] = (),
        role: str = "",
        worker: str = "",
        parent_work_item_id: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses = ["w.workspace_id=?"]
        parameters: list[Any] = [self.workspace_id]
        if statuses:
            placeholders = ",".join("?" for _item in statuses)
            clauses.append(f"w.status IN ({placeholders})")
            parameters.extend(statuses)
        if role:
            clauses.append("w.role=?")
            parameters.append(role)
        if parent_work_item_id:
            clauses.append("w.parent_work_item_id=?")
            parameters.append(parent_work_item_id)
        if worker:
            clauses.append(
                "EXISTS(SELECT 1 FROM work_item_claims c WHERE c.workspace_id=w.workspace_id "
                "AND c.work_item_id=w.work_item_id AND c.worker_label=? AND c.state='active')"
            )
            parameters.append(worker)
        parameters.append(max(1, min(int(limit), 100)))
        with self.workspace.connection_factory.connect() as connection:
            apply_migrations(connection)
            identifiers = [
                str(row[0])
                for row in connection.execute(
                    "SELECT w.work_item_id FROM work_items w WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY w.updated_at DESC, w.work_item_id LIMIT ?",
                    tuple(parameters),
                )
            ]
            return [self._record(connection, identity) for identity in identifiers]

    def claim(
        self,
        work_item_id: str,
        *,
        expected_version: int,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        worker: str,
        lease_seconds: int,
        reclaim_blocked: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        lease_expires_at = _timestamp(current_time + timedelta(seconds=int(lease_seconds)))
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_version(item, expected_version, current)
            status = str(item[5])
            if status in TERMINAL_WORK_ITEM_STATUSES:
                raise self._conflict("work_item_terminal", "A terminal work item cannot be claimed.", item, current)
            dependencies = self._dependencies(connection, work_item_id)
            states = self._dependency_states(connection, dependencies)
            if any(state != "completed" for state in states.values()):
                raise self._conflict(
                    "work_item_dependencies_incomplete",
                    "Work-item dependencies are not complete.",
                    item,
                    current,
                    extra={"dependencies": states},
                )
            if status == "blocked" and not reclaim_blocked:
                raise self._conflict(
                    "work_item_blocked",
                    "Blocked work requires an explicit reclaimBlocked acknowledgement.",
                    item,
                    current,
                )
            self._expire_claims(connection, work_item_id, current_time, timestamp)
            active = self._active_claim_rows(connection, work_item_id, current_time)
            exclusive = bool(item[6])
            if exclusive and active:
                raise self._conflict(
                    "work_item_already_claimed",
                    "The exclusive work item has an active claimant.",
                    item,
                    current,
                    extra={"activeClaimIds": [str(row[0]) for row in active]},
                )
            claim_id = f"claim-{uuid4().hex}"
            version = int(item[19]) + 1
            revision = current + 1
            connection.execute(
                "INSERT INTO work_item_claims(claim_id, workspace_id, work_item_id, state, principal_ref, "
                "authority_session_ref, agent_run_ref, worker_label, claim_revision, claim_version, heartbeat_at, "
                "lease_expires_at, created_at, updated_at) VALUES(?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    claim_id,
                    self.workspace_id,
                    work_item_id,
                    opaque_ref(principal_id),
                    opaque_ref(authority_session_id),
                    opaque_ref(agent_run_id),
                    worker,
                    revision,
                    version,
                    timestamp,
                    lease_expires_at,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE work_items SET status='claimed', blocker_reason='', version=?, "
                "current_workspace_revision=?, updated_at=? WHERE workspace_id=? AND work_item_id=? AND version=?",
                (version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.claimed",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={"claimId": claim_id, "leaseExpiresAt": lease_expires_at, "worker": worker},
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "update", {"status": "claimed", "version": version}),),
                event_type="work_item.claimed",
                summary=f"Claimed operational work item {work_item_id}.",
                payload={"claimId": claim_id, "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        result = self.inspect(work_item_id)
        result["claimId"] = claim_id
        return result

    def heartbeat(
        self,
        work_item_id: str,
        *,
        claim_id: str,
        expected_version: int,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        expires = _timestamp(current_time + timedelta(seconds=int(lease_seconds)))
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_version(item, expected_version, current)
            self._require_active_status(item, current)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                current_time,
            )
            version = int(item[19]) + 1
            revision = current + 1
            connection.execute(
                "UPDATE work_item_claims SET heartbeat_at=?, lease_expires_at=?, updated_at=? "
                "WHERE workspace_id=? AND claim_id=? AND state='active'",
                (timestamp, expires, timestamp, self.workspace_id, claim_id),
            )
            connection.execute(
                "UPDATE work_items SET version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND version=?",
                (version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.heartbeat",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={"claimId": claim_id, "leaseExpiresAt": expires},
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "update", {"heartbeat": timestamp, "version": version}),),
                event_type="work_item.heartbeat",
                summary=f"Renewed claim lease for {work_item_id}.",
                payload={"claimId": claim_id, "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        return self.inspect(work_item_id)

    def update(
        self,
        work_item_id: str,
        value: Mapping[str, Any],
        *,
        claim_id: str,
        expected_version: int,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        references = tuple(value.get("references", []))
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_version(item, expected_version, current)
            self._require_active_status(item, current)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                current_time,
            )
            last_seen_revision = int(value.get("lastSeenWorkspaceRevision", current))
            if last_seen_revision > current:
                raise self._conflict(
                    "work_item_revision_future",
                    "A work item cannot observe a workspace revision newer than workspace truth.",
                    item,
                    current,
                    extra={"lastSeenWorkspaceRevision": last_seen_revision},
                )
            revision = current + 1
            version = int(item[19]) + 1
            selected_packs = value.get("selectedPacks")
            unresolved_gaps = value.get("unresolvedGaps")
            connection.execute(
                "UPDATE work_items SET status='running', progress_summary=?, selected_packs_json=?, "
                "next_recommended_work=?, unresolved_gaps_json=?, last_seen_workspace_revision=?, version=?, "
                "current_workspace_revision=?, updated_at=? WHERE workspace_id=? AND work_item_id=? AND version=?",
                (
                    str(value.get("progressSummary", item[13])),
                    _json(list(selected_packs)) if selected_packs is not None else str(item[8]),
                    str(value.get("nextRecommendedWork", item[17])),
                    _json(list(unresolved_gaps)) if unresolved_gaps is not None else str(item[18]),
                    last_seen_revision,
                    version,
                    revision,
                    timestamp,
                    self.workspace_id,
                    work_item_id,
                    int(item[19]),
                ),
            )
            for reference in references:
                self._upsert_reference(
                    connection,
                    work_item_id,
                    reference,
                    revision=revision,
                    timestamp=timestamp,
                    validate=True,
                )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.updated",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={
                    "claimId": claim_id,
                    "progressSummary": str(value.get("progressSummary") or ""),
                    "references": [dict(item) for item in references],
                },
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "update", {"status": "running", "version": version}),),
                event_type="work_item.updated",
                summary=f"Updated operational work item {work_item_id}.",
                payload={"claimId": claim_id, "referenceCount": len(references), "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        return self.inspect(work_item_id)

    def transition(
        self,
        work_item_id: str,
        value: Mapping[str, Any],
        *,
        operation: str,
        claim_id: str,
        expected_version: int,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_version(item, expected_version, current)
            self._require_active_status(item, current)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                current_time,
            )
            last_seen_revision = int(value.get("lastSeenWorkspaceRevision", current))
            if last_seen_revision > current:
                raise self._conflict(
                    "work_item_revision_future",
                    "A work item cannot observe a workspace revision newer than workspace truth.",
                    item,
                    current,
                    extra={"lastSeenWorkspaceRevision": last_seen_revision},
                )
            references = tuple(value.get("references", []))
            revision = current + 1
            version = int(item[19]) + 1
            other_active = bool(
                connection.execute(
                    "SELECT 1 FROM work_item_claims WHERE workspace_id=? AND work_item_id=? "
                    "AND claim_id<>? AND state='active' AND lease_expires_at>? LIMIT 1",
                    (self.workspace_id, work_item_id, claim_id, timestamp),
                ).fetchone()
            )
            if operation == "handoff":
                status = str(item[5]) if other_active else self._available_status(connection, work_item_id)
                claim_state = "handed_off"
                event_type = "work_item.handed_off"
                reason = str(value.get("reason") or "")
            elif operation == "release":
                status = str(item[5]) if other_active else self._available_status(connection, work_item_id)
                claim_state = "released"
                event_type = "work_item.released"
                reason = str(value.get("reason") or "")
            elif operation == "block":
                status = "blocked"
                claim_state = "released"
                event_type = "work_item.blocked"
                reason = str(value.get("reason") or "")
            elif operation == "complete":
                status = str(value.get("status") or "completed")
                if status not in TERMINAL_WORK_ITEM_STATUSES:
                    raise StateStoreError("work_item_status_invalid", "Completion status must be completed, failed, or cancelled.")
                claim_state = "completed"
                event_type = f"work_item.{status}"
                reason = str(value.get("reason") or "")
            else:
                raise StateStoreError("work_item_operation_invalid", "Unknown work-item transition.")
            for reference in references:
                self._upsert_reference(
                    connection,
                    work_item_id,
                    reference,
                    revision=revision,
                    timestamp=timestamp,
                    validate=True,
                )
            assignee = value.get("assignee")
            gaps = value.get("unresolvedGaps")
            connection.execute(
                "UPDATE work_items SET status=?, assignee_json=?, progress_summary=?, result_summary=?, blocker_reason=?, "
                "handoff_reason=?, next_recommended_work=?, unresolved_gaps_json=?, last_seen_workspace_revision=?, "
                "version=?, current_workspace_revision=?, updated_at=? WHERE workspace_id=? AND work_item_id=? AND version=?",
                (
                    status,
                    _json(dict(assignee)) if assignee is not None else str(item[11]),
                    str(value.get("progressSummary", item[13])),
                    str(value.get("resultSummary", item[14])),
                    reason if operation == "block" else "",
                    reason if operation == "handoff" else "",
                    str(value.get("nextRecommendedWork", item[17])),
                    _json(list(gaps)) if gaps is not None else str(item[18]),
                    last_seen_revision,
                    version,
                    revision,
                    timestamp,
                    self.workspace_id,
                    work_item_id,
                    int(item[19]),
                ),
            )
            connection.execute(
                "UPDATE work_item_claims SET state=?, released_at=?, updated_at=? "
                "WHERE workspace_id=? AND claim_id=? AND state='active'",
                (claim_state, timestamp, timestamp, self.workspace_id, claim_id),
            )
            if status in TERMINAL_WORK_ITEM_STATUSES or status == "blocked":
                connection.execute(
                    "UPDATE work_item_claims SET state='superseded', released_at=?, updated_at=? "
                    "WHERE workspace_id=? AND work_item_id=? AND claim_id<>? AND state='active'",
                    (timestamp, timestamp, self.workspace_id, work_item_id, claim_id),
                )
            payload = {
                "activeOrUnknownExecution": self._active_execution(connection, work_item_id),
                "claimId": claim_id,
                "completedWork": str(value.get("completedWork") or value.get("resultSummary") or ""),
                "outstandingWork": str(value.get("outstandingWork") or value.get("nextRecommendedWork") or ""),
                "reason": reason,
                "references": [dict(item) for item in references],
                "status": status,
            }
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type=event_type,
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload=payload,
                timestamp=timestamp,
            )
            changes: list[tuple[str, str, str, Any]] = [
                ("work_item", work_item_id, "update", {"status": status, "version": version})
            ]
            if status == "completed":
                changes.extend(self._unlock_dependents(connection, work_item_id, revision, timestamp))
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=tuple(changes),
                event_type=event_type,
                summary=f"Transitioned operational work item {work_item_id} to {status}.",
                payload={"claimId": claim_id, "status": status, "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        return self.inspect(work_item_id)

    def recover(
        self,
        *,
        principal_id: str,
        work_item_id: str = "",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        recovered: list[str] = []
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            parameters: list[Any] = [self.workspace_id, timestamp]
            clause = ""
            if work_item_id:
                clause = " AND c.work_item_id=?"
                parameters.append(work_item_id)
            stale_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT c.work_item_id FROM work_item_claims c "
                    "WHERE c.workspace_id=? AND c.state='active' AND c.lease_expires_at<=?" + clause,
                    tuple(parameters),
                )
            ]
            if not stale_ids:
                return {"recoveredWorkItemIds": [], "workspaceRevision": current}
            revision = current + 1
            changes: list[tuple[str, str, str, Any]] = []
            for identity in stale_ids:
                item = self._item_row(connection, identity)
                self._expire_claims(connection, identity, current_time, timestamp)
                live_claims = self._active_claim_rows(connection, identity, current_time)
                if str(item[5]) not in {"claimed", "running"}:
                    continue
                version = int(item[19]) + 1
                status = str(item[5]) if live_claims else self._available_status(connection, identity)
                connection.execute(
                    "UPDATE work_items SET status=?, version=?, current_workspace_revision=?, updated_at=? "
                    "WHERE workspace_id=? AND work_item_id=? AND version=?",
                    (
                        status,
                        version,
                        revision,
                        timestamp,
                        self.workspace_id,
                        identity,
                        int(item[19]),
                    ),
                )
                active_execution = self._active_execution(connection, identity)
                self._event(
                    connection,
                    work_item_id=identity,
                    event_type="work_item.recovered",
                    version=version,
                    actor_ref=_actor_ref(principal_id),
                    revision=revision,
                    payload={
                        "activeOrUnknownExecution": active_execution,
                        "automaticReplay": False,
                        "reconciliationRequired": bool(active_execution),
                        "remainingActiveClaims": len(live_claims),
                        "status": status,
                    },
                    timestamp=timestamp,
                )
                recovered.append(identity)
                changes.append(("work_item", identity, "update", {"recovered": True, "version": version}))
            if not changes:
                return {"recoveredWorkItemIds": [], "workspaceRevision": current}
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=tuple(changes),
                event_type="work_item.recovered",
                summary=f"Recovered {len(recovered)} stale operational work item(s).",
                payload={"automaticReplay": False, "workItemIds": recovered},
                actor_ref=_actor_ref(principal_id),
            )
        return {"recoveredWorkItemIds": recovered, "workspaceRevision": revision}

    def validate_claim(
        self,
        work_item_id: str,
        claim_id: str,
        *,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        with self.workspace.connection_factory.connect() as connection:
            apply_migrations(connection)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                _utc(now),
            )
            return self._record(connection, work_item_id)

    def bind_execution_attempt(
        self,
        work_item_id: str,
        *,
        claim_id: str,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        action_id: str,
        replay_safety: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Bind one durable attempt before dispatch while its claim is valid."""

        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        if not idempotency_key:
            raise StateStoreError(
                "work_item_execution_idempotency_required",
                "A bound work execution requires an idempotency identity.",
            )
        key_ref = opaque_ref(idempotency_key)
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_active_status(item, current)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                current_time,
            )
            prior = connection.execute(
                "SELECT execution_attempt_id, state FROM work_item_execution_attempts "
                "WHERE workspace_id=? AND work_item_id=? AND action_id=? AND idempotency_key_ref=?",
                (self.workspace_id, work_item_id, action_id, key_ref),
            ).fetchone()
            if prior is not None:
                raise self._conflict(
                    "work_item_execution_reconciliation_required",
                    "This work execution is already bound and cannot be replayed automatically.",
                    item,
                    current,
                    extra={"executionReference": str(prior[0]), "executionState": str(prior[1])},
                )
            unresolved = connection.execute(
                "SELECT execution_attempt_id, state FROM work_item_execution_attempts "
                "WHERE workspace_id=? AND work_item_id=? AND state IN ('planned','started','awaiting_approval','unknown') "
                "ORDER BY created_revision, execution_attempt_id LIMIT 1",
                (self.workspace_id, work_item_id),
            ).fetchone()
            if unresolved is not None:
                raise self._conflict(
                    "work_item_execution_reconciliation_required",
                    "Bound work execution requires reconciliation before another dispatch.",
                    item,
                    current,
                    extra={"executionReference": str(unresolved[0]), "executionState": str(unresolved[1])},
                )
            legacy_unresolved = next(
                (
                    reference
                    for reference in self._references(connection, work_item_id)
                    if str(reference.get("executionState") or "") in ACTIVE_EXECUTION_STATES
                ),
                None,
            )
            if legacy_unresolved is not None:
                raise self._conflict(
                    "work_item_execution_reconciliation_required",
                    "Previously linked execution requires reconciliation before another dispatch.",
                    item,
                    current,
                    extra={
                        "executionReference": str(legacy_unresolved.get("id") or ""),
                        "executionState": str(legacy_unresolved.get("executionState") or "unknown"),
                    },
                )
            execution_reference = f"work-execution-{uuid4().hex}"
            revision = current + 1
            version = int(item[19]) + 1
            connection.execute(
                "INSERT INTO work_item_execution_attempts("
                "execution_attempt_id, workspace_id, work_item_id, claim_id, action_id, idempotency_key_ref, "
                "principal_ref, authority_session_ref, agent_run_ref, replay_safety, state, outcome_kind, "
                "created_revision, updated_revision, created_at, updated_at"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', '', ?, ?, ?, ?)",
                (
                    execution_reference,
                    self.workspace_id,
                    work_item_id,
                    claim_id,
                    action_id,
                    key_ref,
                    opaque_ref(principal_id),
                    opaque_ref(authority_session_id),
                    opaque_ref(agent_run_id),
                    replay_safety,
                    revision,
                    revision,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE work_items SET status='running', version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND version=?",
                (version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._upsert_reference(
                connection,
                work_item_id,
                {"type": "action", "id": action_id, "state": "planned", "replaySafety": replay_safety},
                revision=revision,
                timestamp=timestamp,
                validate=False,
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.execution_bound",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={
                    "automaticReplay": False,
                    "claimId": claim_id,
                    "executionReference": execution_reference,
                    "state": "planned",
                },
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "link", {"executionReference": execution_reference, "version": version}),),
                event_type="work_item.execution_bound",
                summary=f"Bound execution attempt for operational work item {work_item_id}.",
                payload={
                    "automaticReplay": False,
                    "executionReference": execution_reference,
                    "workItemId": work_item_id,
                    "version": version,
                },
                actor_ref=_actor_ref(principal_id),
            )
        result = self.inspect(work_item_id)
        result["executionReference"] = execution_reference
        return result

    def start_execution_attempt(
        self,
        execution_reference: str,
        *,
        principal_id: str,
        authority_session_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Mark a bound attempt started immediately before Registry dispatch."""

        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            attempt = self._execution_attempt_row(connection, execution_reference)
            work_item_id = str(attempt[2])
            item = self._item_row(connection, work_item_id)
            self._require_execution_binding(attempt, principal_id, authority_session_id)
            state = str(attempt[10])
            if state not in {"planned", "awaiting_approval"}:
                raise self._conflict(
                    "work_item_execution_reconciliation_required",
                    "Only a newly bound or explicitly resumed approval attempt may start.",
                    item,
                    current,
                    extra={"executionReference": execution_reference, "executionState": state},
                )
            revision = current + 1
            version = int(item[19]) + 1
            connection.execute(
                "UPDATE work_item_execution_attempts SET state='started', outcome_kind='', updated_revision=?, updated_at=? "
                "WHERE workspace_id=? AND execution_attempt_id=? AND state=?",
                (revision, timestamp, self.workspace_id, execution_reference, state),
            )
            connection.execute(
                "UPDATE work_items SET status='running', version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND version=?",
                (version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._upsert_reference(
                connection,
                work_item_id,
                {"type": "action", "id": str(attempt[4]), "state": "started", "replaySafety": str(attempt[9])},
                revision=revision,
                timestamp=timestamp,
                validate=False,
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.execution_started",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={"automaticReplay": False, "executionReference": execution_reference, "state": "started"},
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "link", {"executionReference": execution_reference, "version": version}),),
                event_type="work_item.execution_started",
                summary=f"Started bound execution for operational work item {work_item_id}.",
                payload={"executionReference": execution_reference, "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        result = self.inspect(work_item_id)
        result["executionReference"] = execution_reference
        return result

    def finalize_execution_attempt(
        self,
        execution_reference: str,
        *,
        principal_id: str,
        authority_session_id: str,
        outcome_kind: str,
        state: str,
        references: Sequence[Mapping[str, Any]],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Finalize by bound attempt identity; the originating lease may be expired."""

        if state not in EXECUTION_ATTEMPT_STATES - {"planned", "started"}:
            raise StateStoreError("work_item_execution_state_invalid", "Execution finalization state is invalid.")
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            attempt = self._execution_attempt_row(connection, execution_reference)
            work_item_id = str(attempt[2])
            item = self._item_row(connection, work_item_id)
            self._require_execution_binding(attempt, principal_id, authority_session_id)
            prior_state = str(attempt[10])
            if prior_state != "started":
                raise self._conflict(
                    "work_item_execution_finalization_conflict",
                    "Execution attempt is not awaiting result finalization.",
                    item,
                    current,
                    extra={"executionReference": execution_reference, "executionState": prior_state},
                )
            revision = current + 1
            version = int(item[19]) + 1
            for reference in references:
                self._upsert_reference(
                    connection,
                    work_item_id,
                    reference,
                    revision=revision,
                    timestamp=timestamp,
                    validate=False,
                )
            connection.execute(
                "UPDATE work_item_execution_attempts SET state=?, outcome_kind=?, updated_revision=?, updated_at=? "
                "WHERE workspace_id=? AND execution_attempt_id=? AND state='started'",
                (state, outcome_kind, revision, timestamp, self.workspace_id, execution_reference),
            )
            if str(item[5]) in TERMINAL_WORK_ITEM_STATUSES or str(item[5]) == "blocked":
                status = str(item[5])
            elif self._active_claim_rows(connection, work_item_id, current_time):
                status = "running"
            else:
                status = self._available_status(connection, work_item_id)
            connection.execute(
                "UPDATE work_items SET status=?, version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND version=?",
                (status, version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type="work_item.execution_finalized",
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={
                    "automaticReplay": False,
                    "executionReference": execution_reference,
                    "outcomeKind": outcome_kind,
                    "references": [dict(item) for item in references],
                    "state": state,
                },
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "link", {"executionReference": execution_reference, "version": version}),),
                event_type="work_item.execution_finalized",
                summary=f"Finalized bound execution for operational work item {work_item_id}.",
                payload={
                    "executionReference": execution_reference,
                    "outcomeKind": outcome_kind,
                    "workItemId": work_item_id,
                    "version": version,
                },
                actor_ref=_actor_ref(principal_id),
            )
        result = self.inspect(work_item_id)
        result["executionReference"] = execution_reference
        return result

    def link_execution(
        self,
        work_item_id: str,
        *,
        claim_id: str,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        references: Sequence[Mapping[str, Any]],
        event_type: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _utc(now)
        timestamp = _timestamp(current_time)
        with self.workspace.transaction() as connection:
            current = self.workspace._workspace_revision(connection)
            item = self._item_row(connection, work_item_id)
            self._require_active_status(item, current)
            self._require_active_claim(
                connection,
                work_item_id,
                claim_id,
                principal_id,
                authority_session_id,
                agent_run_id,
                current_time,
            )
            revision = current + 1
            version = int(item[19]) + 1
            for reference in references:
                self._upsert_reference(
                    connection,
                    work_item_id,
                    reference,
                    revision=revision,
                    timestamp=timestamp,
                    validate=False,
                )
            connection.execute(
                "UPDATE work_items SET status='running', version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND version=?",
                (version, revision, timestamp, self.workspace_id, work_item_id, int(item[19])),
            )
            self._event(
                connection,
                work_item_id=work_item_id,
                event_type=event_type,
                version=version,
                actor_ref=_actor_ref(principal_id),
                revision=revision,
                payload={"automaticReplay": False, "claimId": claim_id, "references": [dict(item) for item in references]},
                timestamp=timestamp,
            )
            self.workspace._finish_revision(
                connection,
                current=current,
                changes=(("work_item", work_item_id, "link", {"referenceCount": len(references), "version": version}),),
                event_type=event_type,
                summary=f"Linked execution state to operational work item {work_item_id}.",
                payload={"claimId": claim_id, "workItemId": work_item_id, "version": version},
                actor_ref=_actor_ref(principal_id),
            )
        return self.inspect(work_item_id)

    def execution_references(self, *, idempotency_key: str, result: Any) -> list[dict[str, Any]]:
        references: list[dict[str, Any]] = []
        with self.workspace.connection_factory.connect() as connection:
            apply_migrations(connection)
            dispatch = connection.execute(
                "SELECT dispatch_id, action_id, state FROM action_dispatches "
                "WHERE workspace_id=? AND idempotency_key=? ORDER BY updated_revision DESC LIMIT 1",
                (self.workspace_id, opaque_ref(idempotency_key)),
            ).fetchone()
            if dispatch:
                references.extend(
                    (
                        {"type": "action", "id": str(dispatch[1]), "state": str(dispatch[2])},
                        {"type": "dispatch", "id": str(dispatch[0]), "state": str(dispatch[2]), "replaySafety": "non_idempotent"},
                    )
                )
                for decision_id, payload_json in connection.execute(
                    "SELECT decision_id, payload_json FROM authority_decisions WHERE workspace_id=? ORDER BY created_revision DESC",
                    (self.workspace_id,),
                ):
                    payload = _decode(payload_json)
                    if str(payload.get("dispatchId") or "") == str(dispatch[0]):
                        references.append({"type": "authority_decision", "id": str(decision_id), "state": str(payload.get("decision") or "recorded")})
                        break
        for job_id in _find_reference_values(result, {"jobId"}):
            references.append({"type": "job", "id": job_id, "state": "running", "replaySafety": "non_idempotent"})
        for evidence_id in _find_reference_values(result, {"evidenceId", "evidenceReference"}):
            references.append({"type": "evidence", "id": evidence_id})
        for artifact_id in _find_reference_values(result, {"artifactId"}):
            references.append({"type": "artifact", "id": artifact_id})
        return _dedupe_references(references)

    def _record(self, connection: Any, work_item_id: str) -> dict[str, Any]:
        item = self._item_row(connection, work_item_id)
        dependencies = self._dependencies(connection, work_item_id)
        dependency_states = self._dependency_states(connection, dependencies)
        claims = [
            {
                "claimId": row[0],
                "state": row[1],
                "worker": row[2],
                "claimRevision": int(row[3]),
                "claimVersion": int(row[4]),
                "heartbeatAt": row[5],
                "leaseExpiresAt": row[6],
                "releasedAt": row[7],
            }
            for row in connection.execute(
                "SELECT claim_id, state, worker_label, claim_revision, claim_version, heartbeat_at, lease_expires_at, released_at "
                "FROM work_item_claims WHERE workspace_id=? AND work_item_id=? ORDER BY created_at, claim_id",
                (self.workspace_id, work_item_id),
            )
        ]
        references = self._references(connection, work_item_id)
        execution_attempts = self._execution_attempts(connection, work_item_id)
        attempt_action_ids = {item["actionId"] for item in execution_attempts}
        active_execution = [
            item
            for item in references
            if str(item.get("executionState") or "") in ACTIVE_EXECUTION_STATES
            and not (item.get("type") == "action" and item.get("id") in attempt_action_ids)
        ] + [
            {
                "type": "execution_attempt",
                "id": item["executionReference"],
                "executionState": item["state"],
                "replaySafety": item["replaySafety"],
            }
            for item in execution_attempts
            if item["state"] in RECONCILIATION_ATTEMPT_STATES
        ]
        handoffs = [
            {
                "eventType": row[0],
                "workItemVersion": int(row[1]),
                "payload": _decode(row[2]),
                "workspaceRevision": int(row[3]),
                "createdAt": row[4],
            }
            for row in connection.execute(
                "SELECT event_type, work_item_version, payload_json, created_revision, created_at FROM work_item_events "
                "WHERE workspace_id=? AND work_item_id=? AND event_type IN "
                "('work_item.handed_off','work_item.released','work_item.blocked','work_item.completed','work_item.failed','work_item.cancelled','work_item.recovered') "
                "ORDER BY created_revision, work_item_event_id",
                (self.workspace_id, work_item_id),
            )
        ]
        return {
            "workItemId": item[0],
            "workspaceId": item[1],
            "parentWorkItemId": item[2],
            "objective": item[3],
            "role": item[4],
            "status": item[5],
            "exclusive": bool(item[6]),
            "requiredPacks": _decode(item[7]),
            "selectedPacks": _decode(item[8]),
            "targets": _decode(item[9]),
            "contextQuery": _decode(item[10]),
            "assignee": _decode(item[11]),
            "completionContract": _decode(item[12]),
            "progressSummary": item[13],
            "resultSummary": item[14],
            "blockerReason": item[15],
            "handoffReason": item[16],
            "nextRecommendedWork": item[17],
            "unresolvedGaps": _decode(item[18]),
            "version": int(item[19]),
            "createdWorkspaceRevision": int(item[20]),
            "baseWorkspaceRevision": int(item[21]),
            "currentWorkspaceRevision": int(item[22]),
            "lastSeenWorkspaceRevision": int(item[23]),
            "createdAt": item[24],
            "updatedAt": item[25],
            "dependencyIds": dependencies,
            "dependencyStates": dependency_states,
            "claims": claims,
            "references": references,
            "executionAttempts": execution_attempts,
            "activeOrUnknownExecution": active_execution,
            "executionReviewRequired": bool(active_execution),
            "handoffs": handoffs,
            "automaticReplay": False,
        }

    def _item_row(self, connection: Any, work_item_id: str) -> Any:
        row = connection.execute(
            "SELECT work_item_id, workspace_id, parent_work_item_id, objective, role, status, exclusive_claim, "
            "required_packs_json, selected_packs_json, target_selectors_json, context_query_json, assignee_json, "
            "completion_contract_json, progress_summary, result_summary, blocker_reason, handoff_reason, "
            "next_recommended_work, unresolved_gaps_json, version, created_workspace_revision, base_workspace_revision, "
            "current_workspace_revision, last_seen_workspace_revision, created_at, updated_at "
            "FROM work_items WHERE workspace_id=? AND work_item_id=?",
            (self.workspace_id, work_item_id),
        ).fetchone()
        if row is None:
            raise StateStoreError(
                "work_item_not_found",
                "Operational work item was not found in the trusted workspace.",
                details={"workItemId": work_item_id},
            )
        return row

    def _execution_attempt_row(self, connection: Any, execution_reference: str) -> Any:
        row = connection.execute(
            "SELECT execution_attempt_id, workspace_id, work_item_id, claim_id, action_id, idempotency_key_ref, "
            "principal_ref, authority_session_ref, agent_run_ref, replay_safety, state, outcome_kind, "
            "created_revision, updated_revision, created_at, updated_at "
            "FROM work_item_execution_attempts WHERE workspace_id=? AND execution_attempt_id=?",
            (self.workspace_id, execution_reference),
        ).fetchone()
        if row is None:
            raise StateStoreError(
                "work_item_execution_not_found",
                "Bound work execution was not found in the trusted workspace.",
                details={"executionReference": execution_reference},
            )
        return row

    def _execution_attempts(self, connection: Any, work_item_id: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in connection.execute(
            "SELECT execution_attempt_id, claim_id, action_id, idempotency_key_ref, replay_safety, state, "
            "outcome_kind, created_revision, updated_revision, created_at, updated_at "
            "FROM work_item_execution_attempts WHERE workspace_id=? AND work_item_id=? "
            "ORDER BY created_revision, execution_attempt_id",
            (self.workspace_id, work_item_id),
        ):
            dispatch = connection.execute(
                "SELECT dispatch_id, state FROM action_dispatches WHERE workspace_id=? AND action_id=? "
                "AND idempotency_key=? ORDER BY updated_revision DESC, dispatch_id LIMIT 1",
                (self.workspace_id, str(row[2]), str(row[3])),
            ).fetchone()
            result.append(
                {
                    "executionReference": str(row[0]),
                    "claimId": str(row[1]),
                    "actionId": str(row[2]),
                    "replaySafety": str(row[4]),
                    "state": str(row[5]),
                    "outcomeKind": str(row[6]),
                    "dispatchId": str(dispatch[0]) if dispatch else "",
                    "dispatchState": str(dispatch[1]) if dispatch else "",
                    "createdWorkspaceRevision": int(row[7]),
                    "updatedWorkspaceRevision": int(row[8]),
                    "createdAt": str(row[9]),
                    "updatedAt": str(row[10]),
                    "automaticReplay": False,
                }
            )
        return result

    @staticmethod
    def _require_execution_binding(attempt: Any, principal_id: str, authority_session_id: str) -> None:
        if not opaque_matches(str(attempt[6]), principal_id):
            raise StateConflictError(
                "work_item_execution_principal_mismatch",
                "Bound work execution principal does not match the trusted caller.",
            )
        if not opaque_matches(str(attempt[7]), authority_session_id):
            raise StateConflictError(
                "work_item_execution_session_mismatch",
                "Bound work execution authority session does not match the trusted caller.",
            )

    def _require_version(self, item: Any, expected: int, workspace_revision: int) -> None:
        actual = int(item[19])
        if actual != int(expected):
            raise self._conflict(
                "work_item_version_conflict",
                f"Work-item version changed (expected {expected}, actual {actual}).",
                item,
                workspace_revision,
            )

    def _require_active_status(self, item: Any, workspace_revision: int) -> None:
        if str(item[5]) not in {"claimed", "running"}:
            raise self._conflict(
                "work_item_claim_state_invalid",
                "An active claim may mutate only claimed or running work.",
                item,
                workspace_revision,
            )

    @staticmethod
    def _conflict(
        reason: str,
        message: str,
        item: Any,
        workspace_revision: int,
        *,
        extra: Mapping[str, Any] | None = None,
    ) -> StateConflictError:
        return StateConflictError(
            reason,
            message,
            details={
                "currentVersion": int(item[19]),
                "currentWorkspaceRevision": int(workspace_revision),
                "status": str(item[5]),
                "workItemId": str(item[0]),
                **dict(extra or {}),
            },
        )

    def _require_related_items(self, connection: Any, identities: Sequence[str]) -> None:
        for identity in identities:
            if not identity:
                continue
            if not connection.execute(
                "SELECT 1 FROM work_items WHERE workspace_id=? AND work_item_id=?",
                (self.workspace_id, identity),
            ).fetchone():
                raise StateStoreError(
                    "work_item_relation_invalid",
                    "Parent and dependency work items must exist in the same workspace.",
                    details={"relatedWorkItemId": identity},
                )

    def _dependencies(self, connection: Any, work_item_id: str) -> list[str]:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT depends_on_work_item_id FROM work_item_dependencies "
                "WHERE workspace_id=? AND work_item_id=? ORDER BY depends_on_work_item_id",
                (self.workspace_id, work_item_id),
            )
        ]

    def _dependency_states(self, connection: Any, dependencies: Sequence[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for identity in dependencies:
            row = connection.execute(
                "SELECT status FROM work_items WHERE workspace_id=? AND work_item_id=?",
                (self.workspace_id, identity),
            ).fetchone()
            result[identity] = str(row[0]) if row else "missing"
        return result

    def _available_status(self, connection: Any, work_item_id: str) -> str:
        states = self._dependency_states(connection, self._dependencies(connection, work_item_id))
        return "available" if all(state == "completed" for state in states.values()) else "planned"

    def _expire_claims(self, connection: Any, work_item_id: str, now: datetime, timestamp: str) -> None:
        connection.execute(
            "UPDATE work_item_claims SET state='expired', released_at=?, updated_at=? "
            "WHERE workspace_id=? AND work_item_id=? AND state='active' AND lease_expires_at<=?",
            (timestamp, timestamp, self.workspace_id, work_item_id, _timestamp(now)),
        )

    def _active_claim_rows(self, connection: Any, work_item_id: str, now: datetime) -> list[Any]:
        return list(
            connection.execute(
                "SELECT claim_id, principal_ref, authority_session_ref, agent_run_ref, worker_label "
                "FROM work_item_claims WHERE workspace_id=? AND work_item_id=? AND state='active' AND lease_expires_at>? "
                "ORDER BY created_at, claim_id",
                (self.workspace_id, work_item_id, _timestamp(now)),
            )
        )

    def _require_active_claim(
        self,
        connection: Any,
        work_item_id: str,
        claim_id: str,
        principal_id: str,
        authority_session_id: str,
        agent_run_id: str,
        now: datetime,
    ) -> Any:
        row = connection.execute(
            "SELECT state, principal_ref, authority_session_ref, agent_run_ref, lease_expires_at "
            "FROM work_item_claims WHERE workspace_id=? AND work_item_id=? AND claim_id=?",
            (self.workspace_id, work_item_id, claim_id),
        ).fetchone()
        if row is None:
            raise StateConflictError("work_item_claim_invalid", "Work-item claim is unknown or belongs to another workspace.")
        if str(row[0]) != "active" or _parse_timestamp(str(row[4])) <= now:
            raise StateConflictError("work_item_claim_inactive", "Work-item claim is no longer active.")
        if not opaque_matches(str(row[1]), principal_id):
            raise StateConflictError("work_item_claim_principal_mismatch", "Work-item claim principal binding does not match.")
        if not opaque_matches(str(row[2]), authority_session_id):
            raise StateConflictError("work_item_claim_session_mismatch", "Work-item claim session binding does not match.")
        if agent_run_id and not opaque_matches(str(row[3]), agent_run_id):
            raise StateConflictError("work_item_claim_agent_run_mismatch", "Work-item claim agent-run binding does not match.")
        if str(row[3]) != opaque_ref("") and not agent_run_id:
            raise StateConflictError("work_item_claim_agent_run_mismatch", "A trusted agent-run binding is required for this claim.")
        return row

    def _upsert_reference(
        self,
        connection: Any,
        work_item_id: str,
        value: Mapping[str, Any],
        *,
        revision: int,
        timestamp: str,
        validate: bool,
    ) -> None:
        reference_type = str(value.get("type") or "")
        reference_id = str(value.get("id") or "")
        if reference_type not in REFERENCE_TYPES or not reference_id:
            raise StateStoreError("work_item_reference_invalid", "Work-item references require a supported type and non-empty ID.")
        if validate:
            self._validate_reference(connection, reference_type, reference_id)
        connection.execute(
            "INSERT INTO work_item_references(workspace_id, work_item_id, reference_type, reference_id, execution_state, "
            "replay_safety, payload_json, created_revision, updated_revision, created_at, updated_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(workspace_id, work_item_id, reference_type, reference_id) DO UPDATE SET "
            "execution_state=excluded.execution_state, replay_safety=excluded.replay_safety, payload_json=excluded.payload_json, "
            "updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
            (
                self.workspace_id,
                work_item_id,
                reference_type,
                reference_id,
                str(value.get("state") or ""),
                str(value.get("replaySafety") or ""),
                _json(dict(value.get("metadata") or {})),
                revision,
                revision,
                timestamp,
                timestamp,
            ),
        )

    def _validate_reference(self, connection: Any, reference_type: str, reference_id: str) -> None:
        mappings = {
            "action": ("actions", "action_id"),
            "authority_decision": ("authority_decisions", "decision_id"),
            "dispatch": ("action_dispatches", "dispatch_id"),
            "job": ("tasks", "task_id"),
            "evidence": ("evidence", "evidence_id"),
            "artifact": ("artifacts", "artifact_id"),
            "finding": ("findings", "finding_id"),
        }
        if reference_type in {"operation"}:
            return
        if reference_type in {"observation", "candidate"}:
            exists = connection.execute(
                "SELECT 1 FROM entities WHERE workspace_id=? AND entity_id=?",
                (self.workspace_id, reference_id),
            ).fetchone()
        else:
            table, column = mappings[reference_type]
            exists = connection.execute(
                f"SELECT 1 FROM {table} WHERE workspace_id=? AND {column}=?",
                (self.workspace_id, reference_id),
            ).fetchone()
        if not exists:
            raise StateStoreError(
                "work_item_reference_not_found",
                "Work-item reference does not exist in the trusted workspace.",
                details={"referenceId": reference_id, "referenceType": reference_type},
            )

    def _references(self, connection: Any, work_item_id: str) -> list[dict[str, Any]]:
        result = []
        for row in connection.execute(
            "SELECT reference_type, reference_id, execution_state, replay_safety, payload_json, created_revision, updated_revision "
            "FROM work_item_references WHERE workspace_id=? AND work_item_id=? ORDER BY reference_type, reference_id",
            (self.workspace_id, work_item_id),
        ):
            reference_type, reference_id = str(row[0]), str(row[1])
            state = str(row[2])
            if reference_type == "dispatch":
                current = connection.execute(
                    "SELECT state FROM action_dispatches WHERE workspace_id=? AND dispatch_id=?",
                    (self.workspace_id, reference_id),
                ).fetchone()
                state = str(current[0]) if current else state
            elif reference_type == "job":
                current = connection.execute(
                    "SELECT state FROM tasks WHERE workspace_id=? AND task_id=?",
                    (self.workspace_id, reference_id),
                ).fetchone()
                state = str(current[0]) if current else state
            result.append(
                {
                    "type": reference_type,
                    "id": reference_id,
                    "executionState": state,
                    "replaySafety": str(row[3]),
                    "metadata": _decode(row[4]),
                    "createdWorkspaceRevision": int(row[5]),
                    "updatedWorkspaceRevision": int(row[6]),
                }
            )
        return result

    def _active_execution(self, connection: Any, work_item_id: str) -> list[dict[str, Any]]:
        execution_attempts = self._execution_attempts(connection, work_item_id)
        attempt_action_ids = {item["actionId"] for item in execution_attempts}
        references = [
            item
            for item in self._references(connection, work_item_id)
            if str(item.get("executionState") or "") in ACTIVE_EXECUTION_STATES
            and not (item.get("type") == "action" and item.get("id") in attempt_action_ids)
        ]
        attempts = [
            {
                "type": "execution_attempt",
                "id": item["executionReference"],
                "executionState": item["state"],
                "replaySafety": item["replaySafety"],
            }
            for item in execution_attempts
            if item["state"] in RECONCILIATION_ATTEMPT_STATES
        ]
        return references + attempts

    def _unlock_dependents(self, connection: Any, work_item_id: str, revision: int, timestamp: str) -> list[tuple[str, str, str, Any]]:
        changes: list[tuple[str, str, str, Any]] = []
        downstream = [
            str(row[0])
            for row in connection.execute(
                "SELECT work_item_id FROM work_item_dependencies WHERE workspace_id=? AND depends_on_work_item_id=? "
                "ORDER BY work_item_id",
                (self.workspace_id, work_item_id),
            )
        ]
        for identity in downstream:
            item = self._item_row(connection, identity)
            if str(item[5]) != "planned" or self._available_status(connection, identity) != "available":
                continue
            version = int(item[19]) + 1
            connection.execute(
                "UPDATE work_items SET status='available', version=?, current_workspace_revision=?, updated_at=? "
                "WHERE workspace_id=? AND work_item_id=? AND status='planned' AND version=?",
                (version, revision, timestamp, self.workspace_id, identity, int(item[19])),
            )
            self._event(
                connection,
                work_item_id=identity,
                event_type="work_item.dependencies_completed",
                version=version,
                actor_ref="synapse-runtime",
                revision=revision,
                payload={"completedDependencyId": work_item_id, "status": "available"},
                timestamp=timestamp,
            )
            changes.append(("work_item", identity, "update", {"status": "available", "version": version}))
        return changes

    def _event(
        self,
        connection: Any,
        *,
        work_item_id: str,
        event_type: str,
        version: int,
        actor_ref: str,
        revision: int,
        payload: Mapping[str, Any],
        timestamp: str,
    ) -> None:
        connection.execute(
            "INSERT INTO work_item_events(work_item_event_id, workspace_id, work_item_id, event_type, "
            "work_item_version, actor_ref, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"work-event-{uuid4().hex}",
                self.workspace_id,
                work_item_id,
                event_type,
                version,
                actor_ref,
                _json(payload),
                revision,
                timestamp,
            ),
        )


def context_work_items(connection: Any, workspace_id: str) -> tuple[dict[str, Any], ...]:
    """Return work-item context records from the caller's existing WAL snapshot."""

    repository = _SnapshotWorkItemRepository(workspace_id)
    identifiers = [
        str(row[0])
        for row in connection.execute(
            "SELECT work_item_id FROM work_items WHERE workspace_id=? ORDER BY updated_at DESC, work_item_id",
            (workspace_id,),
        )
    ]
    return tuple(repository.record(connection, identity) for identity in identifiers)


class _SnapshotWorkItemRepository:
    """Small read-only decoder used without opening a second connection."""

    def __init__(self, workspace_id: str) -> None:
        self.workspace_id = workspace_id

    def record(self, connection: Any, work_item_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT work_item_id, parent_work_item_id, objective, role, status, exclusive_claim, required_packs_json, "
            "selected_packs_json, target_selectors_json, context_query_json, assignee_json, completion_contract_json, "
            "progress_summary, result_summary, blocker_reason, handoff_reason, next_recommended_work, unresolved_gaps_json, "
            "version, created_workspace_revision, base_workspace_revision, current_workspace_revision, "
            "last_seen_workspace_revision, created_at, updated_at FROM work_items WHERE workspace_id=? AND work_item_id=?",
            (self.workspace_id, work_item_id),
        ).fetchone()
        dependencies = [
            {"workItemId": item[0], "status": item[1]}
            for item in connection.execute(
                "SELECT d.depends_on_work_item_id, w.status FROM work_item_dependencies d "
                "JOIN work_items w ON w.workspace_id=d.workspace_id AND w.work_item_id=d.depends_on_work_item_id "
                "WHERE d.workspace_id=? AND d.work_item_id=? ORDER BY d.depends_on_work_item_id",
                (self.workspace_id, work_item_id),
            )
        ]
        references = [
            {
                "type": item[0],
                "id": item[1],
                "executionState": item[2],
                "replaySafety": item[3],
                "metadata": _decode(item[4]),
            }
            for item in connection.execute(
                "SELECT reference_type, reference_id, execution_state, replay_safety, payload_json "
                "FROM work_item_references WHERE workspace_id=? AND work_item_id=? ORDER BY reference_type, reference_id",
                (self.workspace_id, work_item_id),
            )
        ]
        for reference in references:
            if reference["type"] == "dispatch":
                current = connection.execute(
                    "SELECT state FROM action_dispatches WHERE workspace_id=? AND dispatch_id=?",
                    (self.workspace_id, reference["id"]),
                ).fetchone()
                if current:
                    reference["executionState"] = str(current[0])
            elif reference["type"] == "job":
                current = connection.execute(
                    "SELECT state FROM tasks WHERE workspace_id=? AND task_id=?",
                    (self.workspace_id, reference["id"]),
                ).fetchone()
                if current:
                    reference["executionState"] = str(current[0])
        execution_attempts = [
            {
                "executionReference": str(item[0]),
                "claimId": str(item[1]),
                "actionId": str(item[2]),
                "replaySafety": str(item[3]),
                "state": str(item[4]),
                "outcomeKind": str(item[5]),
                "createdWorkspaceRevision": int(item[6]),
                "updatedWorkspaceRevision": int(item[7]),
                "automaticReplay": False,
            }
            for item in connection.execute(
                "SELECT execution_attempt_id, claim_id, action_id, replay_safety, state, outcome_kind, "
                "created_revision, updated_revision FROM work_item_execution_attempts "
                "WHERE workspace_id=? AND work_item_id=? ORDER BY created_revision, execution_attempt_id",
                (self.workspace_id, work_item_id),
            )
        ]
        attempt_action_ids = {item["actionId"] for item in execution_attempts}
        claims = [
            {
                "claimId": item[0],
                "state": item[1],
                "worker": item[2],
                "heartbeatAt": item[3],
                "leaseExpiresAt": item[4],
            }
            for item in connection.execute(
                "SELECT claim_id, state, worker_label, heartbeat_at, lease_expires_at FROM work_item_claims "
                "WHERE workspace_id=? AND work_item_id=? ORDER BY created_at, claim_id",
                (self.workspace_id, work_item_id),
            )
        ]
        handoffs = [
            _decode(item[0])
            for item in connection.execute(
                "SELECT payload_json FROM work_item_events WHERE workspace_id=? AND work_item_id=? "
                "AND event_type IN ('work_item.handed_off','work_item.released','work_item.recovered') "
                "ORDER BY created_revision, work_item_event_id",
                (self.workspace_id, work_item_id),
            )
        ]
        return {
            "workItemId": row[0],
            "parentWorkItemId": row[1],
            "objective": row[2],
            "role": row[3],
            "status": row[4],
            "exclusive": bool(row[5]),
            "requiredPacks": _decode(row[6]),
            "selectedPacks": _decode(row[7]),
            "targets": _decode(row[8]),
            "contextQuery": _decode(row[9]),
            "assignee": _decode(row[10]),
            "completionContract": _decode(row[11]),
            "progressSummary": row[12],
            "resultSummary": row[13],
            "blockerReason": row[14],
            "handoffReason": row[15],
            "nextRecommendedWork": row[16],
            "unresolvedGaps": _decode(row[17]),
            "version": int(row[18]),
            "createdWorkspaceRevision": int(row[19]),
            "baseWorkspaceRevision": int(row[20]),
            "currentWorkspaceRevision": int(row[21]),
            "lastSeenWorkspaceRevision": int(row[22]),
            "createdAt": row[23],
            "updatedAt": row[24],
            "dependencies": dependencies,
            "claims": claims,
            "references": references,
            "executionAttempts": execution_attempts,
            "activeOrUnknownExecution": [
                item
                for item in references
                if str(item.get("executionState") or "") in ACTIVE_EXECUTION_STATES
                and not (item.get("type") == "action" and item.get("id") in attempt_action_ids)
            ] + [
                {
                    "type": "execution_attempt",
                    "id": item["executionReference"],
                    "executionState": item["state"],
                    "replaySafety": item["replaySafety"],
                }
                for item in execution_attempts
                if item["state"] in RECONCILIATION_ATTEMPT_STATES
            ],
            "handoffs": handoffs,
            "automaticReplay": False,
        }


def _find_reference_values(value: Any, names: set[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key) in names and isinstance(child, str) and child:
                found.append(child)
            else:
                found.extend(_find_reference_values(child, names))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_find_reference_values(child, names))
    return list(dict.fromkeys(found))


def _dedupe_references(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for value in values:
        result[(str(value.get("type") or ""), str(value.get("id") or ""))] = dict(value)
    return list(result.values())
