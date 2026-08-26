# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Authoritative runtime repositories for activated SQLite-v2 workspaces."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
from uuid import uuid4

from .backup import online_backup
from .connections import StateConnection
from .contracts import ArtifactRecord, ContextRepositorySnapshot
from .errors import (
    StateBusyError,
    StateCommitUnknownError,
    StateConflictError,
    StateIntegrityError,
    StateStoreError,
)
from .migrations import apply_migrations
from .sqlite_store import SQLiteWorkspaceRepository


_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:@/-]+$")
_OPAQUE_KEYS = {
    "authorizationsessionid",
    "idempotencykey",
    "principalid",
    "requeststateid",
    "stepupid",
    "token",
}
_SECRET_KEYS = {
    "authorization",
    "bearer",
    "cookie",
    "password",
    "privatekey",
    "secret",
    "secretvalue",
}
_COLLECTION_ENTITY_TYPES = {
    "services": "service",
    "endpoints": "endpoint",
    "parameters": "parameter",
    "observations": "observation",
    "pretextCandidates": "pretext_candidate",
    "detectionGaps": "detection_gap",
}


@dataclass(frozen=True, slots=True)
class _CommitReceipt:
    workspace_id: str
    start_revision: int
    intended_revision: int
    audit_event_ids: tuple[str, ...]
    change_count: int


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _decode(value: Any) -> Any:
    return json.loads(str(value))


def _stable_id(prefix: str, *parts: Any) -> str:
    digest = sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _safe_id(value: Any, prefix: str, *identity: Any) -> str:
    text = str(value or "").strip()
    if text and len(text.encode("utf-8")) <= 512 and _IDENTIFIER.fullmatch(text):
        return text
    return _stable_id(prefix, *identity, text)


def opaque_ref(value: str) -> str:
    text = str(value or "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", text):
        return text
    return f"sha256:{sha256(text.encode('utf-8')).hexdigest()}"


def opaque_matches(stored: str, supplied: str) -> bool:
    import hmac

    return hmac.compare_digest(str(stored), opaque_ref(supplied))


def _secure(value: Any, key: str = "") -> Any:
    marker = re.sub(r"[^a-z0-9]", "", key.lower())
    if marker in _OPAQUE_KEYS and isinstance(value, str) and value:
        return opaque_ref(value)
    if marker in _SECRET_KEYS or marker.endswith(("password", "secret", "privatekey")):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(name): _secure(item, str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_secure(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _is_busy(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        code = getattr(current, "sqlite_errorcode", None)
        if code is None:
            code = getattr(current, "result", None)
        if isinstance(code, int) and code & 0xFF in {5, 6}:
            return True
        name = type(current).__name__.lower()
        text = str(current).lower()
        if name in {"busyerror", "lockederror"}:
            return True
        if isinstance(current, sqlite3.OperationalError) and ("locked" in text or "busy" in text):
            return True
        current = current.__cause__ or current.__context__
    return False


class ActivatedWorkspaceRepository(SQLiteWorkspaceRepository):
    """Use-case repositories over one workspace database.

    Every method opens its own connection. The object is therefore safe to
    reconstruct after a worker spawn and never owns a live inherited handle.
    """

    @contextmanager
    def transaction(self) -> Iterator[StateConnection]:
        try:
            with self.connection_factory.connect() as connection:
                apply_migrations(connection)
                try:
                    connection.begin_immediate()
                except Exception as exc:
                    if _is_busy(exc):
                        raise StateBusyError(
                            "state_busy_retryable",
                            "State Store remained busy for the bounded pre-commit wait.",
                        ) from exc
                    raise
                start_revision = self._workspace_revision(connection)
                start_changes = int(connection.execute("SELECT total_changes()").fetchone()[0])
                try:
                    yield connection
                except BaseException:
                    try:
                        connection.rollback()
                    except Exception:
                        pass
                    raise
                else:
                    receipt = self._commit_receipt(connection, start_revision, start_changes)
                    try:
                        connection.commit()
                    except BaseException as exc:
                        try:
                            connection.rollback()
                        except Exception:
                            pass
                        if receipt.change_count > 0 and self._receipt_is_committed(receipt):
                            return
                        raise StateCommitUnknownError(
                            "state_commit_unknown",
                            "State Store commit outcome is ambiguous; reconcile the supplied receipt before retrying.",
                            details={
                                "workspaceId": receipt.workspace_id,
                                "startRevision": receipt.start_revision,
                                "intendedRevision": receipt.intended_revision,
                                "auditEventIds": list(receipt.audit_event_ids),
                                "changeCount": receipt.change_count,
                                "reconciliation": "not_observed",
                            },
                        ) from exc
        except (StateBusyError, StateCommitUnknownError):
            raise
        except Exception as exc:
            if _is_busy(exc):
                raise StateBusyError(
                    "state_busy_retryable",
                    "State Store remained busy before a transaction could begin.",
                ) from exc
            raise

    def _commit_receipt(
        self,
        connection: StateConnection,
        start_revision: int,
        start_changes: int,
    ) -> _CommitReceipt:
        intended_revision = self._workspace_revision(connection)
        audit_event_ids = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT event_id FROM audit_events WHERE workspace_id=? AND revision>? AND revision<=? ORDER BY revision, event_id",
                (self.workspace_id, start_revision, intended_revision),
            )
        )
        end_changes = int(connection.execute("SELECT total_changes()").fetchone()[0])
        return _CommitReceipt(
            workspace_id=self.workspace_id,
            start_revision=start_revision,
            intended_revision=intended_revision,
            audit_event_ids=audit_event_ids,
            change_count=max(end_changes - start_changes, 0),
        )

    def _receipt_is_committed(self, receipt: _CommitReceipt) -> bool:
        if receipt.intended_revision <= receipt.start_revision or not receipt.audit_event_ids:
            return False
        try:
            with self.connection_factory.connect() as connection:
                revision_row = connection.execute(
                    "SELECT revision FROM workspace_revisions WHERE workspace_id=?",
                    (self.workspace_id,),
                ).fetchone()
                if revision_row is None or int(revision_row[0]) < receipt.intended_revision:
                    return False
                placeholders = ",".join("?" for _item in receipt.audit_event_ids)
                rows = list(
                    connection.execute(
                        f"SELECT event_id, revision FROM audit_events WHERE workspace_id=? AND event_id IN ({placeholders})",
                        (self.workspace_id, *receipt.audit_event_ids),
                    )
                )
        except Exception:
            return False
        observed = {str(event_id): int(revision) for event_id, revision in rows}
        return all(
            receipt.start_revision < observed.get(event_id, -1) <= receipt.intended_revision
            for event_id in receipt.audit_event_ids
        )
    def _workspace_revision(self, connection: StateConnection) -> int:
        row = connection.execute(
            "SELECT revision FROM workspace_revisions WHERE workspace_id=?",
            (self.workspace_id,),
        ).fetchone()
        if row is None:
            raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
        return int(row[0])

    def snapshot(self) -> dict[str, Any]:
        value = super().snapshot()
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            value.update(
                {
                    "findings": [
                        _decode(row[0])
                        for row in connection.execute(
                            "SELECT payload_json FROM findings WHERE workspace_id=? ORDER BY finding_id",
                            (self.workspace_id,),
                        )
                    ],
                    "reviews": [
                        {
                            "reviewEventId": row[0],
                            "findingId": row[1],
                            "decision": row[2],
                            "reviewerRef": row[3],
                            "payload": _decode(row[4]),
                        }
                        for row in connection.execute(
                            "SELECT review_event_id, finding_id, decision, reviewer_ref, payload_json FROM review_events WHERE workspace_id=? ORDER BY review_event_id",
                            (self.workspace_id,),
                        )
                    ],
                    "actions": [_decode(row[0]) for row in connection.execute(
                        "SELECT payload_json FROM actions WHERE workspace_id=? ORDER BY action_id",
                        (self.workspace_id,),
                    )],
                    "dispatches": [_decode(row[0]) for row in connection.execute(
                        "SELECT payload_json FROM action_dispatches WHERE workspace_id=? ORDER BY dispatch_id",
                        (self.workspace_id,),
                    )],
                    "tasks": self.list_tasks(),
                    "authority": self.authority_state(connection),
                    "entityEvidence": [
                        {"entityId": row[0], "evidenceId": row[1], "createdRevision": int(row[2])}
                        for row in connection.execute(
                            "SELECT entity_id, evidence_id, created_revision FROM entity_evidence WHERE workspace_id=? ORDER BY entity_id, evidence_id",
                            (self.workspace_id,),
                        )
                    ],
                    "executionResults": [
                        {
                            "resultLinkId": row[0],
                            "actionId": row[1],
                            "dispatchId": row[2],
                            "taskId": row[3],
                            "evidenceId": row[4],
                            "artifactId": row[5],
                            "createdRevision": int(row[6]),
                        }
                        for row in connection.execute(
                            "SELECT result_link_id, action_id, dispatch_id, task_id, evidence_id, artifact_id, created_revision FROM execution_result_links WHERE workspace_id=? ORDER BY result_link_id",
                            (self.workspace_id,),
                        )
                    ],
                }
            )
        return value

    def context_snapshot(self, *, since_revision: int | None = None) -> ContextRepositorySnapshot:
        """Read every compiler input from one WAL snapshot."""

        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            connection.execute("BEGIN")
            try:
                workspace_row = connection.execute(
                    "SELECT workspace_id, organization, notes, created_at, updated_at FROM workspaces WHERE workspace_id=?",
                    (self.workspace_id,),
                ).fetchone()
                if workspace_row is None:
                    raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
                revision = self._workspace_revision(connection)
                earliest_row = connection.execute(
                    "SELECT MIN(revision) FROM change_log WHERE workspace_id=?",
                    (self.workspace_id,),
                ).fetchone()
                earliest = int(earliest_row[0]) if earliest_row and earliest_row[0] is not None else None
                scope_row = connection.execute(
                    "SELECT payload_json FROM scope_snapshots WHERE workspace_id=? ORDER BY created_revision DESC, scope_snapshot_id DESC LIMIT 1",
                    (self.workspace_id,),
                ).fetchone()
                targets = tuple(
                    {
                        "targetId": row[0],
                        "naturalKey": row[1],
                        "kind": row[2],
                        "payload": _decode(row[3]),
                        "createdRevision": int(row[4]),
                        "updatedRevision": int(row[5]),
                    }
                    for row in connection.execute(
                        "SELECT target_id, natural_key, kind, payload_json, created_revision, updated_revision FROM targets WHERE workspace_id=? ORDER BY natural_key, target_id",
                        (self.workspace_id,),
                    )
                )
                entities = tuple(
                    {
                        "entityId": row[0],
                        "targetId": row[1],
                        "entityType": row[2],
                        "naturalKey": row[3],
                        "lifecycle": row[4],
                        "payload": _decode(row[5]),
                        "createdRevision": int(row[6]),
                        "updatedRevision": int(row[7]),
                    }
                    for row in connection.execute(
                        "SELECT entity_id, target_id, entity_type, natural_key, lifecycle, payload_json, created_revision, updated_revision FROM entities WHERE workspace_id=? ORDER BY entity_type, natural_key, entity_id",
                        (self.workspace_id,),
                    )
                )
                relations = tuple(
                    {
                        "relationId": row[0],
                        "sourceEntityId": row[1],
                        "targetEntityId": row[2],
                        "relationType": row[3],
                        "payload": _decode(row[4]),
                        "createdRevision": int(row[5]),
                    }
                    for row in connection.execute(
                        "SELECT relation_id, source_entity_id, target_entity_id, relation_type, payload_json, created_revision FROM entity_relations WHERE workspace_id=? ORDER BY relation_type, relation_id",
                        (self.workspace_id,),
                    )
                )
                findings = tuple(
                    {
                        "findingId": row[0],
                        "targetId": row[1],
                        "naturalKey": row[2],
                        "status": row[3],
                        "severity": row[4],
                        "operatorReviewed": bool(row[5]),
                        "payload": _decode(row[6]),
                        "createdRevision": int(row[7]),
                        "updatedRevision": int(row[8]),
                    }
                    for row in connection.execute(
                        "SELECT finding_id, target_id, natural_key, status, severity, operator_reviewed, payload_json, created_revision, updated_revision FROM findings WHERE workspace_id=? ORDER BY natural_key, finding_id",
                        (self.workspace_id,),
                    )
                )
                evidence = tuple(
                    {
                        "evidenceId": row[0],
                        "targetId": row[1],
                        "summary": row[2],
                        "payload": _decode(row[3]),
                        "createdRevision": int(row[4]),
                    }
                    for row in connection.execute(
                        "SELECT evidence_id, target_id, summary, payload_json, created_revision FROM evidence WHERE workspace_id=? ORDER BY created_revision, evidence_id",
                        (self.workspace_id,),
                    )
                )
                evidence_artifacts = tuple(
                    {
                        "evidenceId": row[0],
                        "artifactId": row[1],
                        "digest": row[2],
                        "size": int(row[3]),
                        "mediaType": row[4],
                        "origin": row[5],
                        "createdRevision": int(row[6]),
                    }
                    for row in connection.execute(
                        "SELECT ea.evidence_id, a.artifact_id, a.digest, a.size, a.media_type, a.origin, ea.created_revision "
                        "FROM evidence_artifacts ea JOIN artifacts a ON a.workspace_id=ea.workspace_id AND a.artifact_id=ea.artifact_id "
                        "WHERE ea.workspace_id=? ORDER BY ea.evidence_id, a.artifact_id",
                        (self.workspace_id,),
                    )
                )
                actions = tuple(
                    {
                        "actionId": row[0],
                        "actionName": row[1],
                        "state": row[2],
                        "payload": _decode(row[3]),
                        "createdRevision": int(row[4]),
                        "updatedRevision": int(row[5]),
                    }
                    for row in connection.execute(
                        "SELECT action_id, action_name, state, payload_json, created_revision, updated_revision FROM actions WHERE workspace_id=? ORDER BY updated_revision DESC, action_id",
                        (self.workspace_id,),
                    )
                )
                dispatches = tuple(
                    {
                        "dispatchId": row[0],
                        "actionId": row[1],
                        "state": row[2],
                        "payload": _decode(row[3]),
                        "createdRevision": int(row[4]),
                        "updatedRevision": int(row[5]),
                    }
                    for row in connection.execute(
                        "SELECT dispatch_id, action_id, state, payload_json, created_revision, updated_revision FROM action_dispatches WHERE workspace_id=? ORDER BY updated_revision DESC, dispatch_id",
                        (self.workspace_id,),
                    )
                )
                tasks = tuple(
                    {
                        "taskId": row[0],
                        "actionId": row[1],
                        "state": row[2],
                        "taskRevision": int(row[3]),
                        "payload": _decode(row[4]),
                        "createdRevision": int(row[5]),
                        "updatedRevision": int(row[6]),
                    }
                    for row in connection.execute(
                        "SELECT task_id, action_id, state, revision, payload_json, created_revision, updated_revision FROM tasks WHERE workspace_id=? ORDER BY updated_revision DESC, task_id",
                        (self.workspace_id,),
                    )
                )
                changes = tuple(
                    {
                        "revision": int(row[0]),
                        "sequence": int(row[1]),
                        "entityType": row[2],
                        "entityId": row[3],
                        "changeKind": row[4],
                        "payload": _decode(row[5]),
                    }
                    for row in connection.execute(
                        "SELECT revision, sequence, entity_type, entity_id, change_kind, payload_json FROM change_log "
                        "WHERE workspace_id=? AND revision>? ORDER BY revision, sequence",
                        (self.workspace_id, int(since_revision or 0)),
                    )
                ) if since_revision is not None else ()
                authority = self.authority_state(connection)
                connection.commit()
            except BaseException:
                try:
                    connection.rollback()
                except Exception:
                    pass
                raise
        return ContextRepositorySnapshot(
            store_version="sqlite-v2",
            workspace_id=self.workspace_id,
            revision=revision,
            earliest_change_revision=earliest,
            workspace={
                "workspaceId": workspace_row[0],
                "organization": workspace_row[1],
                "notes": workspace_row[2],
                "createdAt": workspace_row[3],
                "updatedAt": workspace_row[4],
            },
            scope=_decode(scope_row[0]) if scope_row else {},
            targets=targets,
            entities=entities,
            relations=relations,
            findings=findings,
            evidence=evidence,
            evidence_artifacts=evidence_artifacts,
            actions=actions,
            dispatches=dispatches,
            tasks=tasks,
            authority=authority,
            changes=changes,
        )

    def _finish_revision(
        self,
        connection: StateConnection,
        *,
        current: int,
        changes: Sequence[tuple[str, str, str, Any]],
        event_type: str,
        summary: str,
        payload: Mapping[str, Any] | None = None,
        event_id: str | None = None,
        actor_ref: str = "synapse-runtime",
        fault_injector: Callable[[str], None] | None = None,
    ) -> int:
        revision = current + 1
        now = _now()
        connection.executemany(
            "INSERT INTO change_log(workspace_id, revision, sequence, entity_type, entity_id, change_kind, payload_json, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            tuple(
                (
                    self.workspace_id,
                    revision,
                    sequence,
                    entity_type,
                    entity_id,
                    change_kind,
                    _json(_secure(detail)),
                    now,
                )
                for sequence, (entity_type, entity_id, change_kind, detail) in enumerate(changes)
            ),
        )
        if fault_injector is not None:
            fault_injector("after_change_log")
        connection.execute(
            "INSERT INTO audit_events(event_id, workspace_id, revision, event_type, summary, actor_ref, payload_json, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id or f"audit-{uuid4().hex}",
                self.workspace_id,
                revision,
                event_type,
                summary,
                actor_ref,
                _json(_secure(dict(payload or {}))),
                now,
            ),
        )
        if fault_injector is not None:
            fault_injector("after_audit")
        updated = connection.execute(
            "UPDATE workspace_revisions SET revision=?, updated_at=? WHERE workspace_id=? AND revision=?",
            (revision, now, self.workspace_id, current),
        )
        if getattr(updated, "rowcount", 1) == 0:
            raise StateConflictError("workspace_revision_conflict", "Workspace revision compare-and-swap failed.")
        connection.execute(
            "UPDATE workspaces SET updated_at=? WHERE workspace_id=?",
            (now, self.workspace_id),
        )
        if fault_injector is not None:
            fault_injector("after_revision")
        return revision

    def append_audit(self, event_type: str, summary: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            revision = self._finish_revision(
                connection,
                current=current,
                changes=(("audit", event_type, "create", {}),),
                event_type=event_type,
                summary=summary,
                payload=payload,
            )
        return {"logged": True, "storeVersion": "sqlite-v2", "revision": revision}

    def resolve_migrated_opaque_id(self, source_kind: str, supplied: str) -> str:
        source_ref = opaque_ref(supplied)
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT target_id FROM id_mappings WHERE source_kind=? AND source_id=? ORDER BY migration_run_id DESC LIMIT 1",
                (source_kind, source_ref),
            ).fetchone()
        return str(row[0]) if row else source_ref

    # Workspace, targets, collections, findings, reviews, and evidence.

    def workspace_document(self) -> dict[str, Any]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT workspace_id, organization, notes, created_at, updated_at FROM workspaces WHERE workspace_id=?",
                (self.workspace_id,),
            ).fetchone()
        if row is None:
            return {}
        return {
            "workspaceId": row[0],
            "organization": row[1],
            "notes": row[2],
            "createdAt": row[3],
            "updatedAt": row[4],
        }

    def update_workspace(self, payload: Mapping[str, Any]) -> int:
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            connection.execute(
                "UPDATE workspaces SET organization=?, notes=?, updated_at=? WHERE workspace_id=?",
                (str(payload.get("organization") or ""), str(payload.get("notes") or ""), _now(), self.workspace_id),
            )
            return self._finish_revision(
                connection,
                current=current,
                changes=(("workspace", self.workspace_id, "update", payload),),
                event_type="workspace.update",
                summary=f"Updated workspace {self.workspace_id}.",
                payload=payload,
            )

    def scope_document(self) -> dict[str, Any]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT payload_json FROM scope_snapshots WHERE workspace_id=? ORDER BY created_revision DESC LIMIT 1",
                (self.workspace_id,),
            ).fetchone()
        return _decode(row[0]) if row else {}

    def replace_scope(self, payload: Mapping[str, Any]) -> int:
        digest = sha256(_json(payload).encode("utf-8")).hexdigest()
        scope_id = f"scope-{digest[:24]}"
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            revision = current + 1
            connection.execute(
                "INSERT OR IGNORE INTO scope_snapshots(scope_snapshot_id, workspace_id, digest, payload_json, created_revision, created_at) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (scope_id, self.workspace_id, digest, _json(payload), revision, _now()),
            )
            return self._finish_revision(
                connection,
                current=current,
                changes=(("scope_snapshot", scope_id, "create", payload),),
                event_type="scope.update",
                summary=f"Updated scope snapshot for {self.workspace_id}.",
                payload=payload,
            )

    def target_document(self, natural_key: str) -> dict[str, Any]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT payload_json FROM targets WHERE workspace_id=? AND natural_key=?",
                (self.workspace_id, natural_key),
            ).fetchone()
        return _decode(row[0]) if row else {}

    def target_documents(self) -> list[dict[str, Any]]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            rows = list(connection.execute(
                "SELECT payload_json FROM targets WHERE workspace_id=? ORDER BY natural_key",
                (self.workspace_id,),
            ))
        return [_decode(row[0]) for row in rows]

    def upsert_target(self, natural_key: str, payload: Mapping[str, Any]) -> tuple[bool, int]:
        target_id = _stable_id("target", self.workspace_id, natural_key)
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            existing = connection.execute(
                "SELECT target_id, created_at FROM targets WHERE workspace_id=? AND natural_key=?",
                (self.workspace_id, natural_key),
            ).fetchone()
            created = existing is None
            revision = current + 1
            now = _now()
            if existing is None:
                connection.execute(
                    "INSERT INTO targets(target_id, workspace_id, natural_key, kind, payload_json, created_revision, updated_revision, created_at, updated_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (target_id, self.workspace_id, natural_key, str(payload.get("kind") or "host"), _json(payload), revision, revision, now, now),
                )
            else:
                target_id = str(existing[0])
                connection.execute(
                    "UPDATE targets SET kind=?, payload_json=?, updated_revision=?, updated_at=? WHERE workspace_id=? AND target_id=?",
                    (str(payload.get("kind") or "host"), _json(payload), revision, now, self.workspace_id, target_id),
                )
            committed = self._finish_revision(
                connection,
                current=current,
                changes=(("target", target_id, "create" if created else "update", payload),),
                event_type="workspace.add_target" if created else "workspace.update_target",
                summary=f"{'Added' if created else 'Updated'} target {natural_key}.",
                payload={"target": natural_key},
            )
        return created, committed

    def _target_id(self, connection: StateConnection, natural_key: str) -> str | None:
        row = connection.execute(
            "SELECT target_id FROM targets WHERE workspace_id=? AND natural_key=?",
            (self.workspace_id, natural_key),
        ).fetchone()
        return str(row[0]) if row else None

    def collection(self, target: str, entity_type: str) -> list[dict[str, Any]]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            target_id = self._target_id(connection, target)
            if target_id is None:
                return []
            if entity_type == "findings":
                rows = connection.execute(
                    "SELECT payload_json FROM findings WHERE workspace_id=? AND target_id=? ORDER BY natural_key",
                    (self.workspace_id, target_id),
                )
            elif entity_type == "actions":
                rows = connection.execute(
                    "SELECT payload_json FROM actions WHERE workspace_id=? ORDER BY action_id",
                    (self.workspace_id,),
                )
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM entities WHERE workspace_id=? AND target_id=? AND entity_type=? ORDER BY natural_key",
                    (self.workspace_id, target_id, _COLLECTION_ENTITY_TYPES.get(entity_type, entity_type.removesuffix("s"))),
                )
            return [_decode(row[0]) for row in rows]

    def collection_records(self, target: str, entity_type: str) -> list[tuple[str, dict[str, Any]]]:
        """Return internal row identities with payloads for compatibility merging."""

        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            target_id = self._target_id(connection, target)
            if target_id is None:
                return []
            if entity_type == "findings":
                rows = connection.execute(
                    "SELECT finding_id, payload_json FROM findings WHERE workspace_id=? AND target_id=? ORDER BY natural_key",
                    (self.workspace_id, target_id),
                )
            elif entity_type == "actions":
                rows = connection.execute(
                    "SELECT action_id, payload_json FROM actions WHERE workspace_id=? ORDER BY action_id",
                    (self.workspace_id,),
                )
            else:
                rows = connection.execute(
                    "SELECT entity_id, payload_json FROM entities WHERE workspace_id=? AND target_id=? AND entity_type=? ORDER BY natural_key",
                    (self.workspace_id, target_id, _COLLECTION_ENTITY_TYPES.get(entity_type, entity_type.removesuffix("s"))),
                )
            return [(str(row[0]), _decode(row[1])) for row in rows]

    @staticmethod
    def _natural(item: Mapping[str, Any]) -> str:
        return str(item.get("key") or item.get("id") or item.get("entityId") or sha256(_json(item).encode()).hexdigest())

    def _upsert_collection_rows(
        self,
        connection: StateConnection,
        *,
        target: str,
        entity_type: str,
        items: Sequence[Mapping[str, Any]],
        revision: int,
        evidence_id: str = "",
        row_id_hints: Mapping[str, str] | None = None,
    ) -> tuple[int, list[tuple[str, str, str, Any]]]:
        target_id = self._target_id(connection, target)
        if target_id is None:
            raise StateIntegrityError("target_not_found", "Entity target does not exist in the workspace.")
        created_count = 0
        changes: list[tuple[str, str, str, Any]] = []
        now = _now()
        for raw in items:
            item = dict(raw)
            natural = self._natural(item)
            row_hint = str((row_id_hints or {}).get(natural) or "")
            if entity_type == "findings":
                finding_id = _safe_id(item.get("id") or item.get("key"), "finding", self.workspace_id, target, natural)
                existing = (
                    connection.execute(
                        "SELECT finding_id, payload_json FROM findings WHERE workspace_id=? AND target_id=? AND finding_id=?",
                        (self.workspace_id, target_id, row_hint),
                    ).fetchone()
                    if row_hint
                    else connection.execute(
                        "SELECT finding_id, payload_json FROM findings WHERE workspace_id=? AND target_id=? AND natural_key IN (?, ?) ORDER BY CASE WHEN natural_key=? THEN 0 ELSE 1 END LIMIT 1",
                        (self.workspace_id, target_id, f"{target_id}:{natural}", natural, f"{target_id}:{natural}"),
                    ).fetchone()
                )
                merged = {**(_decode(existing[1]) if existing else {}), **item}
                if existing:
                    finding_id = str(existing[0])
                    connection.execute(
                        "UPDATE findings SET status=?, severity=?, operator_reviewed=?, payload_json=?, updated_revision=?, updated_at=? WHERE workspace_id=? AND finding_id=?",
                        (str(merged.get("status") or "candidate"), str(merged.get("severity") or "info"), int(bool(merged.get("operatorReviewed"))), _json(merged), revision, now, self.workspace_id, finding_id),
                    )
                else:
                    connection.execute(
                        "INSERT INTO findings(finding_id, workspace_id, target_id, natural_key, status, severity, operator_reviewed, payload_json, created_revision, updated_revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (finding_id, self.workspace_id, target_id, f"{target_id}:{natural}", str(merged.get("status") or "candidate"), str(merged.get("severity") or "info"), int(bool(merged.get("operatorReviewed"))), _json(merged), revision, revision, now, now),
                    )
                if merged.get("operatorReviewed"):
                    review_id = _stable_id("review", self.workspace_id, finding_id, merged.get("updatedAt") or revision)
                    connection.execute(
                        "INSERT OR IGNORE INTO review_events(review_event_id, workspace_id, finding_id, decision, reviewer_ref, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                        (review_id, self.workspace_id, finding_id, str(merged.get("status") or "reviewed"), str(merged.get("reviewedBy") or "operator"), _json({"source": "runtime"}), revision, now),
                    )
                row_id = finding_id
            elif entity_type == "actions":
                row_id = _safe_id(item.get("actionId") or item.get("id") or natural, "action", self.workspace_id, natural)
                if row_hint:
                    row_id = row_hint
                existing = connection.execute(
                    "SELECT payload_json FROM actions WHERE workspace_id=? AND action_id=?",
                    (self.workspace_id, row_id),
                ).fetchone()
                merged = {**(_decode(existing[0]) if existing else {}), **item}
                connection.execute(
                    "INSERT INTO actions(action_id, workspace_id, action_name, state, plan_fingerprint, payload_json, created_revision, updated_revision, created_at, updated_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(action_id) DO UPDATE SET state=excluded.state, plan_fingerprint=excluded.plan_fingerprint, payload_json=excluded.payload_json, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
                    (row_id, self.workspace_id, str(merged.get("tool") or merged.get("type") or "action"), str(merged.get("status") or merged.get("state") or "recorded"), str(merged.get("planFingerprint") or ""), _json(merged), revision, revision, now, now),
                )
            else:
                singular = _COLLECTION_ENTITY_TYPES.get(entity_type, entity_type.removesuffix("s"))
                db_natural = f"{target_id}:{natural}"
                existing = (
                    connection.execute(
                        "SELECT entity_id, payload_json FROM entities WHERE workspace_id=? AND target_id=? AND entity_type=? AND entity_id=?",
                        (self.workspace_id, target_id, singular, row_hint),
                    ).fetchone()
                    if row_hint
                    else connection.execute(
                        "SELECT entity_id, payload_json FROM entities WHERE workspace_id=? AND target_id=? AND entity_type=? AND natural_key IN (?, ?) ORDER BY CASE WHEN natural_key=? THEN 0 ELSE 1 END LIMIT 1",
                        (self.workspace_id, target_id, singular, db_natural, natural, db_natural),
                    ).fetchone()
                )
                row_id = str(existing[0]) if existing else _stable_id("entity", self.workspace_id, target_id, singular, natural)
                merged = {**(_decode(existing[1]) if existing else {}), **item}
                prior_evidence = set(merged.get("evidenceIds") or []) if isinstance(merged.get("evidenceIds"), list) else set()
                incoming_evidence = set(item.get("evidenceIds") or []) if isinstance(item.get("evidenceIds"), list) else set()
                if evidence_id:
                    incoming_evidence.add(evidence_id)
                if prior_evidence or incoming_evidence:
                    merged["evidenceIds"] = sorted(prior_evidence | incoming_evidence)
                if existing:
                    connection.execute(
                        "UPDATE entities SET lifecycle=?, payload_json=?, updated_revision=?, updated_at=? WHERE workspace_id=? AND entity_id=?",
                        (str(merged.get("status") or "observed"), _json(merged), revision, now, self.workspace_id, row_id),
                    )
                else:
                    connection.execute(
                        "INSERT INTO entities(entity_id, workspace_id, target_id, entity_type, natural_key, lifecycle, payload_json, created_revision, updated_revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (row_id, self.workspace_id, target_id, singular, db_natural, str(merged.get("status") or "observed"), _json(merged), revision, revision, now, now),
                    )
                for linked_evidence in sorted(prior_evidence | incoming_evidence):
                    if connection.execute(
                        "SELECT 1 FROM evidence WHERE workspace_id=? AND evidence_id=?",
                        (self.workspace_id, linked_evidence),
                    ).fetchone():
                        connection.execute(
                            "INSERT OR IGNORE INTO entity_evidence(workspace_id, entity_id, evidence_id, created_revision) VALUES(?, ?, ?, ?)",
                            (self.workspace_id, row_id, linked_evidence, revision),
                        )
            created = existing is None
            created_count += int(created)
            changes.append((entity_type, row_id, "create" if created else "update", {"naturalKey": natural}))
        return created_count, changes

    def replace_collection(self, target: str, entity_type: str, items: Sequence[Mapping[str, Any]]) -> int:
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            _, changes = self._upsert_collection_rows(
                connection,
                target=target,
                entity_type=entity_type,
                items=items,
                revision=current + 1,
            )
            target_id = self._target_id(connection, target)
            if target_id is not None:
                changes.extend(self._sync_relations(connection, target_id, current + 1))
            if not changes:
                return current
            return self._finish_revision(
                connection,
                current=current,
                changes=changes,
                event_type="workspace.collection_update",
                summary=f"Updated {entity_type} for {target}.",
                payload={"target": target, "entityType": entity_type, "count": len(items)},
            )

    def _sync_relations(
        self,
        connection: StateConnection,
        target_id: str,
        revision: int,
    ) -> list[tuple[str, str, str, Any]]:
        rows = list(connection.execute(
            "SELECT entity_id, payload_json FROM entities WHERE workspace_id=? AND target_id=?",
            (self.workspace_id, target_id),
        ))
        references: dict[str, str] = {}
        payloads: dict[str, dict[str, Any]] = {}
        source_ids = [str(row[0]) for row in rows]
        for entity_id, payload_json in rows:
            payload = _decode(payload_json)
            payloads[str(entity_id)] = payload
            for reference in (entity_id, payload.get("entityId"), payload.get("id"), payload.get("key")):
                if reference:
                    references[str(reference)] = str(entity_id)
        for source_id in source_ids:
            connection.execute(
                "DELETE FROM entity_relations WHERE workspace_id=? AND source_entity_id=?",
                (self.workspace_id, source_id),
            )
        changes: list[tuple[str, str, str, Any]] = []
        now = _now()
        for source_id, payload in payloads.items():
            relations = payload.get("relations")
            for relation in relations if isinstance(relations, list) else []:
                if not isinstance(relation, Mapping):
                    continue
                target_reference = str(relation.get("targetEntityId") or relation.get("targetId") or "")
                target_entity_id = references.get(target_reference)
                relation_type = str(relation.get("type") or relation.get("relationType") or "")
                if not target_entity_id or not relation_type:
                    continue
                relation_id = _safe_id(
                    relation.get("relationId"),
                    "relation",
                    self.workspace_id,
                    source_id,
                    target_entity_id,
                    relation_type,
                )
                connection.execute(
                    "INSERT INTO entity_relations(relation_id, workspace_id, source_entity_id, target_entity_id, relation_type, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (relation_id, self.workspace_id, source_id, target_entity_id, relation_type, _json(relation), revision, now),
                )
                changes.append(("entity_relation", relation_id, "link", relation))
        return changes

    def evidence_exists(self, evidence_id: str, target: str = "") -> bool:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            if target:
                target_id = self._target_id(connection, target)
                row = connection.execute(
                    "SELECT 1 FROM evidence WHERE workspace_id=? AND evidence_id=? AND target_id=?",
                    (self.workspace_id, evidence_id, target_id),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT 1 FROM evidence WHERE workspace_id=? AND evidence_id=?",
                    (self.workspace_id, evidence_id),
                ).fetchone()
        return row is not None

    def prune_evidence(
        self,
        *,
        target: str,
        source: str,
        data_type: str,
        keep: int,
        preserve_evidence_id: str = "",
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            target_id = self._target_id(connection, target)
            if target_id is None:
                return {"removedEvidenceIds": [], "removedPaths": [], "kept": 0}
            matching: list[tuple[str, str]] = []
            for evidence_id, created_at, payload_json in connection.execute(
                "SELECT evidence_id, created_at, payload_json FROM evidence WHERE workspace_id=? AND target_id=? ORDER BY created_at, evidence_id",
                (self.workspace_id, target_id),
            ):
                payload = _decode(payload_json)
                if payload.get("source") == source and payload.get("dataType") == data_type:
                    matching.append((str(evidence_id), str(created_at)))
            protected = {preserve_evidence_id} if preserve_evidence_id else set()
            removable = [item for item in matching if item[0] not in protected]
            retain_count = max(max(int(keep), 1) - len(protected), 0)
            removed = [item[0] for item in removable[: max(len(removable) - retain_count, 0)]]
            if not removed:
                return {"removedEvidenceIds": [], "removedPaths": [], "kept": len(matching)}
            revision = current + 1
            for evidence_id in removed:
                connection.execute(
                    "DELETE FROM entity_evidence WHERE workspace_id=? AND evidence_id=?",
                    (self.workspace_id, evidence_id),
                )
                connection.execute(
                    "DELETE FROM evidence_artifacts WHERE workspace_id=? AND evidence_id=?",
                    (self.workspace_id, evidence_id),
                )
                connection.execute(
                    "DELETE FROM evidence WHERE workspace_id=? AND evidence_id=?",
                    (self.workspace_id, evidence_id),
                )
            removed_set = set(removed)
            for entity_id, payload_json in connection.execute(
                "SELECT entity_id, payload_json FROM entities WHERE workspace_id=? AND target_id=?",
                (self.workspace_id, target_id),
            ):
                payload = _decode(payload_json)
                evidence_ids = payload.get("evidenceIds")
                if not isinstance(evidence_ids, list) or not removed_set.intersection(str(item) for item in evidence_ids):
                    continue
                payload["evidenceIds"] = [item for item in evidence_ids if str(item) not in removed_set]
                connection.execute(
                    "UPDATE entities SET payload_json=?, updated_revision=?, updated_at=? WHERE workspace_id=? AND entity_id=?",
                    (_json(payload), revision, _now(), self.workspace_id, entity_id),
                )
            self._finish_revision(
                connection,
                current=current,
                changes=tuple(("evidence", evidence_id, "delete", {}) for evidence_id in removed),
                event_type="workspace.evidence_pruned",
                summary=f"Pruned {len(removed)} superseded evidence records.",
                payload={"target": target, "source": source, "dataType": data_type, "removedEvidenceIds": removed},
            )
            return {"removedEvidenceIds": removed, "removedPaths": [], "kept": len(matching) - len(removed)}

    def ingest_collections(
        self,
        *,
        target: str,
        target_payload: Mapping[str, Any],
        evidence_payload: Mapping[str, Any],
        artifact: ArtifactRecord,
        collections: Mapping[str, Sequence[Mapping[str, Any]]],
        audit_payload: Mapping[str, Any],
        fault_injector: Callable[[str], None] | None = None,
        row_id_hints: Mapping[str, Mapping[str, str]] | None = None,
    ) -> tuple[int, dict[str, int]]:
        if not self.artifacts.blob_exists(artifact):
            raise StateIntegrityError("artifact_blob_not_installed", "Evidence artifact bytes are not installed.")
        evidence_id = str(evidence_payload["evidenceId"])
        counts: dict[str, int] = {name: 0 for name in collections}
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            revision = current + 1
            now = _now()
            target_id = self._target_id(connection, target)
            changes: list[tuple[str, str, str, Any]] = []
            if target_id is None:
                target_id = _stable_id("target", self.workspace_id, target)
                connection.execute(
                    "INSERT INTO targets(target_id, workspace_id, natural_key, kind, payload_json, created_revision, updated_revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (target_id, self.workspace_id, target, str(target_payload.get("kind") or "host"), _json(target_payload), revision, revision, now, now),
                )
                changes.append(("target", target_id, "create", {"target": target}))
            lineage = audit_payload.get("approval") if isinstance(audit_payload.get("approval"), Mapping) else audit_payload
            dispatch_id = str(lineage.get("dispatchId") or "") if isinstance(lineage, Mapping) else ""
            action_id = str(lineage.get("actionId") or "") if isinstance(lineage, Mapping) else ""
            if dispatch_id:
                dispatch_row = connection.execute(
                    "SELECT action_id FROM action_dispatches WHERE workspace_id=? AND dispatch_id=?",
                    (self.workspace_id, dispatch_id),
                ).fetchone()
                if dispatch_row:
                    action_id = str(dispatch_row[0])
                else:
                    dispatch_id = ""
            if action_id and not connection.execute(
                "SELECT 1 FROM actions WHERE workspace_id=? AND action_id=?",
                (self.workspace_id, action_id),
            ).fetchone():
                action_id = self._ensure_action(connection, action_id, revision, {"state": "recorded"})
            connection.execute(
                "INSERT INTO evidence(evidence_id, workspace_id, target_id, summary, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, self.workspace_id, target_id, str(evidence_payload.get("summary") or evidence_payload.get("source") or "Workspace evidence"), _json(_secure(evidence_payload)), revision, now),
            )
            connection.execute(
                "INSERT OR IGNORE INTO artifacts(artifact_id, workspace_id, digest, size, media_type, origin, creator_action_id, creator_dispatch_id, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact.artifact_id, self.workspace_id, artifact.digest, artifact.size, artifact.media_type, artifact.origin, action_id or None, dispatch_id or None, revision, now),
            )
            connection.execute(
                "INSERT INTO evidence_artifacts(workspace_id, evidence_id, artifact_id, created_revision) VALUES(?, ?, ?, ?)",
                (self.workspace_id, evidence_id, artifact.artifact_id, revision),
            )
            changes.extend((("evidence", evidence_id, "create", {}), ("artifact", artifact.artifact_id, "link", {"evidenceId": evidence_id})))
            if action_id:
                result_link_id = _stable_id(
                    "result-link",
                    self.workspace_id,
                    action_id,
                    dispatch_id,
                    evidence_id,
                    artifact.artifact_id,
                )
                connection.execute(
                    "INSERT INTO execution_result_links(result_link_id, workspace_id, action_id, dispatch_id, task_id, evidence_id, artifact_id, created_revision, created_at) VALUES(?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                    (result_link_id, self.workspace_id, action_id, dispatch_id or None, evidence_id, artifact.artifact_id, revision, now),
                )
                changes.append(("execution_result", result_link_id, "link", {"actionId": action_id, "dispatchId": dispatch_id}))
            for name, items in collections.items():
                count, entity_changes = self._upsert_collection_rows(
                    connection,
                    target=target,
                    entity_type=name,
                    items=items,
                    revision=revision,
                    evidence_id=evidence_id,
                    row_id_hints=(row_id_hints or {}).get(name),
                )
                counts[name] = count
                changes.extend(entity_changes)
            changes.extend(self._sync_relations(connection, target_id, revision))
            committed = self._finish_revision(
                connection,
                current=current,
                changes=changes,
                event_type="workspace.ingest",
                summary=str(audit_payload.get("summary") or f"Ingested {target} workspace evidence."),
                payload={**audit_payload, "evidenceId": evidence_id, "artifactId": artifact.artifact_id},
                fault_injector=fault_injector,
            )
        return committed, counts

    def register_artifact(self, artifact: ArtifactRecord, *, event_type: str = "artifact.register") -> int:
        if not self.artifacts.blob_exists(artifact):
            raise StateIntegrityError("artifact_blob_not_installed", "Artifact bytes are not installed.")
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            revision = current + 1
            existing = connection.execute(
                "SELECT artifact_id FROM artifacts WHERE workspace_id=? AND digest=?",
                (self.workspace_id, artifact.digest),
            ).fetchone()
            if existing:
                return current
            connection.execute(
                "INSERT INTO artifacts(artifact_id, workspace_id, digest, size, media_type, origin, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact.artifact_id, self.workspace_id, artifact.digest, artifact.size, artifact.media_type, artifact.origin, revision, _now()),
            )
            return self._finish_revision(
                connection,
                current=current,
                changes=(("artifact", artifact.artifact_id, "create", {"digest": artifact.digest}),),
                event_type=event_type,
                summary="Registered a workspace artifact.",
                payload={"artifactId": artifact.artifact_id, "mediaType": artifact.media_type},
            )

    # Authority use-case transaction. The policy engine evaluates while this
    # transaction holds the write reservation, so grant/budget/dispatch order
    # is the database order, not a process-local observation.

    def authority_state(self, connection: StateConnection) -> dict[str, Any]:
        revision_row = connection.execute(
            "SELECT revision FROM authority_repository_revisions WHERE workspace_id=?",
            (self.workspace_id,),
        ).fetchone()
        grants: dict[str, Any] = {}
        for grant_id, current_revision in connection.execute(
            "SELECT grant_id, current_revision FROM authority_grants WHERE workspace_id=? ORDER BY grant_id",
            (self.workspace_id,),
        ):
            revisions = {
                str(row[0]): _decode(row[1])
                for row in connection.execute(
                    "SELECT grant_revision, policy_json FROM authority_grant_revisions WHERE workspace_id=? AND grant_id=? ORDER BY grant_revision",
                    (self.workspace_id, grant_id),
                )
            }
            grants[str(grant_id)] = {"currentRevision": int(current_revision), "revisions": revisions}
        request_states = {
            str(row[0]): _decode(row[1])
            for row in connection.execute(
                "SELECT r.request_state_id, p.payload_json FROM request_states r "
                "JOIN authority_runtime_payloads p ON p.workspace_id=r.workspace_id AND p.record_kind='request_state' AND p.record_id=r.request_state_id "
                "WHERE r.workspace_id=?",
                (self.workspace_id,),
            )
        }
        step_ups = {
            str(row[0]): _decode(row[1])
            for row in connection.execute(
                "SELECT s.step_up_id, p.payload_json FROM step_ups s "
                "JOIN authority_runtime_payloads p ON p.workspace_id=s.workspace_id AND p.record_kind='step_up' AND p.record_id=s.step_up_id "
                "WHERE s.workspace_id=?",
                (self.workspace_id,),
            )
        }
        budget_windows: dict[str, Any] = {}
        for grant_id, payload in connection.execute(
            "SELECT b.grant_id, p.payload_json FROM budget_windows b "
            "JOIN authority_runtime_payloads p ON p.workspace_id=b.workspace_id AND p.record_kind='budget_window' AND p.record_id=b.budget_window_id "
            "WHERE b.workspace_id=? AND b.dimension='dispatch_total' ORDER BY b.window_start",
            (self.workspace_id,),
        ):
            budget_windows[str(grant_id)] = _decode(payload)
        dispatches: dict[str, Any] = {}
        for dispatch_id, idempotency_key, payload in connection.execute(
            "SELECT dispatch_id, idempotency_key, payload_json FROM action_dispatches WHERE workspace_id=?",
            (self.workspace_id,),
        ):
            item = _decode(payload)
            item.setdefault("dispatchId", dispatch_id)
            item["idempotencyKey"] = str(idempotency_key)
            dispatches[str(dispatch_id)] = item
        decisions = [
            _decode(row[0])
            for row in connection.execute(
                "SELECT payload_json FROM authority_decisions WHERE workspace_id=? ORDER BY created_revision, decision_id",
                (self.workspace_id,),
            )
        ]
        reconciliations = {
            str(row[0]): _decode(row[1])
            for row in connection.execute(
                "SELECT dispatch_id, payload_json FROM reconciliations WHERE workspace_id=?",
                (self.workspace_id,),
            )
        }
        return {
            "schemaVersion": 1,
            "revision": int(revision_row[0]) if revision_row else 0,
            "grants": grants,
            "stepUps": step_ups,
            "requestStates": request_states,
            "budgetWindows": budget_windows,
            "decisions": decisions,
            "dispatches": dispatches,
            "reconciliations": reconciliations,
        }

    def save_authority_state(self, connection: StateConnection, state: Mapping[str, Any]) -> int:
        current_workspace = self._workspace_revision(connection)
        current_authority_row = connection.execute(
            "SELECT revision FROM authority_repository_revisions WHERE workspace_id=?",
            (self.workspace_id,),
        ).fetchone()
        current_authority = int(current_authority_row[0]) if current_authority_row else 0
        requested_revision = int(state.get("revision") or 0)
        if requested_revision != current_authority + 1:
            raise StateConflictError(
                "authority_revision_conflict",
                f"Authority revision changed (expected {requested_revision - 1}, actual {current_authority}).",
            )
        revision = current_workspace + 1
        now = _now()
        changes: list[tuple[str, str, str, Any]] = []
        grants = state.get("grants") if isinstance(state.get("grants"), Mapping) else {}
        for grant_id, entry in grants.items():
            if not isinstance(entry, Mapping):
                continue
            revisions = entry.get("revisions") if isinstance(entry.get("revisions"), Mapping) else {}
            current_grant_revision = int(entry.get("currentRevision") or 0)
            current_value = revisions.get(str(current_grant_revision)) if isinstance(revisions, Mapping) else None
            if not isinstance(current_value, Mapping):
                continue
            connection.execute(
                "INSERT INTO authority_grants(grant_id, workspace_id, current_revision, state, expires_at, created_revision, updated_revision, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(grant_id) DO UPDATE SET current_revision=excluded.current_revision, state=excluded.state, expires_at=excluded.expires_at, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
                (
                    grant_id, self.workspace_id, current_grant_revision,
                    "revoked" if current_value.get("revokedAt") else "active",
                    str(current_value.get("expiresAt") or "9999-12-31T23:59:59Z"),
                    revision, revision, str(current_value.get("createdAt") or now), now,
                ),
            )
            for grant_revision, policy in revisions.items():
                connection.execute(
                    "INSERT OR IGNORE INTO authority_grant_revisions(workspace_id, grant_id, grant_revision, policy_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                    (self.workspace_id, grant_id, int(grant_revision), _json(_secure(policy)), revision, now),
                )
            changes.append(("authority_grant", str(grant_id), "update", {"revision": current_grant_revision}))

        valid_request_ids: set[str] = set()
        requests = state.get("requestStates") if isinstance(state.get("requestStates"), Mapping) else {}
        for raw_id, raw_item in requests.items():
            if not isinstance(raw_item, Mapping):
                continue
            request_id = opaque_ref(str(raw_id))
            item = _secure({**raw_item, "requestStateId": request_id})
            valid_request_ids.add(request_id)
            action_id = self._ensure_action(connection, str(item.get("actionId") or "authority.request"), revision, item)
            grant_id = str(item.get("grantId") or "") or None
            connection.execute(
                "INSERT INTO request_states(request_state_id, workspace_id, action_id, grant_id, opaque_state_ref, state, expires_at, created_revision, updated_revision, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(request_state_id) DO UPDATE SET state=excluded.state, expires_at=excluded.expires_at, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
                (request_id, self.workspace_id, action_id, grant_id, request_id, str(item.get("status") or "pending"), str(item.get("expiresAt") or now), revision, revision, str(item.get("createdAt") or now), now),
            )
            self._upsert_authority_payload(connection, "request_state", request_id, item, revision)
        self._delete_missing(connection, "request_states", "request_state_id", valid_request_ids)

        valid_stepups: set[str] = set()
        stepups = state.get("stepUps") if isinstance(state.get("stepUps"), Mapping) else {}
        for raw_id, raw_item in stepups.items():
            if not isinstance(raw_item, Mapping):
                continue
            stepup_id = opaque_ref(str(raw_id))
            item = _secure(raw_item)
            valid_stepups.add(stepup_id)
            connection.execute(
                "INSERT INTO step_ups(step_up_id, workspace_id, grant_id, grant_revision, authorization_fingerprint, approved_by_ref, expires_at, consumed_at, created_revision, created_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(step_up_id) DO UPDATE SET consumed_at=excluded.consumed_at",
                (stepup_id, self.workspace_id, str(item.get("grantId") or ""), int(item.get("grantRevision") or 0), str(item.get("authorizationFingerprint") or ""), str(item.get("approvedBy") or "operator"), str(item.get("expiresAt") or now), item.get("consumedAt") or None, revision, str(item.get("createdAt") or now)),
            )
            self._upsert_authority_payload(connection, "step_up", stepup_id, item, revision)
        self._delete_missing(connection, "step_ups", "step_up_id", valid_stepups)

        budgets = state.get("budgetWindows") if isinstance(state.get("budgetWindows"), Mapping) else {}
        for grant_id, raw_item in budgets.items():
            if not isinstance(raw_item, Mapping):
                continue
            item = _secure(raw_item)
            window_start = str(item.get("windowStartedAt") or now)
            window_end = str(item.get("windowEndsAt") or "9999-12-31T23:59:59Z")
            for dimension, field, reservation in (
                ("dispatch_total", "dispatchesUsed", False),
                ("dispatch_window", "dispatchWindowUsed", False),
                ("active_dispatch", "activeDispatches", True),
            ):
                amount = max(int(item.get(field) or 0), 0)
                budget_id = _stable_id("budget", self.workspace_id, grant_id, dimension, window_start)
                connection.execute(
                    "INSERT INTO budget_windows(budget_window_id, workspace_id, grant_id, dimension, window_start, window_end, reserved, consumed, created_revision, updated_revision) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(workspace_id, grant_id, dimension, window_start) DO UPDATE SET window_end=excluded.window_end, reserved=excluded.reserved, consumed=excluded.consumed, updated_revision=excluded.updated_revision",
                    (budget_id, self.workspace_id, grant_id, dimension, window_start, window_end, amount if reservation else 0, 0 if reservation else amount, revision, revision),
                )
                self._upsert_authority_payload(connection, "budget_window", budget_id, item, revision)

        dispatches = state.get("dispatches") if isinstance(state.get("dispatches"), Mapping) else {}
        for dispatch_id, raw_item in dispatches.items():
            if not isinstance(raw_item, Mapping):
                continue
            item = _secure(raw_item)
            action_id = self._ensure_action(connection, str(item.get("actionId") or "authority.action"), revision, item)
            idempotency = str(item.get("idempotencyKey") or "")
            grant_id = str(item.get("grantId") or "") or None
            connection.execute(
                "INSERT INTO action_dispatches(dispatch_id, workspace_id, action_id, authority_grant_id, state, idempotency_key, payload_json, created_revision, updated_revision, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(dispatch_id) DO UPDATE SET state=excluded.state, payload_json=excluded.payload_json, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
                (dispatch_id, self.workspace_id, action_id, grant_id, str(item.get("state") or "unknown"), idempotency, _json(item), revision, revision, str(item.get("createdAt") or now), now),
            )
            changes.append(("action_dispatch", str(dispatch_id), "update", {"state": item.get("state")}))

        reconciliations = state.get("reconciliations") if isinstance(state.get("reconciliations"), Mapping) else {}
        for reconciliation_id, raw_item in reconciliations.items():
            if not isinstance(raw_item, Mapping):
                continue
            dispatch_id = str(raw_item.get("dispatchId") or reconciliation_id)
            if dispatch_id not in dispatches:
                continue
            safe_id = _safe_id(reconciliation_id, "reconciliation", self.workspace_id, reconciliation_id)
            connection.execute(
                "INSERT OR IGNORE INTO reconciliations(reconciliation_id, workspace_id, dispatch_id, state, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (safe_id, self.workspace_id, dispatch_id, str(raw_item.get("state") or raw_item.get("resolution") or "recorded"), _json(_secure(raw_item)), revision, now),
            )

        decisions = state.get("decisions") if isinstance(state.get("decisions"), list) else []
        valid_decisions: set[str] = set()
        for index, raw_item in enumerate(decisions):
            if not isinstance(raw_item, Mapping):
                continue
            decision_id = _safe_id(raw_item.get("auditId"), "audit", self.workspace_id, requested_revision, index, _json(raw_item))
            valid_decisions.add(decision_id)
            item = _secure(raw_item)
            inserted = connection.execute(
                "INSERT OR IGNORE INTO authority_decisions(decision_id, workspace_id, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?)",
                (decision_id, self.workspace_id, _json(item), revision, str(item.get("at") or now)),
            )
            if getattr(inserted, "rowcount", 0):
                connection.execute(
                    "INSERT INTO audit_events(event_id, workspace_id, revision, event_type, summary, actor_ref, payload_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (decision_id, self.workspace_id, revision, f"authority.{item.get('kind') or 'decision'}", str(item.get("reason") or "Authority decision"), "authority-engine", _json(item), str(item.get("at") or now)),
                )
        self._delete_missing(connection, "authority_decisions", "decision_id", valid_decisions)

        connection.execute(
            "INSERT INTO authority_repository_revisions(workspace_id, revision, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(workspace_id) DO UPDATE SET revision=excluded.revision, updated_at=excluded.updated_at",
            (self.workspace_id, requested_revision, now),
        )
        if not changes:
            changes.append(("authority", self.workspace_id, "update", {"revision": requested_revision}))
        # Authority decisions above are the use-case audit. Add a generic audit
        # only for commits such as continuation binding with no decision row.
        has_revision_audit = connection.execute(
            "SELECT 1 FROM audit_events WHERE workspace_id=? AND revision=? LIMIT 1",
            (self.workspace_id, revision),
        ).fetchone()
        if has_revision_audit:
            connection.executemany(
                "INSERT INTO change_log(workspace_id, revision, sequence, entity_type, entity_id, change_kind, payload_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                tuple((self.workspace_id, revision, index, kind, identity, change, _json(detail), now) for index, (kind, identity, change, detail) in enumerate(changes)),
            )
            updated = connection.execute(
                "UPDATE workspace_revisions SET revision=?, updated_at=? WHERE workspace_id=? AND revision=?",
                (revision, now, self.workspace_id, current_workspace),
            )
            if getattr(updated, "rowcount", 1) == 0:
                raise StateConflictError("workspace_revision_conflict", "Workspace revision compare-and-swap failed.")
            connection.execute("UPDATE workspaces SET updated_at=? WHERE workspace_id=?", (now, self.workspace_id))
        else:
            self._finish_revision(
                connection,
                current=current_workspace,
                changes=changes,
                event_type="authority.commit",
                summary="Committed authority state transition.",
                payload={"authorityRevision": requested_revision},
            )
        return requested_revision

    def _ensure_action(self, connection: StateConnection, action_id: str, revision: int, payload: Mapping[str, Any]) -> str:
        safe = _safe_id(action_id, "action", self.workspace_id, action_id)
        now = _now()
        connection.execute(
            "INSERT INTO actions(action_id, workspace_id, action_name, state, plan_fingerprint, payload_json, created_revision, updated_revision, created_at, updated_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(action_id) DO UPDATE SET state=excluded.state, plan_fingerprint=excluded.plan_fingerprint, payload_json=excluded.payload_json, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
            (safe, self.workspace_id, action_id, str(payload.get("state") or payload.get("status") or "recorded"), str(payload.get("planFingerprint") or ""), _json(_secure(payload)), revision, revision, now, now),
        )
        return safe

    def _delete_missing(self, connection: StateConnection, table: str, column: str, valid: set[str]) -> None:
        # Table/column values are internal constants supplied by this module.
        rows = list(connection.execute(f"SELECT {column} FROM {table} WHERE workspace_id=?", (self.workspace_id,)))
        for row in rows:
            if str(row[0]) not in valid:
                connection.execute(f"DELETE FROM {table} WHERE workspace_id=? AND {column}=?", (self.workspace_id, row[0]))
                payload_kind = {"request_states": "request_state", "step_ups": "step_up"}.get(table)
                if payload_kind:
                    connection.execute(
                        "DELETE FROM authority_runtime_payloads WHERE workspace_id=? AND record_kind=? AND record_id=?",
                        (self.workspace_id, payload_kind, row[0]),
                    )

    def _upsert_authority_payload(
        self,
        connection: StateConnection,
        kind: str,
        record_id: str,
        payload: Mapping[str, Any],
        revision: int,
    ) -> None:
        connection.execute(
            "INSERT INTO authority_runtime_payloads(workspace_id, record_kind, record_id, payload_json, updated_revision) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(workspace_id, record_kind, record_id) DO UPDATE SET payload_json=excluded.payload_json, updated_revision=excluded.updated_revision",
            (self.workspace_id, kind, record_id, _json(payload), revision),
        )

    # Durable background task records.

    def read_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT state, revision, payload_json FROM tasks WHERE workspace_id=? AND task_id=?",
                (self.workspace_id, task_id),
            ).fetchone()
        if row is None:
            return None
        payload = _decode(row[2])
        payload.update({"jobId": task_id, "workspaceId": self.workspace_id, "status": row[0], "revision": int(row[1])})
        return payload

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            rows = list(connection.execute(
                "SELECT task_id, state, revision, payload_json FROM tasks WHERE workspace_id=? ORDER BY created_at DESC",
                (self.workspace_id,),
            ))
        result = []
        for task_id, state, revision, payload in rows:
            item = _decode(payload)
            item.update({"jobId": task_id, "workspaceId": self.workspace_id, "status": state, "revision": int(revision)})
            result.append(item)
        return result

    def write_task(self, record: Mapping[str, Any], *, expected_revision: int) -> int:
        task_id = str(record["jobId"])
        with self.transaction() as connection:
            workspace_revision = self._workspace_revision(connection)
            row = connection.execute(
                "SELECT revision, created_at FROM tasks WHERE workspace_id=? AND task_id=?",
                (self.workspace_id, task_id),
            ).fetchone()
            actual = int(row[0]) if row else 0
            if actual != int(expected_revision):
                raise StateConflictError(
                    "task_revision_conflict",
                    f"Task revision changed (expected {expected_revision}, actual {actual}).",
                )
            task_revision = actual + 1
            revision = workspace_revision + 1
            now = _now()
            plan = record.get("executionPlan") if isinstance(record.get("executionPlan"), Mapping) else {}
            action_id = self._ensure_action(
                connection,
                str(plan.get("actionId") or record.get("tool") or "background.job"),
                revision,
                record,
            )
            safe_record = _secure(dict(record))
            safe_record["revision"] = task_revision
            connection.execute(
                "INSERT INTO tasks(task_id, workspace_id, action_id, state, revision, payload_json, created_revision, updated_revision, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(task_id) DO UPDATE SET state=excluded.state, revision=excluded.revision, payload_json=excluded.payload_json, updated_revision=excluded.updated_revision, updated_at=excluded.updated_at",
                (task_id, self.workspace_id, action_id, str(record.get("status") or "unknown"), task_revision, _json(safe_record), revision, revision, str(record.get("createdAt") or now), now),
            )
            approval = record.get("approval") if isinstance(record.get("approval"), Mapping) else {}
            dispatch_id = str(approval.get("dispatchId") or "")
            if dispatch_id and connection.execute(
                "SELECT 1 FROM action_dispatches WHERE workspace_id=? AND dispatch_id=?",
                (self.workspace_id, dispatch_id),
            ).fetchone():
                connection.execute(
                    "INSERT OR IGNORE INTO task_dispatch_links(workspace_id, task_id, dispatch_id, created_revision) VALUES(?, ?, ?, ?)",
                    (self.workspace_id, task_id, dispatch_id, revision),
                )
            else:
                dispatch_id = ""
            result_link_id = _stable_id("result-link", self.workspace_id, action_id, dispatch_id, task_id)
            connection.execute(
                "INSERT OR IGNORE INTO execution_result_links(result_link_id, workspace_id, action_id, dispatch_id, task_id, evidence_id, artifact_id, created_revision, created_at) VALUES(?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
                (result_link_id, self.workspace_id, action_id, dispatch_id or None, task_id, revision, now),
            )
            event_type = "task.finalization_result" if record.get("finalized") else (
                "task.finalization_reserved"
                if isinstance(record.get("finalization"), Mapping) and record["finalization"].get("state") == "applying"
                else "task.transition"
            )
            event_id = _stable_id("task-event", self.workspace_id, task_id, task_revision)
            connection.execute(
                "INSERT INTO task_events(task_event_id, workspace_id, task_id, event_type, task_revision, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, self.workspace_id, task_id, event_type, task_revision, _json({"state": record.get("status"), "finalization": _secure(record.get("finalization"))}), revision, now),
            )
            self._finish_revision(
                connection,
                current=workspace_revision,
                changes=(("task", task_id, "create" if row is None else "update", {"taskRevision": task_revision}),),
                event_type=event_type,
                summary=f"Persisted task {task_id} revision {task_revision}.",
                payload={"taskId": task_id, "taskRevision": task_revision, "state": record.get("status")},
                event_id=f"audit-{event_id}",
            )
        return task_revision

    # Durable opaque artifact resources.

    def issue_resource(
        self,
        artifact: ArtifactRecord,
        *,
        reference: str,
        principal_id: str,
        authority_session_id: str,
        artifact_type: str,
        media_type: str,
    ) -> int:
        if not self.artifacts.blob_exists(artifact):
            raise StateIntegrityError("artifact_blob_not_installed", "Resource artifact bytes are not installed.")
        with self.transaction() as connection:
            current = self._workspace_revision(connection)
            revision = current + 1
            now = _now()
            connection.execute(
                "INSERT OR IGNORE INTO artifacts(artifact_id, workspace_id, digest, size, media_type, origin, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact.artifact_id, self.workspace_id, artifact.digest, artifact.size, artifact.media_type, artifact.origin, revision, now),
            )
            reference_digest = opaque_ref(reference)
            connection.execute(
                "INSERT INTO artifact_resource_refs(reference_digest, workspace_id, artifact_id, principal_ref, authority_session_ref, artifact_type, media_type, version, size, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (reference_digest, self.workspace_id, artifact.artifact_id, opaque_ref(principal_id), opaque_ref(authority_session_id), artifact_type, media_type, artifact.digest, artifact.size, revision, now),
            )
            return self._finish_revision(
                connection,
                current=current,
                changes=(("artifact_resource", reference_digest, "link", {"artifactId": artifact.artifact_id}),),
                event_type="artifact.resource_issued",
                summary="Issued an opaque workspace artifact reference.",
                payload={"artifactId": artifact.artifact_id, "artifactType": artifact_type},
            )

    def resource_record(self, reference: str) -> dict[str, Any] | None:
        digest = opaque_ref(reference)
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT artifact_id, principal_ref, authority_session_ref, artifact_type, media_type, version, size FROM artifact_resource_refs WHERE workspace_id=? AND reference_digest=?",
                (self.workspace_id, digest),
            ).fetchone()
        if row is None:
            return None
        path = self.artifacts.resolve(str(row[0]), workspace_id=self.workspace_id)
        return {
            "artifactId": row[0],
            "path": path,
            "workspaceId": self.workspace_id,
            "principalRef": row[1],
            "authoritySessionRef": row[2],
            "artifactType": row[3],
            "mediaType": row[4],
            "version": row[5],
            "size": int(row[6]),
        }

    def artifact_record(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT artifact_id, digest, size, media_type, origin FROM artifacts WHERE workspace_id=? AND artifact_id=?",
                (self.workspace_id, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifactId": row[0],
            "path": self.artifacts.resolve(str(row[0]), workspace_id=self.workspace_id),
            "workspaceId": self.workspace_id,
            "version": row[1],
            "size": int(row[2]),
            "mediaType": row[3],
            "origin": row[4],
        }

    # Bounded WAL status/checkpoint and online backup.

    def checkpoint_status(self, *, manual: bool = False) -> dict[str, Any]:
        owner = opaque_ref(f"{uuid4().hex}:{time.time_ns()}")
        if manual:
            with self.transaction() as connection:
                row = connection.execute(
                    "SELECT state, started_at FROM checkpoint_leases WHERE workspace_id=?",
                    (self.workspace_id,),
                ).fetchone()
                if row and str(row[0]) == "running":
                    return {"state": "blocked", "reasonCode": "checkpoint_already_running"}
                connection.execute(
                    "INSERT INTO checkpoint_leases(workspace_id, owner_ref, state, started_at, completed_at, detail_json) VALUES(?, ?, 'running', ?, NULL, '{}') "
                    "ON CONFLICT(workspace_id) DO UPDATE SET owner_ref=excluded.owner_ref, state='running', started_at=excluded.started_at, completed_at=NULL, detail_json='{}'",
                    (self.workspace_id, owner, _now()),
                )
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            mode = "RESTART" if manual else "PASSIVE"
            busy, frames, checkpointed = connection.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
        state = "blocked" if int(busy) or int(checkpointed) < int(frames) else "completed"
        result = {
            "state": state,
            "busy": int(busy),
            "frames": int(frames),
            "checkpointedFrames": int(checkpointed),
            "mode": mode.lower(),
        }
        if manual:
            with self.transaction() as connection:
                connection.execute(
                    "UPDATE checkpoint_leases SET state=?, completed_at=?, detail_json=? WHERE workspace_id=? AND owner_ref=?",
                    (state, _now(), _json(result), self.workspace_id, owner),
                )
        return result

    def backup_to(self, destination: Path) -> Path:
        return online_backup(self.connection_factory, destination)


def activated_repository(workspace_id: str, workspaces_root: Path) -> ActivatedWorkspaceRepository:
    return ActivatedWorkspaceRepository(workspace_id, Path(workspaces_root) / workspace_id)
