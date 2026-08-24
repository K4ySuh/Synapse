# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Transactional SQLite-v2 repository for one isolated workspace."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from hashlib import sha256
import json
from pathlib import Path
import time
from typing import Any

from .artifacts import ContentAddressedArtifactRepository, normalize_workspace_id
from .connections import ConnectionFactory, StateConnection, immediate_transaction, verify_database_integrity
from .contracts import (
    ArtifactRecord,
    AuditRecord,
    EntityRecord,
    EvidenceRecord,
    RelationRecord,
    TargetRecord,
    VerticalSlice,
    WorkspaceRecord,
)
from .errors import StateConflictError, StateIntegrityError, StateStoreError
from .migrations import apply_migrations


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _json_value(value: Any) -> Any:
    return json.loads(str(value))


class SQLiteWorkspaceRepository:
    """Workspace repository whose public writes are revision transactions."""

    def __init__(
        self,
        workspace_id: str,
        workspace_root: Path,
        *,
        connection_factory: ConnectionFactory | None = None,
        artifact_repository: ContentAddressedArtifactRepository | None = None,
    ) -> None:
        self._workspace_id = normalize_workspace_id(workspace_id)
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        if self.workspace_root.name != self._workspace_id:
            raise StateStoreError(
                "state_workspace_root_mismatch",
                "State Store root does not belong to the bound workspace.",
            )
        self.state_root = self.workspace_root / "state-v2"
        self.database_path = self.state_root / "state.sqlite3"
        self.connection_factory = connection_factory or ConnectionFactory(self.database_path)
        if self.connection_factory.database_path.resolve(strict=False) != self.database_path.resolve(strict=False):
            raise StateStoreError(
                "state_database_path_mismatch",
                "Connection factory does not point at the bound workspace database.",
            )
        self.artifacts = artifact_repository or ContentAddressedArtifactRepository(
            self._workspace_id,
            self.workspace_root,
        )

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def initialize(self, record: WorkspaceRecord, *, audit: AuditRecord) -> int:
        if normalize_workspace_id(record.workspace_id) != self._workspace_id:
            raise StateStoreError("state_workspace_mismatch", "Workspace record identity does not match repository.")
        now = _now_utc()
        try:
            with self.connection_factory.connect() as connection:
                apply_migrations(connection)
                with immediate_transaction(connection):
                    if connection.execute(
                        "SELECT 1 FROM workspaces WHERE workspace_id=?",
                        (self._workspace_id,),
                    ).fetchone():
                        raise StateConflictError("workspace_already_exists", "Workspace already exists in State Store v2.")
                    connection.execute(
                        "INSERT INTO workspaces(workspace_id, organization, notes, created_at, updated_at) VALUES(?, ?, ?, ?, ?)",
                        (self._workspace_id, record.organization, record.notes, now, now),
                    )
                    connection.execute(
                        "INSERT INTO workspace_revisions(workspace_id, revision, updated_at) VALUES(?, 1, ?)",
                        (self._workspace_id, now),
                    )
                    self._insert_changes(
                        connection,
                        1,
                        (("workspace", self._workspace_id, "create", {"organization": record.organization}),),
                        now,
                    )
                    self._insert_audit(connection, audit, 1, now)
            return 1
        except StateStoreError:
            raise
        except Exception as exc:
            raise self._translate_write_error(exc) from exc

    def initialize_fresh(
        self,
        record: WorkspaceRecord,
        *,
        scope: dict[str, Any],
        targets: Sequence[TargetRecord],
        audit: AuditRecord,
    ) -> int:
        """Create one fresh v2 workspace, scope, and target set atomically."""

        if normalize_workspace_id(record.workspace_id) != self._workspace_id:
            raise StateStoreError("state_workspace_mismatch", "Workspace record identity does not match repository.")
        now = _now_utc()
        try:
            with self.connection_factory.connect() as connection:
                apply_migrations(connection)
                with immediate_transaction(connection):
                    if connection.execute(
                        "SELECT 1 FROM workspaces WHERE workspace_id=?",
                        (self._workspace_id,),
                    ).fetchone():
                        raise StateConflictError("workspace_already_exists", "Workspace already exists in State Store v2.")
                    connection.execute(
                        "INSERT INTO workspaces(workspace_id, organization, notes, created_at, updated_at) VALUES(?, ?, ?, ?, ?)",
                        (self._workspace_id, record.organization, record.notes, now, now),
                    )
                    changes: list[tuple[str, str, str, Any]] = [
                        ("workspace", self._workspace_id, "create", {"organization": record.organization})
                    ]
                    if scope:
                        scope_json = _json(scope)
                        scope_digest = sha256(scope_json.encode("utf-8")).hexdigest()
                        scope_id = f"scope-{scope_digest[:24]}"
                        connection.execute(
                            "INSERT INTO scope_snapshots(scope_snapshot_id, workspace_id, digest, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, 1, ?)",
                            (scope_id, self._workspace_id, scope_digest, scope_json, now),
                        )
                        changes.append(("scope_snapshot", scope_id, "create", scope))
                    for target in targets:
                        self._insert_target(connection, target, 1, now)
                        changes.append(("target", target.target_id, "create", target.payload))
                    connection.execute(
                        "INSERT INTO workspace_revisions(workspace_id, revision, updated_at) VALUES(?, 1, ?)",
                        (self._workspace_id, now),
                    )
                    self._insert_changes(connection, 1, changes, now)
                    self._insert_audit(connection, audit, 1, now)
            return 1
        except StateStoreError:
            raise
        except Exception as exc:
            raise self._translate_write_error(exc) from exc

    def apply_vertical_slice(
        self,
        value: VerticalSlice,
        *,
        expected_revision: int,
        fault_injector: Callable[[str], None] | None = None,
    ) -> int:
        """Commit domain rows, revision, change log, and audit atomically."""

        if value.artifact is not None:
            self._verify_artifact_record(value.artifact)
        try:
            with self.connection_factory.connect() as connection:
                apply_migrations(connection)

                def mutation(revision: int, now: str) -> Sequence[tuple[str, str, str, Any]]:
                    scope_json = _json(value.scope)
                    scope_digest = sha256(scope_json.encode("utf-8")).hexdigest()
                    connection.execute(
                        "INSERT INTO scope_snapshots(scope_snapshot_id, workspace_id, digest, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                        (value.scope_snapshot_id, self._workspace_id, scope_digest, scope_json, revision, now),
                    )
                    changes: list[tuple[str, str, str, Any]] = [
                        ("scope_snapshot", value.scope_snapshot_id, "create", value.scope)
                    ]
                    for target in value.targets:
                        self._insert_target(connection, target, revision, now)
                        changes.append(("target", target.target_id, "create", target.payload))
                    for entity in value.entities:
                        self._insert_entity(connection, entity, revision, now)
                        changes.append(("entity", entity.entity_id, "create", entity.payload))
                    for relation in value.relations:
                        self._insert_relation(connection, relation, revision, now)
                        changes.append(("entity_relation", relation.relation_id, "link", relation.payload))
                    for evidence in value.evidence:
                        self._insert_evidence(connection, evidence, revision, now)
                        changes.append(("evidence", evidence.evidence_id, "create", evidence.payload))
                    if value.artifact is not None:
                        self._insert_artifact(connection, value.artifact, revision, now)
                        changes.append(("artifact", value.artifact.artifact_id, "create", {"digest": value.artifact.digest}))
                    for evidence_id, artifact_id in value.evidence_artifact_links:
                        connection.execute(
                            "INSERT INTO evidence_artifacts(workspace_id, evidence_id, artifact_id, created_revision) VALUES(?, ?, ?, ?)",
                            (self._workspace_id, evidence_id, artifact_id, revision),
                        )
                        changes.append(("evidence_artifact", f"{evidence_id}:{artifact_id}", "link", {}))
                    if fault_injector is not None:
                        fault_injector("before_revision_commit")
                    return changes

                return self._commit_revision(
                    expected_revision=expected_revision,
                    audit=value.audit,
                    mutation=mutation,
                    connection=connection,
                )
        except StateStoreError:
            raise
        except Exception as exc:
            raise self._translate_write_error(exc) from exc

    def revision(self) -> int:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            row = connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id=?",
                (self._workspace_id,),
            ).fetchone()
        if row is None:
            raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
        return int(row[0])

    def snapshot(self) -> dict[str, Any]:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            connection.execute("BEGIN")
            workspace = connection.execute(
                "SELECT workspace_id, organization, notes, created_at, updated_at FROM workspaces WHERE workspace_id=?",
                (self._workspace_id,),
            ).fetchone()
            if workspace is None:
                raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
            revision = int(connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id=?",
                (self._workspace_id,),
            ).fetchone()[0])
            scope = [
                {"scopeSnapshotId": row[0], "digest": row[1], "payload": _json_value(row[2]), "createdRevision": int(row[3])}
                for row in connection.execute(
                    "SELECT scope_snapshot_id, digest, payload_json, created_revision FROM scope_snapshots WHERE workspace_id=? ORDER BY created_revision, scope_snapshot_id",
                    (self._workspace_id,),
                )
            ]
            targets = [
                {"targetId": row[0], "naturalKey": row[1], "kind": row[2], "payload": _json_value(row[3])}
                for row in connection.execute(
                    "SELECT target_id, natural_key, kind, payload_json FROM targets WHERE workspace_id=? ORDER BY target_id",
                    (self._workspace_id,),
                )
            ]
            entities = [
                {"entityId": row[0], "targetId": row[1], "entityType": row[2], "naturalKey": row[3], "lifecycle": row[4], "payload": _json_value(row[5])}
                for row in connection.execute(
                    "SELECT entity_id, target_id, entity_type, natural_key, lifecycle, payload_json FROM entities WHERE workspace_id=? ORDER BY entity_id",
                    (self._workspace_id,),
                )
            ]
            relations = [
                {"relationId": row[0], "sourceEntityId": row[1], "targetEntityId": row[2], "relationType": row[3], "payload": _json_value(row[4])}
                for row in connection.execute(
                    "SELECT relation_id, source_entity_id, target_entity_id, relation_type, payload_json FROM entity_relations WHERE workspace_id=? ORDER BY relation_id",
                    (self._workspace_id,),
                )
            ]
            evidence = [
                {"evidenceId": row[0], "targetId": row[1], "summary": row[2], "payload": _json_value(row[3])}
                for row in connection.execute(
                    "SELECT evidence_id, target_id, summary, payload_json FROM evidence WHERE workspace_id=? ORDER BY evidence_id",
                    (self._workspace_id,),
                )
            ]
            artifacts = [
                {"artifactId": row[0], "digest": row[1], "size": int(row[2]), "mediaType": row[3], "origin": row[4]}
                for row in connection.execute(
                    "SELECT artifact_id, digest, size, media_type, origin FROM artifacts WHERE workspace_id=? ORDER BY artifact_id",
                    (self._workspace_id,),
                )
            ]
            audits = [
                {"eventId": row[0], "revision": int(row[1]), "eventType": row[2], "summary": row[3], "actorRef": row[4], "payload": _json_value(row[5])}
                for row in connection.execute(
                    "SELECT event_id, revision, event_type, summary, actor_ref, payload_json FROM audit_events WHERE workspace_id=? ORDER BY revision, event_id",
                    (self._workspace_id,),
                )
            ]
            connection.commit()
        return {
            "storeVersion": "sqlite-v2",
            "revision": revision,
            "workspace": {"workspaceId": workspace[0], "organization": workspace[1], "notes": workspace[2], "createdAt": workspace[3], "updatedAt": workspace[4]},
            "scopeSnapshots": scope,
            "targets": targets,
            "entities": entities,
            "relations": relations,
            "evidence": evidence,
            "artifacts": artifacts,
            "auditEvents": audits,
        }

    def verify_integrity(self) -> None:
        with self.connection_factory.connect() as connection:
            apply_migrations(connection)
            verify_database_integrity(connection)
            for artifact_id, digest, size, media_type, origin in connection.execute(
                "SELECT artifact_id, digest, size, media_type, origin FROM artifacts WHERE workspace_id=?",
                (self._workspace_id,),
            ):
                path = self.artifacts.path_for_digest(str(digest))
                record = ArtifactRecord(
                    str(artifact_id),
                    str(digest),
                    int(size),
                    str(media_type),
                    str(origin),
                    path,
                )
                if not self.artifacts.blob_exists(record):
                    raise StateIntegrityError(
                        "artifact_metadata_blob_missing",
                        "State Store artifact metadata references a missing or mismatched blob.",
                    )

    def _commit_revision(
        self,
        *,
        expected_revision: int,
        audit: AuditRecord,
        mutation: Callable[[int, str], Sequence[tuple[str, str, str, Any]]],
        connection: StateConnection,
    ) -> int:
        with immediate_transaction(connection):
            row = connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id=?",
                (self._workspace_id,),
            ).fetchone()
            if row is None:
                raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
            current = int(row[0])
            if current != int(expected_revision):
                raise StateConflictError(
                    "workspace_revision_conflict",
                    f"Workspace revision changed (expected {expected_revision}, actual {current}).",
                )
            revision = current + 1
            now = _now_utc()
            changes = mutation(revision, now)
            self._insert_changes(connection, revision, changes, now)
            self._insert_audit(connection, audit, revision, now)
            cursor = connection.execute(
                "UPDATE workspace_revisions SET revision=?, updated_at=? WHERE workspace_id=? AND revision=?",
                (revision, now, self._workspace_id, current),
            )
            rowcount = getattr(cursor, "rowcount", None)
            if rowcount is not None and int(rowcount) == 0:
                raise StateConflictError("workspace_revision_conflict", "Workspace revision compare-and-swap failed.")
            connection.execute("UPDATE workspaces SET updated_at=? WHERE workspace_id=?", (now, self._workspace_id))
        return revision

    def _insert_target(self, connection: StateConnection, value: TargetRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO targets(target_id, workspace_id, natural_key, kind, payload_json, created_revision, updated_revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (value.target_id, self._workspace_id, value.natural_key, value.kind, _json(value.payload), revision, revision, now, now),
        )

    def _insert_entity(self, connection: StateConnection, value: EntityRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO entities(entity_id, workspace_id, target_id, entity_type, natural_key, lifecycle, payload_json, created_revision, updated_revision, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (value.entity_id, self._workspace_id, value.target_id, value.entity_type, value.natural_key, value.lifecycle, _json(value.payload), revision, revision, now, now),
        )

    def _insert_relation(self, connection: StateConnection, value: RelationRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO entity_relations(relation_id, workspace_id, source_entity_id, target_entity_id, relation_type, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (value.relation_id, self._workspace_id, value.source_entity_id, value.target_entity_id, value.relation_type, _json(value.payload), revision, now),
        )

    def _insert_evidence(self, connection: StateConnection, value: EvidenceRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO evidence(evidence_id, workspace_id, target_id, summary, payload_json, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (value.evidence_id, self._workspace_id, value.target_id, value.summary, _json(value.payload), revision, now),
        )

    def _insert_artifact(self, connection: StateConnection, value: ArtifactRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO artifacts(artifact_id, workspace_id, digest, size, media_type, origin, created_revision, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (value.artifact_id, self._workspace_id, value.digest, value.size, value.media_type, value.origin, revision, now),
        )

    def _insert_audit(self, connection: StateConnection, value: AuditRecord, revision: int, now: str) -> None:
        connection.execute(
            "INSERT INTO audit_events(event_id, workspace_id, revision, event_type, summary, actor_ref, payload_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (value.event_id, self._workspace_id, revision, value.event_type, value.summary, value.actor_ref, _json(value.payload), now),
        )

    def _insert_changes(
        self,
        connection: StateConnection,
        revision: int,
        changes: Sequence[tuple[str, str, str, Any]],
        now: str,
    ) -> None:
        connection.executemany(
            "INSERT INTO change_log(workspace_id, revision, sequence, entity_type, entity_id, change_kind, payload_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            tuple(
                (self._workspace_id, revision, sequence, entity_type, entity_id, kind, _json(payload), now)
                for sequence, (entity_type, entity_id, kind, payload) in enumerate(changes)
            ),
        )

    def _verify_artifact_record(self, value: ArtifactRecord) -> None:
        expected_path = self.artifacts.path_for_digest(value.digest).resolve(strict=False)
        if value.path.resolve(strict=False) != expected_path or not self.artifacts.blob_exists(value):
            raise StateIntegrityError(
                "artifact_blob_not_installed",
                "Artifact bytes must be installed in this workspace before metadata commits.",
            )

    @staticmethod
    def _translate_write_error(exc: Exception) -> StateStoreError:
        message = str(exc).lower()
        if "unique constraint failed" in message:
            return StateConflictError("state_natural_key_conflict", "State Store natural key or identity already exists.")
        if "foreign key constraint failed" in message:
            return StateIntegrityError("state_foreign_key_violation", "State Store reference crosses a workspace or is missing.")
        if "audit_events_append_only" in message:
            return StateIntegrityError("audit_append_only", "Audit events are append-only.")
        if "constraint" in message:
            return StateIntegrityError("state_constraint_violation", "State Store constraint rejected the write.")
        return StateStoreError("state_write_failed", "State Store transaction failed.")
