# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Canonical State Store v2 export and empty-workspace import bundles."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .artifacts import ContentAddressedArtifactRepository, normalize_workspace_id
from .connections import immediate_transaction, verify_database_integrity
from .errors import ArtifactStoreError, StateConflictError, StateIntegrityError, StateStoreError
from .migration import (
    FORMAT_VERSION,
    WorkspaceFileLock,
    _PRIMARY_KEYS,
    canonical_digest,
    canonical_json_bytes,
)
from .migrations import apply_migrations, schema_hash
from .sqlite_store import SQLiteWorkspaceRepository


BUNDLE_FORMAT = "synapse-state-bundle"
BUNDLE_TABLES = (
    "workspaces",
    "workspace_revisions",
    "change_log",
    "scope_snapshots",
    "targets",
    "entities",
    "entity_relations",
    "findings",
    "review_events",
    "evidence",
    "entity_evidence",
    "actions",
    "authority_grants",
    "authority_grant_revisions",
    "step_ups",
    "request_states",
    "budget_windows",
    "action_dispatches",
    "artifacts",
    "evidence_artifacts",
    "tasks",
    "task_events",
    "task_dispatch_links",
    "execution_result_links",
    "reconciliations",
    "authority_runtime_payloads",
    "authority_repository_revisions",
    "authority_decisions",
    "artifact_resource_refs",
    "checkpoint_leases",
    "audit_events",
    "migration_runs",
    "migration_orphans",
    "id_mappings",
)
_TABLE = re.compile(r"^[a-z_]+$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_BUNDLE_LIMIT = 256 * 1024 * 1024


class StateBundleService:
    def __init__(self, data_root: Path) -> None:
        self.data_root = Path(data_root).resolve(strict=False)
        self.workspaces_root = self.data_root / "workspaces"

    def export(self, workspace_id: str, output: Path) -> dict[str, Any]:
        wid = normalize_workspace_id(workspace_id)
        root = self.workspaces_root / wid
        repository = SQLiteWorkspaceRepository(wid, root)
        with WorkspaceFileLock(root).hold():
            payload = self._payload(repository)
            destination = Path(output).resolve(strict=False)
            if destination.exists():
                existing = self.read_manifest(destination)
                if existing.get("contentDigest") == payload["contentDigest"]:
                    return self._result(destination, payload)
                raise StateConflictError("bundle_destination_conflict", "Export destination contains a different bundle.")
            temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
            temporary.mkdir(parents=True, exist_ok=False, mode=0o700)
            try:
                self._copy_artifacts(repository, temporary, payload["artifacts"])
                self._write_file(temporary / "bundle.json", canonical_json_bytes(payload) + b"\n")
                os.replace(temporary, destination)
                self._fsync_directory(destination.parent)
            except BaseException:
                self._remove_empty_tree(temporary)
                raise
            return self._result(destination, payload)

    def import_bundle(self, bundle: Path, *, workspace_id: str | None = None) -> dict[str, Any]:
        supplied = Path(bundle)
        if supplied.is_symlink():
            raise StateIntegrityError("bundle_path_invalid", "State bundle cannot be a symbolic link.")
        try:
            source = supplied.resolve(strict=True)
        except OSError as exc:
            raise StateIntegrityError("bundle_path_invalid", "State bundle path is unavailable.") from exc
        payload = self.read_manifest(source)
        source_wid = normalize_workspace_id(str(payload.get("workspaceId") or ""))
        destination_wid = normalize_workspace_id(workspace_id or source_wid)
        if destination_wid != source_wid:
            raise StateIntegrityError("bundle_cross_workspace", "State bundles cannot be rebound to another workspace identity.")
        self._validate_payload(payload, source_wid)
        self._validate_artifacts(source, payload["artifacts"])
        root = self.workspaces_root / destination_wid
        if root.exists() and any(root.iterdir()):
            raise StateConflictError("bundle_identity_conflict", "Import destination is not an empty workspace.")
        with WorkspaceFileLock(root).hold():
            repository = SQLiteWorkspaceRepository(destination_wid, root)
            for artifact in payload["artifacts"]:
                record = repository.artifacts.ingest_path(
                    source / artifact["path"],
                    media_type=str(artifact["mediaType"]),
                    origin="state-bundle-import",
                )
                if record.digest != artifact["digest"] or record.size != int(artifact["size"]):
                    raise StateIntegrityError("bundle_artifact_hash_mismatch", "Imported artifact content differs from its manifest.")
            with repository.connection_factory.connect() as connection:
                apply_migrations(connection)
                with immediate_transaction(connection):
                    for table in BUNDLE_TABLES:
                        for row in payload["tables"].get(table, []):
                            self._insert_row(connection, table, row)
                    connection.execute(
                        "INSERT OR REPLACE INTO store_metadata(key, value) VALUES('import_bundle_digest', ?)",
                        (payload["contentDigest"],),
                    )
                verify_database_integrity(connection)
            imported = self._payload(repository)
            if imported["contentDigest"] != payload["contentDigest"]:
                raise StateIntegrityError("bundle_semantic_mismatch", "Imported state is not semantically identical to the bundle.")
            self._write_file(
                root / "state-v2" / "imports" / "bundle-status.json",
                canonical_json_bytes(
                    {
                        "contentDigest": payload["contentDigest"],
                        "format": BUNDLE_FORMAT,
                        "formatVersion": FORMAT_VERSION,
                        "workspaceId": destination_wid,
                    }
                )
                + b"\n",
            )
            return {"contentDigest": payload["contentDigest"], "revision": payload["revision"], "workspaceId": destination_wid}

    def semantic_payload(self, workspace_id: str) -> dict[str, Any]:
        wid = normalize_workspace_id(workspace_id)
        return self._payload(SQLiteWorkspaceRepository(wid, self.workspaces_root / wid))

    @staticmethod
    def read_manifest(bundle: Path) -> dict[str, Any]:
        root = Path(bundle)
        if root.is_symlink() or not root.is_dir():
            raise StateIntegrityError("bundle_path_invalid", "State bundle must be a regular directory.")
        path = root / "bundle.json"
        if path.is_symlink() or not path.is_file():
            raise StateIntegrityError("bundle_manifest_missing", "State bundle manifest is missing.")
        if path.stat(follow_symlinks=False).st_size > _BUNDLE_LIMIT:
            raise StateIntegrityError("bundle_manifest_limit", "State bundle manifest exceeds the size limit.")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StateIntegrityError("bundle_manifest_invalid", "State bundle manifest is invalid.") from exc
        if not isinstance(value, dict):
            raise StateIntegrityError("bundle_manifest_invalid", "State bundle manifest must be an object.")
        return value

    def _payload(self, repository: SQLiteWorkspaceRepository) -> dict[str, Any]:
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            verify_database_integrity(connection)
            revision_row = connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id=?", (repository.workspace_id,)
            ).fetchone()
            if revision_row is None:
                raise StateStoreError("workspace_not_initialized", "Workspace is not initialized in State Store v2.")
            tables: dict[str, list[dict[str, Any]]] = {}
            for table in BUNDLE_TABLES:
                columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]
                if not columns:
                    raise StateIntegrityError("bundle_table_missing", f"State table is missing: {table}")
                primary = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})") if int(row[5]) > 0]
                order = primary or columns
                records = []
                for values in connection.execute(
                    f"SELECT {','.join(columns)} FROM {table} ORDER BY {','.join(order)}"
                ):
                    records.append({column: value for column, value in zip(columns, values)})
                tables[table] = records
        artifacts = [
            {
                "artifactId": row["artifact_id"],
                "digest": row["digest"],
                "mediaType": row["media_type"],
                "path": f"artifacts/sha256/{row['digest'][:2]}/{row['digest']}",
                "size": int(row["size"]),
            }
            for row in tables["artifacts"]
        ]
        unsigned = {
            "artifacts": artifacts,
            "format": BUNDLE_FORMAT,
            "formatVersion": FORMAT_VERSION,
            "revision": int(revision_row[0]),
            "schemaHash": schema_hash(),
            "tables": tables,
            "workspaceId": repository.workspace_id,
        }
        payload = {**unsigned, "contentDigest": canonical_digest(unsigned)}
        self._validate_payload(payload, repository.workspace_id)
        return payload

    def _copy_artifacts(self, repository: SQLiteWorkspaceRepository, destination: Path, artifacts: Sequence[Mapping[str, Any]]) -> None:
        for artifact in artifacts:
            source = repository.artifacts.resolve(str(artifact["artifactId"]), workspace_id=repository.workspace_id)
            target = destination / str(artifact["path"])
            self._stream_copy(source, target, int(artifact["size"]))

    @staticmethod
    def _stream_copy(source: Path, destination: Path, expected_size: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        size = 0
        try:
            with os.fdopen(descriptor, "rb") as reader:
                descriptor = -1
                with destination.open("xb") as writer:
                    os.chmod(destination, 0o600)
                    while chunk := reader.read(1024 * 1024):
                        size += len(chunk)
                        writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
            if size != expected_size:
                raise StateIntegrityError("bundle_artifact_size_mismatch", "Artifact size changed during bundle export.")
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _validate_payload(payload: Mapping[str, Any], workspace_id: str) -> None:
        if payload.get("format") != BUNDLE_FORMAT or payload.get("formatVersion") != FORMAT_VERSION:
            raise StateIntegrityError("bundle_format_unsupported", "State bundle format is unsupported.")
        if str(payload.get("workspaceId") or "") != workspace_id:
            raise StateIntegrityError("bundle_cross_workspace", "State bundle workspace identity is not canonical.")
        unsigned = dict(payload)
        claimed = str(unsigned.pop("contentDigest", ""))
        if canonical_digest(unsigned) != claimed:
            raise StateIntegrityError("bundle_content_digest_mismatch", "State bundle content digest does not match.")
        if payload.get("schemaHash") != schema_hash():
            raise StateIntegrityError("bundle_schema_unsupported", "State bundle schema is unsupported.")
        if not isinstance(payload.get("tables"), Mapping) or not isinstance(payload.get("artifacts"), list):
            raise StateIntegrityError("bundle_manifest_invalid", "State bundle table or artifact manifest is invalid.")
        for table in BUNDLE_TABLES:
            records = payload["tables"].get(table)
            if not isinstance(records, list):
                raise StateIntegrityError("bundle_table_missing", f"State bundle table is missing: {table}")
            seen: set[tuple[Any, ...]] = set()
            for row in records:
                if not isinstance(row, Mapping):
                    raise StateIntegrityError("bundle_row_invalid", f"State bundle row is invalid: {table}")
                identity = tuple(row.get(column) for column in _PRIMARY_KEYS[table])
                if identity in seen:
                    raise StateIntegrityError("bundle_duplicate_identity", f"State bundle contains a duplicate identity: {table}")
                seen.add(identity)
                bound = row.get("workspace_id")
                if bound is not None and str(bound) != workspace_id:
                    raise StateIntegrityError("bundle_cross_workspace", "State bundle contains cross-workspace rows.")
        workspaces = payload["tables"]["workspaces"]
        if len(workspaces) != 1 or str(workspaces[0].get("workspace_id") or "") != workspace_id:
            raise StateIntegrityError("bundle_identity_conflict", "State bundle workspace identity is invalid.")
        expected_artifacts = [
            {
                "artifactId": row["artifact_id"],
                "digest": row["digest"],
                "mediaType": row["media_type"],
                "path": f"artifacts/sha256/{row['digest'][:2]}/{row['digest']}",
                "size": int(row["size"]),
            }
            for row in payload["tables"]["artifacts"]
        ]
        for artifact in payload["artifacts"]:
            digest = str(artifact.get("digest") or "")
            if (
                not _DIGEST.fullmatch(digest)
                or artifact.get("path") != f"artifacts/sha256/{digest[:2]}/{digest}"
            ):
                raise StateIntegrityError(
                    "bundle_artifact_path_invalid",
                    "State bundle artifact path or identity is invalid.",
                )
        if payload["artifacts"] != expected_artifacts:
            raise StateIntegrityError(
                "bundle_artifact_manifest_mismatch",
                "State bundle artifact manifest does not match artifact metadata.",
            )

    @staticmethod
    def _validate_artifacts(bundle: Path, artifacts: Sequence[Mapping[str, Any]]) -> None:
        seen: set[str] = set()
        for artifact in artifacts:
            digest = str(artifact.get("digest") or "")
            relative = str(artifact.get("path") or "")
            expected = f"artifacts/sha256/{digest[:2]}/{digest}"
            if not _DIGEST.fullmatch(digest) or relative != expected or digest in seen:
                raise StateIntegrityError("bundle_artifact_path_invalid", "State bundle artifact path or identity is invalid.")
            seen.add(digest)
            path = bundle / relative
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(bundle.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise StateIntegrityError("bundle_artifact_traversal", "State bundle artifact escapes its bundle.") from exc
            if path.is_symlink() or not path.is_file():
                raise StateIntegrityError("bundle_artifact_path_invalid", "State bundle artifact is not a regular file.")
            from hashlib import sha256

            digest_value = sha256()
            size = 0
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest_value.update(chunk)
                    size += len(chunk)
            if digest_value.hexdigest() != digest or size != int(artifact.get("size") or -1):
                raise StateIntegrityError("bundle_artifact_hash_mismatch", "State bundle artifact does not match its manifest.")

    @staticmethod
    def _insert_row(connection: Any, table: str, row: Mapping[str, Any]) -> None:
        if table not in BUNDLE_TABLES or not _TABLE.fullmatch(table):
            raise StateIntegrityError("bundle_table_invalid", "State bundle table is invalid.")
        columns = tuple(row)
        if not columns or any(not _TABLE.fullmatch(column) for column in columns):
            raise StateIntegrityError("bundle_column_invalid", "State bundle row contains an invalid column.")
        placeholders = ",".join("?" for _ in columns)
        try:
            connection.execute(
                f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})",
                tuple(row[column] for column in columns),
            )
        except Exception as exc:
            raise StateIntegrityError("bundle_duplicate_identity", "State bundle identity conflicts during import.") from exc

    @staticmethod
    def _write_file(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("xb") as handle:
            os.chmod(path, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _remove_empty_tree(cls, path: Path) -> None:
        if not path.exists():
            return
        for child in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            try:
                if child.is_file() and not child.is_symlink():
                    child.unlink()
                elif child.is_dir() and not child.is_symlink():
                    child.rmdir()
            except FileNotFoundError:
                pass
        try:
            path.rmdir()
        except FileNotFoundError:
            pass

    @staticmethod
    def _result(destination: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "artifactCount": len(payload["artifacts"]),
            "contentDigest": payload["contentDigest"],
            "path": str(destination),
            "revision": payload["revision"],
            "workspaceId": payload["workspaceId"],
        }


__all__ = ["BUNDLE_FORMAT", "BUNDLE_TABLES", "StateBundleService"]
