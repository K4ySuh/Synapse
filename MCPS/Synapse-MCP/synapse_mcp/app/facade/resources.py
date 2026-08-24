# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Opaque, reauthorized references for local Synapse artifacts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
import json
import mimetypes
import os
from pathlib import Path
import secrets
from typing import Any

from synapse_mcp.core import evidence, paths, workspace
from synapse_mcp.core.atomic_io import atomic_write_text, file_lock

from .contracts import FacadeCallContext, ResolvedArtifact, ResourceReference


class ResourceAccessError(PermissionError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class _ResourceRecord:
    reference: ResourceReference
    path: Path
    workspace_id: str
    principal_id: str
    authority_session_id: str
    durable_artifact: bool = False


@dataclass(frozen=True, slots=True)
class _DirectoryLimits:
    file_count: int
    total_bytes: int
    per_file_bytes: int
    relative_path_bytes: int
    depth: int


@dataclass(frozen=True, slots=True)
class _DirectoryFile:
    path: Path
    relative: str
    size: int


def _directory_files(path: Path, limits: _DirectoryLimits) -> tuple[_DirectoryFile, ...]:
    """Stream a bounded tree inventory before any file content is hashed."""

    files: list[_DirectoryFile] = []
    total_bytes = 0
    directories = [path]
    while directories:
        current = directories.pop()
        try:
            entries = os.scandir(current)
        except OSError as exc:
            raise ResourceAccessError(
                "resource_directory_unreadable",
                "Directory resource tree could not be enumerated",
            ) from exc
        with entries:
            for entry in entries:
                item = Path(entry.path)
                relative_path = item.relative_to(path)
                relative = relative_path.as_posix()
                path_bytes = len(relative.encode("utf-8", errors="surrogateescape"))
                if path_bytes > limits.relative_path_bytes:
                    raise ResourceAccessError(
                        "resource_directory_path_limit",
                        "Directory resource relative path exceeds the configured byte limit",
                    )
                if len(relative_path.parts) > limits.depth:
                    raise ResourceAccessError(
                        "resource_directory_depth_limit",
                        "Directory resource exceeds the configured depth limit",
                    )
                if entry.is_symlink():
                    raise ResourceAccessError(
                        "resource_symlink_forbidden",
                        "Directory resource trees cannot contain symbolic links",
                    )
                try:
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(item)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        raise ResourceAccessError(
                            "resource_non_regular_file",
                            "Directory resource trees may contain only directories and regular files",
                        )
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError as exc:
                    raise ResourceAccessError(
                        "resource_directory_unreadable",
                        "Directory resource entry could not be inspected",
                    ) from exc
                if size > limits.per_file_bytes:
                    raise ResourceAccessError(
                        "resource_directory_file_bytes_limit",
                        "Directory resource file exceeds the configured byte limit",
                    )
                if len(files) >= limits.file_count:
                    raise ResourceAccessError(
                        "resource_directory_file_count_limit",
                        "Directory resource exceeds the configured file-count limit",
                    )
                total_bytes += size
                if total_bytes > limits.total_bytes:
                    raise ResourceAccessError(
                        "resource_directory_total_bytes_limit",
                        "Directory resource exceeds the configured total-byte limit",
                    )
                files.append(_DirectoryFile(path=item, relative=relative, size=size))
    return tuple(sorted(files, key=lambda item: item.relative))


def _path_version(path: Path, directory_limits: _DirectoryLimits) -> tuple[str, int]:
    digest = sha256()
    size = 0
    files = (
        (_DirectoryFile(path=path, relative=path.name, size=path.stat().st_size),)
        if path.is_file()
        else _directory_files(path, directory_limits)
    )
    for item in files:
        relative = item.relative
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        file_size = 0
        with item.path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > directory_limits.per_file_bytes and path.is_dir():
                    raise ResourceAccessError(
                        "resource_directory_file_bytes_limit",
                        "Directory resource file grew beyond the configured byte limit while hashing",
                    )
                if size + len(chunk) > directory_limits.total_bytes and path.is_dir():
                    raise ResourceAccessError(
                        "resource_directory_total_bytes_limit",
                        "Directory resource grew beyond the configured total-byte limit while hashing",
                    )
                digest.update(chunk)
                size += len(chunk)
    return digest.hexdigest(), size


def _directory_manifest(path: Path, directory_limits: _DirectoryLimits) -> str:
    files = [
        {"name": item.relative, "bytes": item.size}
        for item in _directory_files(path, directory_limits)
    ]
    return json.dumps({"type": "directory", "files": files}, separators=(",", ":"))


class ResourceReferenceService:
    """Server-held resource map; public references contain no local paths.

    Phase 3B keeps the default process-local map. A modern transport supplies a
    private state path so references survive restarts and can be reauthorized
    consistently by multiple workers.
    """

    def __init__(
        self,
        *,
        allowed_roots: tuple[Path, ...] | None = None,
        max_read_bytes: int = 16 * 1024 * 1024,
        max_directory_files: int = 10_000,
        max_directory_total_bytes: int = 2 * 1024 * 1024 * 1024,
        max_directory_file_bytes: int = 512 * 1024 * 1024,
        max_directory_path_bytes: int = 4096,
        max_directory_depth: int = 64,
        state_path: Path | None = None,
    ) -> None:
        configured = allowed_roots or (
            workspace.WORKSPACES_DIR,
            workspace.REPORTS_DIR,
            evidence.EVIDENCE_DIR,
            paths.DATA_DIR,
            paths.REPORTS_DIR,
        )
        self._allowed_roots = tuple(root.resolve() for root in configured)
        self._max_read_bytes = max_read_bytes
        limit_values = (
            max_directory_files,
            max_directory_total_bytes,
            max_directory_file_bytes,
            max_directory_path_bytes,
            max_directory_depth,
        )
        if any(int(value) < 1 for value in limit_values):
            raise ValueError("Directory resource limits must be positive integers")
        self._directory_limits = _DirectoryLimits(*(int(value) for value in limit_values))
        self._state_path = Path(state_path).resolve() if state_path is not None else None
        self._records: dict[str, _ResourceRecord] = {}

    def issue(
        self,
        path: str | Path,
        *,
        workspace_id: str,
        context: FacadeCallContext,
        artifact_type: str,
        media_type: str | None = None,
    ) -> ResourceReference:
        resolved = self._validated_path(Path(path))
        token = f"resource-{secrets.token_urlsafe(24)}"
        trusted_workspace = workspace.normalize_workspace_id(workspace_id)
        from synapse_mcp.state.runtime import ActivatedWorkspaceRepository, opaque_ref
        from synapse_mcp.state.selector import selected_store_version

        workspace_root = workspace.workspace_path(trusted_workspace)
        durable_repository = (
            ActivatedWorkspaceRepository(trusted_workspace, workspace_root)
            if selected_store_version(workspace_root) == "sqlite-v2"
            else None
        )
        artifact = (
            durable_repository.artifacts.ingest_path(
                resolved,
                media_type=media_type or mimetypes.guess_type(resolved.name)[0] or "application/octet-stream",
                origin="modern.resource",
            )
            if durable_repository is not None
            else None
        )
        version, size = (
            (artifact.digest, artifact.size)
            if artifact is not None
            else _path_version(resolved, self._directory_limits)
        )
        reference = ResourceReference(
            reference=token,
            artifact_type=artifact_type or "artifact",
            media_type=(
                media_type
                or ("application/vnd.synapse.directory+json" if resolved.is_dir() else None)
                or mimetypes.guess_type(resolved.name)[0]
                or "application/octet-stream"
            ),
            version=version,
            size=size,
        )
        record = _ResourceRecord(
            reference=reference,
            path=artifact.path if artifact is not None else resolved,
            workspace_id=trusted_workspace,
            principal_id=opaque_ref(context.principal_id) if artifact is not None else context.principal_id,
            authority_session_id=opaque_ref(context.authority_session_id) if artifact is not None else context.authority_session_id,
            durable_artifact=artifact is not None,
        )
        if durable_repository is not None and artifact is not None:
            durable_repository.issue_resource(
                artifact,
                reference=token,
                principal_id=context.principal_id,
                authority_session_id=context.authority_session_id,
                artifact_type=reference.artifact_type,
                media_type=reference.media_type,
            )
        elif self._state_path is None:
            self._records[token] = record
        else:
            with file_lock(self._state_path):
                state = self._read_state()
                state["records"][token] = self._serialize_record(record)
                self._write_state(state)
        return reference

    def allows_output_path(self, path: str | Path) -> bool:
        """Return whether a prospective absolute output stays in trusted roots."""

        resolved = Path(path).expanduser().resolve(strict=False)
        return any(_is_relative_to(resolved, root) for root in self._allowed_roots)

    def resolve(self, reference: str, *, context: FacadeCallContext) -> ResolvedArtifact:
        record = self._record(reference, context=context)
        if record is None:
            raise ResourceAccessError("resource_reference_invalid", "Opaque resource reference is unknown")
        if not _binding_matches(record.principal_id, context.principal_id):
            raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
        if not _binding_matches(record.authority_session_id, context.authority_session_id):
            raise ResourceAccessError("resource_authority_mismatch", "Resource authority binding does not match")
        trusted_workspace = workspace.normalize_workspace_id(context.workspace_id)
        if not trusted_workspace or not secrets.compare_digest(record.workspace_id, trusted_workspace):
            raise ResourceAccessError("resource_workspace_mismatch", "Resource workspace binding does not match")
        resolved = self._validated_path(record.path)
        version, size = _record_version(record, resolved, self._directory_limits)
        if not secrets.compare_digest(version, record.reference.version) or size != record.reference.size:
            raise ResourceAccessError("resource_version_stale", "Resource changed after the reference was issued")
        content = (
            _directory_manifest(resolved, self._directory_limits).encode("utf-8")
            if resolved.is_dir()
            else resolved.read_bytes()
        )
        if len(content) > self._max_read_bytes:
            raise ResourceAccessError("resource_too_large", "Resource exceeds the bounded read limit")
        try:
            rendered = content.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            rendered = base64.b64encode(content).decode("ascii")
            encoding = "base64"
        return ResolvedArtifact(reference=record.reference, encoding=encoding, content=rendered)

    def resolve_path(self, reference: str, *, context: FacadeCallContext) -> Path:
        """Resolve a bound opaque reference for server-internal action input only."""

        record = self._record(reference, context=context)
        if record is None:
            raise ResourceAccessError("resource_reference_invalid", "Opaque resource reference is unknown")
        if not _binding_matches(record.principal_id, context.principal_id):
            raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
        if not _binding_matches(record.authority_session_id, context.authority_session_id):
            raise ResourceAccessError("resource_authority_mismatch", "Resource authority binding does not match")
        trusted_workspace = workspace.normalize_workspace_id(context.workspace_id)
        if not trusted_workspace or not secrets.compare_digest(record.workspace_id, trusted_workspace):
            raise ResourceAccessError("resource_workspace_mismatch", "Resource workspace binding does not match")
        resolved = self._validated_path(record.path)
        version, size = _record_version(record, resolved, self._directory_limits)
        if not secrets.compare_digest(version, record.reference.version) or size != record.reference.size:
            raise ResourceAccessError("resource_version_stale", "Resource changed after the reference was issued")
        return resolved

    def workspace_hint(self, reference: str, *, principal_id: str) -> str:
        """Return a principal-bound workspace hint for adapter identity resolution."""

        context_binding = _context_reference_parts(reference)
        if context_binding is not None:
            workspace_id, _artifact_id, principal_ref, _authority_ref = context_binding
            if not secrets.compare_digest(principal_ref, sha256(principal_id.encode("utf-8")).hexdigest()):
                raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
            return workspace_id
        record = self._record(reference)
        if record is None:
            raise ResourceAccessError("resource_reference_invalid", "Opaque resource reference is unknown")
        if not _binding_matches(record.principal_id, principal_id):
            raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
        return record.workspace_id

    def sanitize_result(
        self,
        value: Any,
        *,
        workspace_id: str,
        context: FacadeCallContext,
    ) -> tuple[Any, list[ResourceReference]]:
        """Replace local output paths with opaque references in a model-facing result."""

        references: list[ResourceReference] = []

        def visit(item: Any, key: str = "") -> Any:
            if isinstance(item, dict):
                return {str(name): visit(child, str(name)) for name, child in item.items()}
            if isinstance(item, (list, tuple)):
                return [visit(child, key) for child in item]
            if isinstance(item, Path):
                item = str(item)
            if isinstance(item, str) and _is_path_key(key) and Path(item).is_absolute():
                candidate = Path(item)
                exportable_directory = candidate.is_dir() and "burp-dumps" in candidate.parts
                if candidate.is_file() or exportable_directory:
                    try:
                        reference = self.issue(
                            candidate,
                            workspace_id=workspace_id,
                            context=context,
                            artifact_type=_artifact_type(key),
                        )
                    except ResourceAccessError:
                        return {"localPath": "withheld", "reason": "resource_not_exportable"}
                    references.append(reference)
                    return {"resourceRef": reference.reference, "version": reference.version}
                return {"localPath": "withheld", "reason": "resource_not_readable"}
            return item

        return visit(value), references

    def _validated_path(self, candidate: Path) -> Path:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ResourceAccessError("resource_not_found", "Resource does not exist") from exc
        if not (resolved.is_file() or resolved.is_dir()):
            raise ResourceAccessError("resource_not_readable", "Resource references must identify files or directories")
        if not any(_is_relative_to(resolved, root) for root in self._allowed_roots):
            raise ResourceAccessError("resource_outside_allowed_roots", "Resource is outside Synapse artifact roots")
        return resolved

    def _record(
        self,
        reference: str,
        *,
        context: FacadeCallContext | None = None,
    ) -> _ResourceRecord | None:
        context_binding = _context_reference_parts(reference)
        if context_binding is not None:
            if context is None:
                return None
            workspace_id, artifact_id, principal_ref, authority_ref = context_binding
            trusted_workspace = workspace.normalize_workspace_id(context.workspace_id)
            if not secrets.compare_digest(workspace_id, trusted_workspace):
                raise ResourceAccessError("resource_workspace_mismatch", "Resource workspace binding does not match")
            if not secrets.compare_digest(principal_ref, sha256(context.principal_id.encode("utf-8")).hexdigest()):
                raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
            if not secrets.compare_digest(authority_ref, sha256(context.authority_session_id.encode("utf-8")).hexdigest()):
                raise ResourceAccessError("resource_authority_mismatch", "Resource authority binding does not match")
            from synapse_mcp.state.runtime import ActivatedWorkspaceRepository, opaque_ref
            from synapse_mcp.state.selector import selected_store_version

            root = workspace.workspace_path(workspace_id)
            if selected_store_version(root) != "sqlite-v2":
                return None
            value = ActivatedWorkspaceRepository(workspace_id, root).artifact_record(artifact_id)
            if value is None:
                return None
            return _ResourceRecord(
                reference=ResourceReference(
                    reference=reference,
                    artifact_type="evidence",
                    media_type=str(value["mediaType"]),
                    version=str(value["version"]),
                    size=int(value["size"]),
                ),
                path=Path(value["path"]),
                workspace_id=workspace_id,
                principal_id=opaque_ref(context.principal_id),
                authority_session_id=opaque_ref(context.authority_session_id),
                durable_artifact=True,
            )
        if self._state_path is None:
            local = self._records.get(reference)
            if local is not None:
                return local
        from synapse_mcp.state.runtime import ActivatedWorkspaceRepository
        from synapse_mcp.state.selector import selected_store_version

        if workspace.WORKSPACES_DIR.exists():
            for root in sorted(workspace.WORKSPACES_DIR.iterdir()):
                if not root.is_dir() or selected_store_version(root) != "sqlite-v2":
                    continue
                value = ActivatedWorkspaceRepository(root.name, root).resource_record(reference)
                if value is None:
                    continue
                return _ResourceRecord(
                    reference=ResourceReference(
                        reference=reference,
                        artifact_type=str(value["artifactType"]),
                        media_type=str(value["mediaType"]),
                        version=str(value["version"]),
                        size=int(value["size"]),
                    ),
                    path=Path(value["path"]),
                    workspace_id=str(value["workspaceId"]),
                    principal_id=str(value["principalRef"]),
                    authority_session_id=str(value["authoritySessionRef"]),
                    durable_artifact=True,
                )
        if self._state_path is None:
            return None
        with file_lock(self._state_path):
            raw = self._read_state()["records"].get(reference)
        if raw is None:
            return None
        try:
            return self._deserialize_record(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise ResourceAccessError("resource_record_corrupt", "Opaque resource record is invalid") from exc

    def _read_state(self) -> dict[str, Any]:
        assert self._state_path is not None
        if not self._state_path.exists():
            return {"version": 1, "records": {}}
        try:
            value = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ResourceAccessError("resource_store_corrupt", "Opaque resource store is unreadable") from exc
        if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("records"), dict):
            raise ResourceAccessError("resource_store_corrupt", "Opaque resource store has an unknown schema")
        return value

    def _write_state(self, state: dict[str, Any]) -> None:
        assert self._state_path is not None
        atomic_write_text(
            self._state_path,
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            mode=0o600,
        )

    @staticmethod
    def _serialize_record(record: _ResourceRecord) -> dict[str, Any]:
        return {
            "reference": record.reference.model_dump(mode="json", by_alias=True),
            "path": str(record.path),
            "workspaceId": record.workspace_id,
            "principalId": record.principal_id,
            "authoritySessionId": record.authority_session_id,
            "durableArtifact": record.durable_artifact,
        }

    @staticmethod
    def _deserialize_record(value: Any) -> _ResourceRecord:
        if not isinstance(value, dict):
            raise TypeError("resource record must be an object")
        return _ResourceRecord(
            reference=ResourceReference.model_validate(value["reference"]),
            path=Path(value["path"]),
            workspace_id=str(value["workspaceId"]),
            principal_id=str(value["principalId"]),
            authority_session_id=str(value["authoritySessionId"]),
            durable_artifact=bool(value.get("durableArtifact")),
        )


def _context_reference_parts(reference: str) -> tuple[str, str, str, str] | None:
    if not reference.startswith("context-artifact:"):
        return None
    try:
        workspace_id, remainder = reference.removeprefix("context-artifact:").split(":", 1)
        artifact_id, principal_ref, authority_ref = remainder.rsplit(":", 2)
    except ValueError:
        return None
    if workspace.normalize_workspace_id(workspace_id) != workspace_id or not artifact_id:
        return None
    if any(len(value) != 64 or any(character not in "0123456789abcdef" for character in value) for value in (principal_ref, authority_ref)):
        return None
    return workspace_id, artifact_id, principal_ref, authority_ref


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _binding_matches(stored: str, supplied: str) -> bool:
    if str(stored).startswith("sha256:"):
        from synapse_mcp.state.runtime import opaque_matches

        return opaque_matches(stored, supplied)
    return secrets.compare_digest(stored, supplied)


def _record_version(
    record: _ResourceRecord,
    path: Path,
    directory_limits: _DirectoryLimits,
) -> tuple[str, int]:
    if record.durable_artifact:
        content = path.read_bytes()
        return sha256(content).hexdigest(), len(content)
    return _path_version(path, directory_limits)


def _is_path_key(key: str) -> bool:
    normalized = key.lower().replace("_", "")
    return (
        normalized == "path"
        or normalized.endswith("path")
        or normalized.endswith("paths")
        or normalized.endswith("dir")
        or normalized in {
            "findingsdocument",
            "reportfile",
            "artifactfile",
            "historyjsonl",
            "manifest",
        }
    )


def _artifact_type(key: str) -> str:
    normalized = key.lower()
    if "report" in normalized:
        return "report"
    if "evidence" in normalized:
        return "evidence"
    if "finding" in normalized:
        return "finding_document"
    return "artifact"
