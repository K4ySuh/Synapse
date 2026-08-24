# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Opaque, reauthorized references for local Synapse artifacts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
import json
import mimetypes
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


def _file_version(path: Path) -> tuple[str, int]:
    digest = sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


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
        resolved = self._validated_file(Path(path))
        version, size = _file_version(resolved)
        token = f"resource-{secrets.token_urlsafe(24)}"
        reference = ResourceReference(
            reference=token,
            artifact_type=artifact_type or "artifact",
            media_type=media_type or mimetypes.guess_type(resolved.name)[0] or "application/octet-stream",
            version=version,
            size=size,
        )
        record = _ResourceRecord(
            reference=reference,
            path=resolved,
            workspace_id=workspace.normalize_workspace_id(workspace_id),
            principal_id=context.principal_id,
            authority_session_id=context.authority_session_id,
        )
        if self._state_path is None:
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
        record = self._record(reference)
        if record is None:
            raise ResourceAccessError("resource_reference_invalid", "Opaque resource reference is unknown")
        if not secrets.compare_digest(record.principal_id, context.principal_id):
            raise ResourceAccessError("resource_principal_mismatch", "Resource principal binding does not match")
        if not secrets.compare_digest(record.authority_session_id, context.authority_session_id):
            raise ResourceAccessError("resource_authority_mismatch", "Resource authority binding does not match")
        trusted_workspace = workspace.normalize_workspace_id(context.workspace_id)
        if not trusted_workspace or not secrets.compare_digest(record.workspace_id, trusted_workspace):
            raise ResourceAccessError("resource_workspace_mismatch", "Resource workspace binding does not match")
        resolved = self._validated_file(record.path)
        version, size = _file_version(resolved)
        if not secrets.compare_digest(version, record.reference.version) or size != record.reference.size:
            raise ResourceAccessError("resource_version_stale", "Resource changed after the reference was issued")
        if size > self._max_read_bytes:
            raise ResourceAccessError("resource_too_large", "Resource exceeds the bounded read limit")
        content = resolved.read_bytes()
        try:
            rendered = content.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            rendered = base64.b64encode(content).decode("ascii")
            encoding = "base64"
        return ResolvedArtifact(reference=record.reference, encoding=encoding, content=rendered)

    def workspace_hint(self, reference: str, *, principal_id: str) -> str:
        """Return a principal-bound workspace hint for adapter identity resolution."""

        record = self._record(reference)
        if record is None:
            raise ResourceAccessError("resource_reference_invalid", "Opaque resource reference is unknown")
        if not secrets.compare_digest(record.principal_id, principal_id):
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
                if candidate.is_file():
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

    def _validated_file(self, candidate: Path) -> Path:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ResourceAccessError("resource_not_found", "Resource does not exist") from exc
        if not resolved.is_file():
            raise ResourceAccessError("resource_not_file", "Resource references must identify files")
        if not any(_is_relative_to(resolved, root) for root in self._allowed_roots):
            raise ResourceAccessError("resource_outside_allowed_roots", "Resource is outside Synapse artifact roots")
        return resolved

    def _record(self, reference: str) -> _ResourceRecord | None:
        if self._state_path is None:
            return self._records.get(reference)
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
        )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_path_key(key: str) -> bool:
    normalized = key.lower().replace("_", "")
    return normalized == "path" or normalized.endswith("path") or normalized in {
        "findingsdocument",
        "reportfile",
        "artifactfile",
    }


def _artifact_type(key: str) -> str:
    normalized = key.lower()
    if "report" in normalized:
        return "report"
    if "evidence" in normalized:
        return "evidence"
    if "finding" in normalized:
        return "finding_document"
    return "artifact"
