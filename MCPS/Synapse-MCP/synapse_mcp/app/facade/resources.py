# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Opaque, reauthorized references for local Synapse artifacts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
import mimetypes
from pathlib import Path
import secrets
from typing import Any

from synapse_mcp.core import evidence, paths, workspace

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
    """Server-held resource map; public references contain no local paths."""

    def __init__(
        self,
        *,
        allowed_roots: tuple[Path, ...] | None = None,
        max_read_bytes: int = 16 * 1024 * 1024,
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
        self._records[token] = _ResourceRecord(
            reference=reference,
            path=resolved,
            workspace_id=workspace.normalize_workspace_id(workspace_id),
            principal_id=context.principal_id,
            authority_session_id=context.authority_session_id,
        )
        return reference

    def resolve(self, reference: str, *, context: FacadeCallContext) -> ResolvedArtifact:
        record = self._records.get(reference)
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
