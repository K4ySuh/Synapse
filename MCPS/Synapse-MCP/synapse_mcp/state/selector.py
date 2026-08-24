# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Workspace store selection with an absent-selector JSON-v1 default."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from .artifacts import normalize_workspace_id
from .contracts import WorkspaceRepositoryBundle
from .errors import StateSelectionError
from .json_v1 import JsonV1EvidenceRepository, JsonV1WorkspaceRepository
from .runtime import ActivatedWorkspaceRepository


StoreVersion = Literal["json-v1", "sqlite-v2"]


def selector_path(workspace_root: Path) -> Path:
    return Path(workspace_root) / "state-v2" / "store-selector.json"


def selected_store_version(workspace_root: Path) -> StoreVersion:
    path = selector_path(workspace_root)
    if not path.exists():
        return "json-v1"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StateSelectionError("store_selector_corrupt", "Workspace store selector is unreadable.") from exc
    if not isinstance(value, dict) or value.get("version") != 1:
        raise StateSelectionError("store_selector_corrupt", "Workspace store selector schema is invalid.")
    selected = value.get("authoritativeStore")
    if selected not in {"json-v1", "sqlite-v2"}:
        raise StateSelectionError("store_selector_unknown", "Workspace store selector names an unknown store.")
    return selected


def write_store_selector(workspace_root: Path, payload: dict) -> Path:
    """Install one fsynced selector without exposing an intermediate file."""

    path = selector_path(workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def assert_json_v1_write_allowed(path: Path) -> None:
    """Fail closed when a legacy writer targets an activated workspace."""

    candidate = Path(path).resolve(strict=False)
    parts = candidate.parts
    indexes = [index for index, part in enumerate(parts) if part == "workspaces"]
    if not indexes:
        return
    index = indexes[-1]
    if len(parts) <= index + 1:
        return
    workspace_root = Path(*parts[: index + 2])
    if selected_store_version(workspace_root) == "sqlite-v2":
        relative = candidate.relative_to(workspace_root)
        if relative.parts and relative.parts[0] == "state-v2":
            return
        raise StateSelectionError(
            "json_v1_write_after_activation",
            "JSON-v1 is immutable after SQLite-v2 activation.",
        )


def repository_bundle(workspace_id: str, workspaces_root: Path) -> WorkspaceRepositoryBundle:
    normalized_workspace_id = normalize_workspace_id(workspace_id)
    root = Path(workspaces_root) / normalized_workspace_id
    selected = selected_store_version(root)
    if selected == "json-v1":
        return WorkspaceRepositoryBundle(
            store_version=selected,
            workspace=JsonV1WorkspaceRepository(normalized_workspace_id),
            evidence=JsonV1EvidenceRepository(),
        )
    repository = ActivatedWorkspaceRepository(normalized_workspace_id, root)
    return WorkspaceRepositoryBundle(
        store_version=selected,
        workspace=repository,
        evidence=_SQLiteEvidenceBoundary(),
        artifacts=repository.artifacts,
    )


class _SQLiteEvidenceBoundary:
    """No standalone v2 evidence writes: use the repository revision API."""

    def record(self, event_type: str, summary: str, data: dict | None = None) -> dict:
        raise StateSelectionError(
            "sqlite_evidence_transaction_required",
            "SQLite-v2 evidence must commit through a workspace revision transaction.",
        )
