# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Crash-safe State Store v2 bootstrap for genuinely new workspaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any

from .artifacts import normalize_workspace_id
from .contracts import AuditRecord, TargetRecord, WorkspaceRecord
from .errors import StateConflictError, StateIntegrityError
from .migration import WorkspaceFileLock
from .runtime import ActivatedWorkspaceRepository
from .selector import selected_store_version, write_store_selector


def _target_id(workspace_id: str, natural_key: str) -> str:
    digest = sha256(f"{workspace_id}\x1f{natural_key}".encode("utf-8")).hexdigest()
    return f"target-{digest[:24]}"


class NewWorkspaceStoreService:
    """Create or resume an unselected fresh-v2 workspace under one lock."""

    def __init__(self, workspaces_root: Path) -> None:
        self.workspaces_root = Path(workspaces_root).resolve(strict=False)

    def create(
        self,
        workspace_id: str,
        *,
        organization: str,
        notes: str,
        scope: Mapping[str, Any],
        targets: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        wid = normalize_workspace_id(workspace_id)
        root = self.workspaces_root / wid
        with WorkspaceFileLock(root).hold():
            selected = selected_store_version(root)
            repository = ActivatedWorkspaceRepository(wid, root)
            if selected == "sqlite-v2":
                return self._result(repository, created=False)
            legacy_entries = [
                path.name
                for path in root.iterdir()
                if path.name not in {".lock", "state-v2"}
            ]
            if legacy_entries:
                raise StateConflictError(
                    "fresh_workspace_legacy_content",
                    "An existing JSON-v1 workspace must be migrated and activated explicitly.",
                )
            existing = repository.workspace_document()
            if existing:
                if str(existing.get("workspaceId") or "") != wid:
                    raise StateIntegrityError(
                        "fresh_workspace_identity_mismatch",
                        "An interrupted fresh workspace has a different identity.",
                    )
                created = False
            else:
                records = tuple(
                    TargetRecord(
                        target_id=_target_id(wid, str(item.get("target") or "")),
                        natural_key=str(item.get("target") or ""),
                        kind=str(item.get("kind") or "host"),
                        payload=dict(item),
                    )
                    for item in targets
                )
                repository.initialize_fresh(
                    WorkspaceRecord(wid, organization=organization, notes=notes),
                    scope=dict(scope),
                    targets=records,
                    audit=AuditRecord(
                        event_id="workspace-create",
                        event_type="workspace.create",
                        summary=f"Created workspace {wid} in State Store v2.",
                        payload={"hosts": [item.natural_key for item in records]},
                    ),
                )
                created = True
            revision = repository.revision()
            write_store_selector(
                root,
                {
                    "activatedRevision": revision,
                    "authoritativeStore": "sqlite-v2",
                    "creationMode": "fresh-v2",
                    "version": 1,
                },
            )
            return self._result(repository, created=created)

    @staticmethod
    def _result(repository: ActivatedWorkspaceRepository, *, created: bool) -> dict[str, Any]:
        return {
            "created": created,
            "path": str(repository.workspace_root),
            "revision": repository.revision(),
            "storeVersion": "sqlite-v2",
            "workspace": repository.workspace_document(),
            "workspaceId": repository.workspace_id,
        }
