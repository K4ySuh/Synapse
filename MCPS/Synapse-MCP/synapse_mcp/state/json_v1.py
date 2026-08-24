# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Compatibility adapters over the unchanged JSON-v1 implementation."""

from __future__ import annotations

from typing import Any

from .contracts import ContextRepositorySnapshot


class JsonV1WorkspaceRepository:
    def __init__(self, workspace_id: str) -> None:
        from synapse_mcp.core import workspace

        self._workspace = workspace
        self._workspace_id = workspace.normalize_workspace_id(workspace_id)

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def revision(self) -> int:
        return 0

    def snapshot(self) -> dict[str, Any]:
        return self._workspace.workspace_summary(self._workspace_id)

    def context_snapshot(self, *, since_revision: int | None = None) -> ContextRepositorySnapshot:
        root = self._workspace.workspace_path(self._workspace_id)
        targets: list[dict[str, Any]] = []
        entities: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        actions: list[dict[str, Any]] = []
        with self._workspace.workspace_lock(self._workspace_id):
            workspace_document = self._workspace._read_json(root / "workspace.json", {})
            scope_document = self._workspace._read_json(root / "scope.json", {})
            authority_document = self._workspace._read_json(root / "authority" / "state.json", {})
            target_root = root / "targets"
            for target_path in sorted(target_root.iterdir()) if target_root.is_dir() else ():
                if not target_path.is_dir():
                    continue
                target = self._workspace._read_json(target_path / "target.json", {})
                if not isinstance(target, dict) or not target:
                    continue
                target_id = str(target.get("target") or target_path.name)
                targets.append(
                    {
                        "targetId": target_id,
                        "naturalKey": target_id,
                        "kind": str(target.get("kind") or "host"),
                        "payload": target,
                        "createdRevision": 0,
                        "updatedRevision": 0,
                    }
                )
                entity_root = target_path / "entities"
                for collection, filename in self._workspace.ENTITY_FILES.items():
                    rows = self._workspace._read_json(entity_root / filename, [])
                    for index, payload in enumerate(rows if isinstance(rows, list) else []):
                        if not isinstance(payload, dict):
                            continue
                        identity = str(
                            payload.get("id")
                            or payload.get("key")
                            or payload.get("entityId")
                            or f"{target_id}:{collection}:{index}"
                        )
                        record = {
                            "entityId": identity,
                            "targetId": target_id,
                            "entityType": str(payload.get("type") or collection.removesuffix("s")),
                            "naturalKey": identity,
                            "lifecycle": str(payload.get("status") or "observed"),
                            "payload": payload,
                            "createdRevision": 0,
                            "updatedRevision": 0,
                        }
                        if collection == "findings":
                            findings.append({**record, "findingId": identity})
                        elif collection == "actions":
                            actions.append({**record, "actionId": identity})
                        else:
                            entities.append(record)
        return ContextRepositorySnapshot(
            store_version="json-v1",
            workspace_id=self._workspace_id,
            revision=0,
            earliest_change_revision=None,
            workspace=workspace_document if isinstance(workspace_document, dict) else {},
            scope=scope_document if isinstance(scope_document, dict) else {},
            targets=tuple(targets),
            entities=tuple(entities),
            findings=tuple(findings),
            actions=tuple(actions),
            authority=authority_document if isinstance(authority_document, dict) else {},
        )

    def create(self, *, organization: str = "", notes: str = "") -> dict[str, Any]:
        return self._workspace.create_workspace(self._workspace_id, organization=organization, notes=notes)

    def add_target(self, target: str, *, kind: str = "host", notes: str = "") -> dict[str, Any]:
        return self._workspace.add_target(self._workspace_id, target, kind=kind, notes=notes)


class JsonV1EvidenceRepository:
    def record(self, event_type: str, summary: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        from synapse_mcp.core import evidence

        return evidence.log_event(event_type, summary, data)
