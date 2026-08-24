# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Compatibility adapters over the unchanged JSON-v1 implementation."""

from __future__ import annotations

from typing import Any


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

    def create(self, *, organization: str = "", notes: str = "") -> dict[str, Any]:
        return self._workspace.create_workspace(self._workspace_id, organization=organization, notes=notes)

    def add_target(self, target: str, *, kind: str = "host", notes: str = "") -> dict[str, Any]:
        return self._workspace.add_target(self._workspace_id, target, kind=kind, notes=notes)


class JsonV1EvidenceRepository:
    def record(self, event_type: str, summary: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        from synapse_mcp.core import evidence

        return evidence.log_event(event_type, summary, data)
