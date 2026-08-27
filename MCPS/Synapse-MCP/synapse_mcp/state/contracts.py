# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Storage-neutral contracts for one workspace repository bundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


JsonObject = Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class WorkspaceRecord:
    workspace_id: str
    organization: str = ""
    notes: str = ""


@dataclass(frozen=True, slots=True)
class TargetRecord:
    target_id: str
    natural_key: str
    kind: str = "host"
    payload: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EntityRecord:
    entity_id: str
    entity_type: str
    natural_key: str
    target_id: str | None = None
    lifecycle: str = "observed"
    payload: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RelationRecord:
    relation_id: str
    source_entity_id: str
    target_entity_id: str
    relation_type: str
    payload: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    summary: str
    target_id: str | None = None
    payload: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    artifact_id: str
    digest: str
    size: int
    media_type: str
    origin: str
    path: Path


@dataclass(frozen=True, slots=True)
class AuditRecord:
    event_id: str
    event_type: str
    summary: str
    actor_ref: str = "system"
    payload: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerticalSlice:
    scope_snapshot_id: str
    scope: JsonObject
    targets: Sequence[TargetRecord]
    entities: Sequence[EntityRecord]
    relations: Sequence[RelationRecord]
    evidence: Sequence[EvidenceRecord]
    artifact: ArtifactRecord | None
    evidence_artifact_links: Sequence[tuple[str, str]]
    audit: AuditRecord


@dataclass(frozen=True, slots=True)
class ContextRepositorySnapshot:
    """One committed repository snapshot consumed by the Context Compiler."""

    store_version: str
    workspace_id: str
    revision: int
    earliest_change_revision: int | None
    workspace: JsonObject
    scope: JsonObject
    targets: Sequence[JsonObject] = field(default_factory=tuple)
    entities: Sequence[JsonObject] = field(default_factory=tuple)
    relations: Sequence[JsonObject] = field(default_factory=tuple)
    findings: Sequence[JsonObject] = field(default_factory=tuple)
    evidence: Sequence[JsonObject] = field(default_factory=tuple)
    evidence_artifacts: Sequence[JsonObject] = field(default_factory=tuple)
    actions: Sequence[JsonObject] = field(default_factory=tuple)
    dispatches: Sequence[JsonObject] = field(default_factory=tuple)
    tasks: Sequence[JsonObject] = field(default_factory=tuple)
    work_items: Sequence[JsonObject] = field(default_factory=tuple)
    authority: JsonObject = field(default_factory=dict)
    changes: Sequence[JsonObject] = field(default_factory=tuple)


class WorkspaceRepository(Protocol):
    @property
    def workspace_id(self) -> str: ...

    def revision(self) -> int: ...

    def snapshot(self) -> dict[str, Any]: ...

    def context_snapshot(self, *, since_revision: int | None = None) -> ContextRepositorySnapshot: ...


class WorkItemRepository(Protocol):
    """Application-facing repository contract for durable coordination state."""

    workspace_id: str

    def create(self, value: JsonObject, *, principal_id: str, now: Any = None) -> dict[str, Any]: ...

    def inspect(self, work_item_id: str) -> dict[str, Any]: ...

    def list(
        self,
        *,
        statuses: Sequence[str] = (),
        role: str = "",
        worker: str = "",
        parent_work_item_id: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]: ...


class EvidenceRepository(Protocol):
    def record(self, event_type: str, summary: str, data: JsonObject | None = None) -> dict[str, Any]: ...


class ArtifactRepository(Protocol):
    @property
    def workspace_id(self) -> str: ...

    def ingest_path(self, path: Path, *, media_type: str = "application/octet-stream", origin: str = "local") -> ArtifactRecord: ...

    def resolve(self, artifact_id: str, *, workspace_id: str) -> Path: ...


@dataclass(frozen=True, slots=True)
class WorkspaceRepositoryBundle:
    store_version: str
    workspace: WorkspaceRepository
    evidence: EvidenceRepository
    artifacts: ArtifactRepository | None = None
