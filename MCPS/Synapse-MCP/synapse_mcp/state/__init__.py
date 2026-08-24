# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Transport-independent State Store v2 foundations."""

from .artifacts import ArtifactLimits, ContentAddressedArtifactRepository
from .backup import online_backup
from .contracts import (
    ArtifactRecord,
    AuditRecord,
    EntityRecord,
    EvidenceRecord,
    RelationRecord,
    TargetRecord,
    VerticalSlice,
    WorkspaceRecord,
    WorkspaceRepositoryBundle,
)
from .errors import (
    ArtifactCollisionError,
    ArtifactLimitError,
    ArtifactStoreError,
    StateConflictError,
    StateIntegrityError,
    StateReadinessError,
    StateSelectionError,
    StateStoreError,
)
from .selector import repository_bundle, selected_store_version
from .sqlite_store import SQLiteWorkspaceRepository


__all__ = [
    "ArtifactCollisionError",
    "ArtifactLimitError",
    "ArtifactLimits",
    "ArtifactRecord",
    "ArtifactStoreError",
    "AuditRecord",
    "ContentAddressedArtifactRepository",
    "EntityRecord",
    "EvidenceRecord",
    "RelationRecord",
    "SQLiteWorkspaceRepository",
    "StateConflictError",
    "StateIntegrityError",
    "StateReadinessError",
    "StateSelectionError",
    "StateStoreError",
    "TargetRecord",
    "VerticalSlice",
    "WorkspaceRecord",
    "WorkspaceRepositoryBundle",
    "online_backup",
    "repository_bundle",
    "selected_store_version",
]
