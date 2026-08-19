# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-specific legacy names and serializers for migrated actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from synapse_mcp.app.actions import REGISTRY


SerializerChoice = Literal["transport", "executor"]


@dataclass(frozen=True, slots=True)
class LegacyProjection:
    legacy_name: str
    serializer: SerializerChoice


LEGACY_PROJECTION_MAP = {
    str(descriptor.id): LegacyProjection(
        descriptor.legacy_aliases[0],
        descriptor.legacy_serializer,  # type: ignore[arg-type]
    )
    for descriptor in REGISTRY.descriptors()
}

# Schema ownership remains stable when one action rolls back to its retained
# legacy dispatch branch. Remove an id from this set to disable only registry
# dispatch; do not delete its projection row or descriptor schema.
LEGACY_DISPATCH_ACTIONS = frozenset(LEGACY_PROJECTION_MAP)
