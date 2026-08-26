# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""High-level operational capability-pack lifecycle."""

from .builtins import (
    BUILTIN_NAMESPACE_OWNERS,
    BUILTIN_PACK_ORDER,
    builtin_action_owners,
    builtin_manifests,
)
from .contracts import (
    CapabilityAvailability,
    CapabilityPackId,
    CapabilityPackManifest,
    CapabilityPackOrigin,
    CapabilityResource,
)
from .errors import (
    CapabilityPackCompatibilityError,
    CapabilityPackDiscoveryError,
    CapabilityPackError,
    CapabilityPackValidationError,
)
from .loader import (
    ENTRY_POINT_GROUP,
    AssembledCapabilityPacks,
    assemble_capability_packs,
    discover_external_manifests,
)
from .service import (
    CAPABILITY_PACK_CATALOG_URI,
    CAPABILITY_PACK_RESOURCE_TEMPLATE,
    CapabilityPackCatalogService,
)

__all__ = [
    "BUILTIN_NAMESPACE_OWNERS",
    "BUILTIN_PACK_ORDER",
    "ENTRY_POINT_GROUP",
    "AssembledCapabilityPacks",
    "CapabilityAvailability",
    "CapabilityPackCompatibilityError",
    "CapabilityPackCatalogService",
    "CapabilityPackDiscoveryError",
    "CapabilityPackError",
    "CapabilityPackId",
    "CapabilityPackManifest",
    "CapabilityPackOrigin",
    "CapabilityPackValidationError",
    "CapabilityResource",
    "CAPABILITY_PACK_CATALOG_URI",
    "CAPABILITY_PACK_RESOURCE_TEMPLATE",
    "assemble_capability_packs",
    "builtin_action_owners",
    "builtin_manifests",
    "discover_external_manifests",
]
