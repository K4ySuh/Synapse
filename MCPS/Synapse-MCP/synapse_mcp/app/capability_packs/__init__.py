# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""High-level operational capability-pack lifecycle.

Exports are lazy so a launcher can select packs before importing the action
package and assembling its compatibility Registry.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS = {
    "BUILTIN_NAMESPACE_OWNERS": ("builtins", "BUILTIN_NAMESPACE_OWNERS"),
    "BUILTIN_PACK_ORDER": ("builtins", "BUILTIN_PACK_ORDER"),
    "builtin_action_owners": ("builtins", "builtin_action_owners"),
    "builtin_manifests": ("builtins", "builtin_manifests"),
    "CapabilityAvailability": ("contracts", "CapabilityAvailability"),
    "CapabilityPackId": ("contracts", "CapabilityPackId"),
    "CapabilityPackManifest": ("contracts", "CapabilityPackManifest"),
    "CapabilityPackOrigin": ("contracts", "CapabilityPackOrigin"),
    "CapabilityResource": ("contracts", "CapabilityResource"),
    "CapabilityPackCompatibilityError": ("errors", "CapabilityPackCompatibilityError"),
    "CapabilityPackDiscoveryError": ("errors", "CapabilityPackDiscoveryError"),
    "CapabilityPackError": ("errors", "CapabilityPackError"),
    "CapabilityPackValidationError": ("errors", "CapabilityPackValidationError"),
    "ENTRY_POINT_GROUP": ("loader", "ENTRY_POINT_GROUP"),
    "AssembledCapabilityPacks": ("loader", "AssembledCapabilityPacks"),
    "assemble_capability_packs": ("loader", "assemble_capability_packs"),
    "discover_external_manifests": ("loader", "discover_external_manifests"),
    "CAPABILITY_PACK_CATALOG_URI": ("service", "CAPABILITY_PACK_CATALOG_URI"),
    "CAPABILITY_PACK_RESOURCE_TEMPLATE": ("service", "CAPABILITY_PACK_RESOURCE_TEMPLATE"),
    "CapabilityPackCatalogService": ("service", "CapabilityPackCatalogService"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    # Public lifecycle imports may occur before ``app.actions``. Let that
    # package complete the one startup assembly first; its exact submodule
    # imports do not re-enter this lazy attribute path.
    import_module("synapse_mcp.app.actions")
    value = getattr(import_module(f"{__name__}.{module_name}"), attribute)
    globals()[name] = value
    return value
