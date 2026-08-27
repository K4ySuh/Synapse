# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Canonical built-in capability-pack manifests and ownership."""

from __future__ import annotations

from functools import lru_cache
from types import MappingProxyType
from typing import Mapping

from synapse_mcp.app.actions.descriptor import ActionDescriptor
from synapse_mcp.app.actions.inventory import action_inventory

from .contracts import (
    CapabilityAvailability,
    CapabilityPackId,
    CapabilityPackManifest,
    CapabilityPackOrigin,
    CapabilityResource,
)


BUILTIN_NAMESPACE_OWNERS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "core": (
        "adapters",
        "cache",
        "credentials",
        "dumps",
        "evidence",
        "jobs",
        "project",
        "scope",
        "workspace",
    ),
    "web": (
        "access_control",
        "command_injection",
        "cors",
        "crawler",
        "csrf",
        "ffuf",
        "graphql",
        "headers_cookies",
        "insecure_deser",
        "js",
        "jwt",
        "lfi",
        "nuclei",
        "open_redirect",
        "sitemap",
        "spec_import",
        "sqli",
        "ssi",
        "ssrf",
        "ssti",
        "tls_posture",
        "xss",
        "xxe",
    ),
    "infra": ("fingerprint", "nmap", "perimeter"),
    "reporting": ("documentation",),
    "purple": ("purple_team", "social"),
    "intelligence": ("cve", "shodan"),
})

BUILTIN_PACK_ORDER = ("core", "web", "infra", "reporting", "purple", "intelligence")

_PACK_DETAILS = {
    "core": (
        "Synapse core operations",
        "Workspace, scope, evidence, credentials, jobs, dumps, cache, and project operations.",
    ),
    "web": (
        "Web assessment operations",
        "Passive web analysis, bounded validation, crawling, discovery, and application modeling.",
    ),
    "infra": (
        "Infrastructure operations",
        "Fingerprinting, perimeter analysis, and bounded network mapping.",
    ),
    "reporting": (
        "Reporting operations",
        "Workspace documentation contexts, evidence packs, and self-contained internal reports.",
    ),
    "purple": (
        "Purple-team operations",
        "Detection-gap and operator-reviewed social-engineering workflow state.",
    ),
    "intelligence": (
        "External intelligence operations",
        "CVE correlation and Shodan intelligence normalized into local workspace truth.",
    ),
}


@lru_cache(maxsize=1)
def builtin_action_owners() -> Mapping[str, str]:
    namespace_owner = {
        namespace: pack_id
        for pack_id, namespaces in BUILTIN_NAMESPACE_OWNERS.items()
        for namespace in namespaces
    }
    inventory_namespaces = {str(entry["pack"]) for entry in action_inventory()}
    missing = inventory_namespaces - set(namespace_owner)
    orphaned = set(namespace_owner) - inventory_namespaces
    if missing or orphaned:
        raise ValueError(
            f"built-in capability ownership is incomplete: missing={sorted(missing)}, "
            f"orphaned={sorted(orphaned)}"
        )
    return MappingProxyType(
        {
            str(entry["actionId"]): namespace_owner[str(entry["pack"])]
            for entry in action_inventory()
        }
    )


def _native_descriptors(pack_id: str) -> tuple[ActionDescriptor, ...]:
    if pack_id == "core":
        from synapse_mcp.app.actions.packs.jobs import DESCRIPTORS as jobs
        from synapse_mcp.app.actions.packs.workspace import DESCRIPTORS as workspace

        return (*jobs, *workspace)
    if pack_id == "web":
        from synapse_mcp.app.actions.packs.cors import DESCRIPTORS as cors
        from synapse_mcp.app.actions.packs.crawler import DESCRIPTORS as crawler
        from synapse_mcp.app.actions.packs.headers_cookies import DESCRIPTORS as headers

        return (*headers, *cors, *crawler)
    return ()


def _provider(pack_id: str):
    def provide() -> tuple[ActionDescriptor, ...]:
        from synapse_mcp.app.actions.catalog import generated_descriptors

        owned = tuple(
            action_id
            for action_id, owner in builtin_action_owners().items()
            if owner == pack_id
        )
        native = _native_descriptors(pack_id)
        native_by_id = {str(descriptor.id): descriptor for descriptor in native}
        generated = {
            str(descriptor.id): descriptor
            for descriptor in generated_descriptors(
                owned,
                native_action_ids=frozenset(native_by_id),
            )
        }
        return tuple(native_by_id.get(action_id) or generated[action_id] for action_id in owned)

    provide.__name__ = f"provide_{pack_id}_capabilities"
    return provide


def builtin_manifests() -> tuple[CapabilityPackManifest, ...]:
    owners = builtin_action_owners()
    manifests = []
    for pack_id in BUILTIN_PACK_ORDER:
        title, summary = _PACK_DETAILS[pack_id]
        manifests.append(
            CapabilityPackManifest(
                id=CapabilityPackId(pack_id),
                title=title,
                summary=summary,
                contract_version=1,
                origin=CapabilityPackOrigin.BUILTIN,
                distribution_id="synapse-mcp",
                descriptor_provider=_provider(pack_id),
                action_ids=tuple(
                    action_id for action_id, owner in owners.items() if owner == pack_id
                ),
                dependencies=() if pack_id == "core" else (CapabilityPackId("core"),),
                resources=(
                    CapabilityResource(
                        uri=f"synapse://capability-packs/{pack_id}",
                        title=title,
                        summary=summary,
                    ),
                ),
                availability=(
                    CapabilityAvailability(
                        "runtime",
                        "Pack actions remain discoverable; each descriptor reports its own runtime availability.",
                    ),
                ),
            )
        )
    return tuple(manifests)
