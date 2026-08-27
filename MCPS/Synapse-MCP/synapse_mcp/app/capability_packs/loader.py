# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Deterministic startup discovery, validation, and assembly."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Any, Iterable

from synapse_mcp import __version__
from synapse_mcp.app.actions.descriptor import ActionDescriptor
from synapse_mcp.app.actions.inventory import action_inventory
from synapse_mcp.app.actions.registry import ActionRegistry, PolicyEvaluator

from .builtins import BUILTIN_PACK_ORDER, builtin_manifests
from .contracts import CapabilityPackId, CapabilityPackManifest, CapabilityPackOrigin
from .errors import (
    CapabilityPackCompatibilityError,
    CapabilityPackDiscoveryError,
    CapabilityPackValidationError,
)


ENTRY_POINT_GROUP = "synapse_mcp.capability_packs"


@dataclass(frozen=True, slots=True)
class AssembledCapabilityPacks:
    """Frozen selected manifest catalog and its sole Action Registry."""

    registry: ActionRegistry
    manifests: tuple[CapabilityPackManifest, ...]
    action_owners: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.registry.frozen:
            raise CapabilityPackValidationError("assembled capability-pack Registry must be frozen")
        if not isinstance(self.manifests, tuple) or not all(
            isinstance(item, CapabilityPackManifest) for item in self.manifests
        ):
            raise CapabilityPackValidationError("assembled manifests must be an immutable manifest tuple")
        manifest_ids = tuple(str(item.id) for item in self.manifests)
        if not manifest_ids or len(manifest_ids) != len(set(manifest_ids)):
            raise CapabilityPackValidationError("assembled manifests must have unique pack ids")
        if not isinstance(self.action_owners, tuple) or not all(
            isinstance(item, tuple)
            and len(item) == 2
            and all(isinstance(value, str) for value in item)
            for item in self.action_owners
        ):
            raise CapabilityPackValidationError(
                "assembled action ownership must be an immutable pair tuple"
            )
        descriptor_ids = tuple(str(item.id) for item in self.registry.descriptors())
        owner_ids = tuple(action_id for action_id, _owner in self.action_owners)
        if owner_ids != descriptor_ids or len(owner_ids) != len(set(owner_ids)):
            raise CapabilityPackValidationError(
                "assembled action ownership must exactly match Registry order"
            )
        declared: dict[str, str] = {}
        for manifest in self.manifests:
            for action_id in manifest.action_ids:
                if action_id in declared:
                    raise CapabilityPackValidationError(
                        f"assembled action {action_id} has multiple manifest owners"
                    )
                declared[action_id] = str(manifest.id)
        if dict(self.action_owners) != declared:
            raise CapabilityPackValidationError(
                "assembled action ownership must exactly match selected manifest declarations"
            )

    def pack(self, pack_id: CapabilityPackId | str) -> CapabilityPackManifest:
        selected = str(CapabilityPackId.parse(pack_id))
        for manifest in self.manifests:
            if str(manifest.id) == selected:
                return manifest
        raise LookupError(f"Unknown selected capability pack: {selected}")

    def owner_for(self, action_id: str) -> str:
        for candidate, owner in self.action_owners:
            if candidate == action_id:
                return owner
        raise LookupError(f"Unknown selected action id: {action_id}")

    def as_document(self) -> dict[str, Any]:
        owners = dict(self.action_owners)
        return {
            "contractVersion": 1,
            "applicationVersion": __version__,
            "frozen": self.registry.frozen,
            "packCount": len(self.manifests),
            "actionCount": len(self.action_owners),
            "packs": [
                {
                    "packId": str(manifest.id),
                    "title": manifest.title,
                    "summary": manifest.summary,
                    "origin": manifest.origin.value,
                    "distributionId": manifest.distribution_id,
                    "dependencies": [str(item) for item in manifest.dependencies],
                    "actionCount": len(manifest.action_ids),
                    "actionIds": list(manifest.action_ids),
                    "resources": [
                        {
                            "uri": item.uri,
                            "title": item.title,
                            "summary": item.summary,
                            "mediaType": item.media_type,
                        }
                        for item in manifest.resources
                    ],
                    "availability": [
                        {"kind": item.kind, "summary": item.summary}
                        for item in manifest.availability
                    ],
                    "applicationCompatibility": {
                        "minimum": manifest.application_min,
                        "maximumExclusive": manifest.application_max_exclusive,
                    },
                    "ownedActions": [
                        action_id for action_id in manifest.action_ids if owners[action_id] == str(manifest.id)
                    ],
                }
                for manifest in self.manifests
            ],
        }


def discover_external_manifests(
    *,
    entry_points: Iterable[Any] | None = None,
) -> tuple[CapabilityPackManifest, ...]:
    """Load installed external manifests once and fail with entry-point identity."""

    if entry_points is None:
        discovered = metadata.entry_points()
        entry_points = (
            discovered.select(group=ENTRY_POINT_GROUP)
            if hasattr(discovered, "select")
            else discovered.get(ENTRY_POINT_GROUP, ())
        )
    loaded: list[CapabilityPackManifest] = []
    for entry_point in sorted(entry_points, key=lambda item: (item.name, item.value)):
        try:
            contribution = entry_point.load()
            manifest = contribution() if callable(contribution) and not isinstance(
                contribution, CapabilityPackManifest
            ) else contribution
        except Exception as exc:
            raise CapabilityPackDiscoveryError(
                f"capability-pack entry point {entry_point.name!r} ({entry_point.value}) failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(manifest, CapabilityPackManifest):
            raise CapabilityPackDiscoveryError(
                f"capability-pack entry point {entry_point.name!r} did not return a manifest"
            )
        if manifest.origin is not CapabilityPackOrigin.EXTERNAL:
            raise CapabilityPackDiscoveryError(
                f"capability-pack entry point {entry_point.name!r} must declare external origin"
            )
        loaded.append(manifest)
    return tuple(loaded)


def _ordered_selection(
    manifests: dict[str, CapabilityPackManifest],
    requested: tuple[str, ...],
) -> tuple[CapabilityPackManifest, ...]:
    selected: set[str] = set()
    visiting: set[str] = set()

    def include(pack_id: str) -> None:
        if pack_id in selected:
            return
        if pack_id in visiting:
            raise CapabilityPackValidationError(f"capability-pack dependency cycle includes {pack_id}")
        manifest = manifests.get(pack_id)
        if manifest is None:
            raise CapabilityPackValidationError(f"unknown capability pack selection or dependency: {pack_id}")
        visiting.add(pack_id)
        for dependency in manifest.dependencies:
            include(str(dependency))
        visiting.remove(pack_id)
        selected.add(pack_id)

    for pack_id in requested:
        include(pack_id)
    builtin_rank = {pack_id: index for index, pack_id in enumerate(BUILTIN_PACK_ORDER)}
    return tuple(
        manifests[pack_id]
        for pack_id in sorted(
            selected,
            key=lambda value: (0, builtin_rank[value]) if value in builtin_rank else (1, value),
        )
    )


def _validate_manifest_graph(manifests: dict[str, CapabilityPackManifest]) -> None:
    """Reject invalid installed ownership and dependencies before selection."""

    action_owners: dict[str, str] = {}
    resource_owners: dict[str, str] = {}
    for pack_id, manifest in manifests.items():
        for dependency in manifest.dependencies:
            dependency_id = str(dependency)
            if dependency_id not in manifests:
                raise CapabilityPackValidationError(
                    f"unknown capability pack dependency: {pack_id} requires {dependency_id}"
                )
        for action_id in manifest.action_ids:
            previous = action_owners.get(action_id)
            if previous is not None:
                raise CapabilityPackValidationError(
                    f"action {action_id} is owned by both {previous} and {pack_id}"
                )
            action_owners[action_id] = pack_id
        for resource in manifest.resources:
            previous = resource_owners.get(resource.uri)
            if previous is not None:
                raise CapabilityPackValidationError(
                    f"resource {resource.uri} is contributed by both {previous} and {pack_id}"
                )
            resource_owners[resource.uri] = pack_id

    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(pack_id: str) -> None:
        if pack_id in visited:
            return
        if pack_id in visiting:
            raise CapabilityPackValidationError(
                f"capability-pack dependency cycle includes {pack_id}"
            )
        visiting.add(pack_id)
        for dependency in manifests[pack_id].dependencies:
            visit(str(dependency))
        visiting.remove(pack_id)
        visited.add(pack_id)

    for pack_id in manifests:
        visit(pack_id)


def assemble_capability_packs(
    selection: Iterable[CapabilityPackId | str] | None = None,
    *,
    registry: ActionRegistry | None = None,
    policy_evaluator: PolicyEvaluator | None = None,
    external_manifests: Iterable[CapabilityPackManifest] | None = None,
    discover_external: bool = True,
    application_version: str = __version__,
) -> AssembledCapabilityPacks:
    """Build and freeze one isolated registry from explicit startup selection."""

    if registry is not None and policy_evaluator is not None:
        raise CapabilityPackValidationError("pass either a registry or policy evaluator, not both")
    target = registry or ActionRegistry(policy_evaluator)
    if target.frozen or target.descriptors():
        raise CapabilityPackValidationError("assembly target must be a fresh mutable registry")

    installed = tuple(external_manifests or ())
    for manifest in installed:
        if not isinstance(manifest, CapabilityPackManifest):
            raise CapabilityPackValidationError(
                "external capability-pack contributions must be manifests"
            )
        if manifest.origin is not CapabilityPackOrigin.EXTERNAL:
            raise CapabilityPackValidationError(
                f"{manifest.id}: caller-supplied external manifest must declare external origin"
            )
    if discover_external:
        installed = (*installed, *discover_external_manifests())
    all_manifests = (*builtin_manifests(), *installed)
    by_id: dict[str, CapabilityPackManifest] = {}
    for manifest in all_manifests:
        pack_id = str(manifest.id)
        if pack_id in by_id:
            raise CapabilityPackValidationError(f"duplicate capability pack id: {pack_id}")
        if not manifest.supports(application_version):
            raise CapabilityPackCompatibilityError(
                f"{pack_id}: application {application_version} is outside "
                f"[{manifest.application_min}, {manifest.application_max_exclusive})"
            )
        by_id[pack_id] = manifest
    _validate_manifest_graph(by_id)

    requested_values = BUILTIN_PACK_ORDER if selection is None else tuple(selection)
    requested = tuple(str(CapabilityPackId.parse(item)) for item in requested_values)
    if not requested or len(requested) != len(set(requested)):
        raise CapabilityPackValidationError("capability-pack selection must be non-empty and unique")
    selected = _ordered_selection(by_id, requested)

    owners: dict[str, str] = {}
    external_ids: list[str] = []
    for manifest in selected:
        try:
            descriptors = manifest.descriptor_provider()
        except Exception as exc:
            raise CapabilityPackValidationError(
                f"{manifest.id}: descriptor provider failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(descriptors, tuple):
            raise CapabilityPackValidationError(f"{manifest.id}: descriptor provider must return a tuple")
        if not all(isinstance(descriptor, ActionDescriptor) for descriptor in descriptors):
            raise CapabilityPackValidationError(
                f"{manifest.id}: descriptor provider returned a non-ActionDescriptor contribution"
            )
        provided_ids = tuple(str(descriptor.id) for descriptor in descriptors)
        if provided_ids != manifest.action_ids:
            raise CapabilityPackValidationError(
                f"{manifest.id}: descriptor provider does not match declared ordered action ownership"
            )
        for descriptor in descriptors:
            action_id = str(descriptor.id)
            previous = owners.get(action_id)
            if previous is not None:
                raise CapabilityPackValidationError(
                    f"action {action_id} is owned by both {previous} and {manifest.id}"
                )
            owners[action_id] = str(manifest.id)
            try:
                target.register(
                    descriptor,
                    legacy_compatible=manifest.origin is CapabilityPackOrigin.BUILTIN,
                )
            except ValueError as exc:
                raise CapabilityPackValidationError(f"{manifest.id}: {exc}") from exc
            if manifest.origin is CapabilityPackOrigin.EXTERNAL:
                external_ids.append(action_id)

    built_in_ids = tuple(
        str(entry["actionId"])
        for entry in action_inventory()
        if str(entry["actionId"]) in owners
    )
    selected_builtin_ids = {
        action_id
        for manifest in selected
        if manifest.origin is CapabilityPackOrigin.BUILTIN
        for action_id in manifest.action_ids
    }
    if set(built_in_ids) != selected_builtin_ids:
        raise CapabilityPackValidationError("selected built-in action ownership is incomplete")
    order = (*built_in_ids, *sorted(external_ids))
    target.set_descriptor_order(order)
    target.freeze()
    return AssembledCapabilityPacks(
        registry=target,
        manifests=selected,
        action_owners=tuple((action_id, owners[action_id]) for action_id in order),
    )
