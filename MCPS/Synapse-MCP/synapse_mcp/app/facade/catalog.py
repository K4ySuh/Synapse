# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Deterministic discovery and descriptor metadata for application surfaces."""

from __future__ import annotations

import base64
from hashlib import sha256
import json
from typing import Any

from synapse_mcp.app.actions import (
    CAPABILITY_PACKS,
    ActionDescriptor,
    ActionEffects,
    Availability,
    Idempotency,
    REGISTRY,
)
from synapse_mcp.app.actions.legacy_bridge import retained_legacy_implementation_bound
from synapse_mcp.app.actions.inventory import action_inventory
from synapse_mcp.app.actions.registry import ActionRegistry
from synapse_mcp.app.capability_packs.loader import AssembledCapabilityPacks

from .contracts import (
    ActionDescription,
    CapabilitiesSearchInput,
    CatalogItem,
    CatalogPage,
    EffectSummary,
    OperationAnnotations,
)


def effect_summary(effects: ActionEffects) -> EffectSummary:
    return EffectSummary(
        traffic=sorted(item.value for item in effects.traffic),
        local_writes=sorted(item.value for item in effects.local_writes),
        local_change=effects.local_change,
        local_destruction=effects.local_destruction,
        remote_state_change=effects.remote_state_change,
        credential_use=effects.credential_use,
        secret_use=effects.secret_use,
        replay_safety=effects.replay_safety.value,
        resolution_notes=list(effects.resolution_notes),
    )


def action_annotations(descriptor: ActionDescriptor[Any, Any]) -> OperationAnnotations:
    effects = descriptor.effects
    read_only = (
        not effects.traffic
        and not effects.local_writes
        and not effects.local_change
        and not effects.remote_state_change
        and not effects.credential_use
        and not effects.secret_use
    )
    idempotent = effects.replay_safety in {
        Idempotency.PURE_READ,
        Idempotency.IDEMPOTENT_WRITE,
        Idempotency.IDEMPOTENT_CONTROL,
    }
    return OperationAnnotations(
        read_only=read_only,
        destructive=effects.local_destruction or effects.remote_state_change,
        open_world=bool(effects.traffic),
        idempotent=idempotent,
        resource_references=bool(effects.local_writes),
    )


def _availability(
    descriptor: ActionDescriptor[Any, Any],
    entry: dict[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    declaration = descriptor.availability
    if callable(declaration):
        if entry is None:
            return "runtime_resolved", {"status": "runtime_resolved", "probe": {}}
        probe = dict(entry.get("availability", {}))
        if not retained_legacy_implementation_bound():
            return "unavailable", {
                "status": "unavailable",
                "reason": "Retained implementation adapter is not bound.",
                "reasonCode": "implementation_not_bound",
                "probe": probe,
            }
        if probe.get("probe") == "available":
            return "available", {"status": "available", "probe": probe}
        return "runtime_resolved", {
            "status": "runtime_resolved",
            "probe": probe,
        }
    if not isinstance(declaration, Availability):
        return "unavailable", {"status": "unavailable", "reasonCode": "invalid_declaration"}
    if declaration.available:
        return "available", {"status": "available"}
    return "unavailable", {
        "status": "unavailable",
        "reason": declaration.reason,
        "reasonCode": declaration.reason_code,
    }


def _effect_labels(descriptor: ActionDescriptor[Any, Any], side_effect: str) -> frozenset[str]:
    effects = descriptor.effects
    values = {side_effect, effects.replay_safety.value}
    if effects.traffic:
        values.add("traffic")
    if effects.local_writes:
        values.add("local_write")
        values.update(item.value for item in effects.local_writes)
    if effects.local_change:
        values.add("local_change")
    if effects.local_destruction:
        values.add("destructive")
    if effects.remote_state_change:
        values.add("remote_state_change")
    if effects.credential_use:
        values.add("credential_use")
    if effects.secret_use:
        values.add("secret_use")
    return frozenset(values)


def _target_types(descriptor: ActionDescriptor[Any, Any]) -> tuple[str, ...]:
    properties = descriptor.input_model.contract_document.parsed().get("properties", {})
    names = set(properties) if isinstance(properties, dict) else set()
    values: set[str] = set()
    if "workspaceId" in names:
        values.add("workspace")
    if names.intersection({"url", "requestUrl", "protectedUrl", "targetUrls"}):
        values.add("url")
    if names.intersection({"target", "hosts", "assets", "ip", "ips", "hostnames"}):
        values.add("host")
    if names.intersection({"requestFile", "candidate", "method", "headers", "body"}):
        values.add("request")
    if names.intersection({"dumpPath", "inputPath", "manifestPath", "specPath"}):
        values.add("artifact")
    return tuple(sorted(values or {"general"}))


def _task_suitability(descriptor: ActionDescriptor[Any, Any]) -> tuple[str, ...]:
    values = {
        "background" if descriptor.task_policy.background_capable else "foreground",
        "recordable" if descriptor.task_policy.passive_recordable else "direct",
    }
    forbidden = bool(
        descriptor.effects.traffic
        or descriptor.effects.credential_use
        or descriptor.effects.secret_use
        or descriptor.effects.remote_state_change
        or descriptor.effects.local_destruction
    )
    values.add("active" if forbidden else "passive")
    return tuple(sorted(values))


def _safe_value(name: str, schema: dict[str, Any]) -> Any:
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    value_type = schema.get("type")
    lowered = name.lower()
    if value_type == "string":
        if "workspace" in lowered:
            return "workspace-example"
        if lowered in {"target", "url", "requesturl", "protectedurl"}:
            return "https://example.test"
        if "credential" in lowered or lowered == "profileid":
            return "credential-reference"
        if lowered == "organization":
            return "example-organization"
        return f"{name}-example"
    if value_type == "integer":
        return max(1, int(schema.get("minimum", 1)))
    if value_type == "number":
        return max(1, schema.get("minimum", 1))
    if value_type == "boolean":
        return False
    if value_type == "array":
        item_schema = schema.get("items")
        if name == "hosts" and isinstance(item_schema, dict):
            return ["example.test"]
        return []
    if value_type == "object":
        return {}
    return None


def _safe_examples(schema: dict[str, Any]) -> list[dict[str, Any]]:
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        return [{}]
    example: dict[str, Any] = {}
    for name in required:
        property_schema = properties.get(name, {})
        if isinstance(name, str) and isinstance(property_schema, dict):
            example[name] = _safe_value(name, property_schema)
    return [example]


def model_facing_action_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Remove frozen legacy authority shims from compact model discovery."""

    value = json.loads(json.dumps(schema))
    properties = value.get("properties")
    if isinstance(properties, dict):
        properties.pop("confirm", None)
        properties.pop("allowExternalOutput", None)
    required = value.get("required")
    if isinstance(required, list):
        value["required"] = [
            name for name in required if name not in {"confirm", "allowExternalOutput"}
        ]
    return value


def _filter_fingerprint(value: CapabilitiesSearchInput) -> str:
    payload = value.model_dump(
        mode="json",
        by_alias=True,
        exclude={"cursor", "limit"},
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()[:16]


def _encode_cursor(offset: int, fingerprint: str) -> str:
    raw = json.dumps({"offset": offset, "filter": fingerprint}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str | None, fingerprint: str) -> int:
    if not cursor:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        offset = int(value["offset"])
    except Exception as exc:
        raise ValueError("Invalid capability-search cursor") from exc
    if value.get("filter") != fingerprint or offset < 0:
        raise ValueError("Capability-search cursor does not match this query")
    return offset


class ActionCatalogService:
    """Bounded discovery over one frozen selected canonical Registry."""

    def __init__(
        self,
        registry: ActionRegistry = REGISTRY,
        capability_packs: AssembledCapabilityPacks = CAPABILITY_PACKS,
    ) -> None:
        self.registry = registry
        self._inventory = {str(item["actionId"]): item for item in action_inventory()}
        self.capability_packs = capability_packs
        self._owners = dict(capability_packs.action_owners)
        self._manifests = {str(item.id): item for item in capability_packs.manifests}

    def search(self, value: CapabilitiesSearchInput) -> CatalogPage:
        fingerprint = _filter_fingerprint(value)
        offset = _decode_cursor(value.cursor, fingerprint)
        query_terms = tuple(part for part in value.query.lower().split() if part)
        matches: list[tuple[int, int, CatalogItem]] = []
        namespace_filter = value.pack
        for index, descriptor in enumerate(self.registry.descriptors()):
            action_id = str(descriptor.id)
            entry = self._inventory.get(action_id, {})
            capability_pack = self._owners[action_id]
            availability, _ = _availability(descriptor, entry)
            searchable = " ".join(
                (
                    action_id,
                    descriptor.title,
                    descriptor.summary,
                    descriptor.pack,
                    capability_pack,
                    str(entry.get("useCase", "")),
                    str(entry.get("sideEffectClass", "")),
                )
            ).lower()
            term_score = sum(term in searchable for term in query_terms)
            if query_terms and term_score == 0:
                continue
            if value.capability_pack and capability_pack != value.capability_pack:
                continue
            if namespace_filter and descriptor.pack != namespace_filter:
                continue
            if value.intent and entry.get("useCase") != value.intent:
                continue
            if value.effect and value.effect not in _effect_labels(
                descriptor, str(entry.get("sideEffectClass", ""))
            ):
                continue
            if value.risk and descriptor.risk_class.value != value.risk:
                continue
            if value.availability and availability != value.availability:
                continue
            credential_values = {
                descriptor.credential_policy.requirement.value,
                descriptor.credential_policy.access.value,
            }
            if value.credential_need and value.credential_need not in credential_values:
                continue
            if value.scope and descriptor.scope_policy.requirement.value != value.scope:
                continue
            target_types = _target_types(descriptor)
            if value.target_type and value.target_type not in target_types:
                continue
            task_suitability = _task_suitability(descriptor)
            if value.task_suitability and value.task_suitability not in task_suitability:
                continue
            matches.append(
                (
                    term_score,
                    index,
                    self._item(
                        descriptor,
                        entry,
                        availability,
                        capability_pack,
                        target_types,
                        task_suitability,
                    ),
                )
            )
        if query_terms:
            complete = [item for item in matches if item[0] == len(query_terms)]
            matches = complete or sorted(matches, key=lambda item: (-item[0], item[1]))
        items = [item[2] for item in matches]
        page = items[offset : offset + value.limit]
        next_offset = offset + len(page)
        return CatalogPage(
            items=page,
            total=len(items),
            returned=len(page),
            cursor=value.cursor,
            next_cursor=(
                _encode_cursor(next_offset, fingerprint) if next_offset < len(items) else None
            ),
        )

    def describe(self, action_id: str) -> ActionDescription:
        descriptor = self.registry.get(action_id)
        entry = self._inventory.get(str(descriptor.id), {})
        capability_pack = self._owners[str(descriptor.id)]
        schemas = self.registry.contract_schema(action_id)
        public_input = model_facing_action_input_schema(schemas["inputSchema"])
        _, availability = _availability(descriptor, entry)
        return ActionDescription(
            action_id=str(descriptor.id),
            title=descriptor.title,
            description=descriptor.summary,
            pack=descriptor.pack,
            capability_pack=capability_pack,
            intent=str(entry.get("useCase", "external")),
            input_schema=public_input,
            output_schema=schemas["outputSchema"],
            effects=effect_summary(descriptor.effects),
            risk=descriptor.risk_class.value,
            scope={
                "requirement": descriptor.scope_policy.requirement.value,
                "enforcement": descriptor.scope_policy.enforcement.value,
            },
            credentials={
                "requirement": descriptor.credential_policy.requirement.value,
                "access": descriptor.credential_policy.access.value,
                "enforcement": descriptor.credential_policy.enforcement.value,
            },
            availability=availability,
            approval={
                "legacyConfirmDeclared": descriptor.approval_required,
                "modernAuthoritySource": "server_held",
                "callerAuthorityFieldsAccepted": False,
            },
            annotations=action_annotations(descriptor),
            examples=_safe_examples(public_input),
        )

    def _item(
        self,
        descriptor: ActionDescriptor[Any, Any],
        entry: dict[str, Any],
        availability: str,
        capability_pack: str,
        target_types: tuple[str, ...],
        task_suitability: tuple[str, ...],
    ) -> CatalogItem:
        manifest = self._manifests[capability_pack]
        return CatalogItem(
            action_id=str(descriptor.id),
            title=descriptor.title,
            description=descriptor.summary,
            pack=descriptor.pack,
            capability_pack=capability_pack,
            intent=str(entry.get("useCase", "external")),
            effects=effect_summary(descriptor.effects),
            risk=descriptor.risk_class.value,
            availability=availability,
            credential_need=descriptor.credential_policy.requirement.value,
            credential_use=descriptor.effects.credential_use,
            scope=descriptor.scope_policy.requirement.value,
            approval_required=descriptor.approval_required,
            target_types=list(target_types),
            task_suitability=list(task_suitability),
            methodology_resources=[item.uri for item in manifest.resources],
        )
