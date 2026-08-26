# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Project canonical action metadata into transitional adapter discovery."""

from __future__ import annotations

from typing import Any

from .policies import (
    CredentialRequirement,
    LocalWriteDomain,
    RiskClass,
    ScopeRequirement,
    TrafficDestination,
)
from .registry import REGISTRY, ActionRegistry


def derive_adapter_operational_metadata(
    action_ids: tuple[str, ...],
    *,
    registry: ActionRegistry = REGISTRY,
) -> dict[str, Any]:
    descriptors = []
    for action_id in action_ids:
        try:
            descriptors.append(registry.get(action_id))
        except LookupError:
            continue
    if not descriptors:
        return {
            "sendsTraffic": False,
            "requiresConfirmation": False,
            "requiresScope": False,
            "requiresCredentials": False,
            "touchesThirdParty": False,
            "defaultRiskTier": "info",
            "executionMode": "unselected",
            "backgroundJobProvider": "",
            "executorTool": "",
            "operationalMetadataSource": "action_registry_v2",
            "selected": False,
            "actions": [],
        }
    risk_order = {RiskClass.NONE: 0, RiskClass.LOW: 1, RiskClass.MODERATE: 2, RiskClass.HIGH: 3}
    risk_names = {0: "info", 1: "low", 2: "medium", 3: "high"}
    action_views = []
    for descriptor in descriptors:
        effects = descriptor.effects
        contract = descriptor.input_model.contract_document.parsed()
        action_views.append(
            {
                "actionId": str(descriptor.id),
                "riskClass": descriptor.risk_class.value,
                "availability": "runtime_resolved" if callable(descriptor.availability) else "available",
                "requiresLegacyConfirmation": "confirm" in contract.get("properties", {}),
                "effects": {
                    "traffic": sorted(item.value for item in effects.traffic),
                    "localWrites": sorted(item.value for item in effects.local_writes),
                    "localChange": effects.local_change,
                    "localDestruction": effects.local_destruction,
                    "remoteStateChange": effects.remote_state_change,
                    "credentialUse": effects.credential_use,
                    "secretUse": effects.secret_use,
                    "replaySafety": effects.replay_safety.value,
                },
            }
        )
    return {
        "sendsTraffic": any(bool(descriptor.effects.traffic) for descriptor in descriptors),
        "requiresConfirmation": any(view["requiresLegacyConfirmation"] for view in action_views),
        "requiresScope": any(
            descriptor.scope_policy.requirement is ScopeRequirement.REQUIRED for descriptor in descriptors
        ),
        "requiresCredentials": any(
            descriptor.credential_policy.requirement is CredentialRequirement.REQUIRED for descriptor in descriptors
        ),
        "touchesThirdParty": any(
            TrafficDestination.THIRD_PARTY in descriptor.effects.traffic for descriptor in descriptors
        ),
        "defaultRiskTier": risk_names[max(risk_order[item.risk_class] for item in descriptors)],
        "executionMode": (
            "async_default" if any(item.task_policy.background_capable for item in descriptors) else "sync_only"
        ),
        "backgroundJobProvider": (
            "jobs" if any(LocalWriteDomain.JOBS in item.effects.local_writes for item in descriptors) else ""
        ),
        "executorTool": action_ids[0] if len(action_ids) == 1 else "",
        "operationalMetadataSource": "action_registry_v2",
        "selected": True,
        "actions": action_views,
    }
