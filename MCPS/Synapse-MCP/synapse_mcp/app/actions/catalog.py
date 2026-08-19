# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Register generated canonical descriptors not owned by explicit packs."""

from __future__ import annotations

import json
import shutil
from typing import Any
from urllib.parse import urlsplit

from synapse_mcp.core import workspace
from synapse_mcp.core.execution import (
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    ProviderRoute,
    RedirectPolicy,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
)

from .contracts import InputContractDocument, make_input_model, make_json_object_output_model
from .descriptor import ActionDescriptor, ActionRequest
from .identity import ActionId
from .inventory import action_inventory
from .legacy_bridge import RetainedLegacyExecutor, retained_legacy_implementation_bound
from .policies import (
    ActionEffects,
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Idempotency,
    IdempotencyPolicy,
    LocalWriteDomain,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    TaskPolicy,
    TrafficDestination,
)
from .registry import REGISTRY


def _maximum_effects(entry: dict[str, Any]) -> ActionEffects:
    side_effect = str(entry["sideEffectClass"])
    replay = Idempotency(str(entry["idempotency"]["behaviour"]))
    input_properties = entry.get("inputSchema", {}).get("properties", {})
    input_fields = set(input_properties) if isinstance(input_properties, dict) else set()
    traffic: set[TrafficDestination] = set()
    writes: set[LocalWriteDomain] = set()
    local_change = False
    local_destruction = False
    remote_state_change = False

    if side_effect == "active_probe":
        traffic.add(TrafficDestination.AUTHORIZED_TARGET)
        writes.update({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE})
        local_change = True
        remote_state_change = True
    elif side_effect == "third_party_read":
        traffic.add(TrafficDestination.THIRD_PARTY)
        writes.add(LocalWriteDomain.EVIDENCE)
        if "workspaceId" in input_fields or "ingest" in input_fields:
            writes.add(LocalWriteDomain.WORKSPACE)
        local_change = True
        replay = Idempotency.NON_IDEMPOTENT
    elif side_effect == "passive_analysis":
        if bool(entry["passiveRecordable"]) or "ingest" in input_fields:
            writes.update({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE})
            local_change = True
            replay = Idempotency.NON_IDEMPOTENT
    elif side_effect == "workspace_write":
        writes.update({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE})
        local_change = True
    elif side_effect == "report_build" and replay is not Idempotency.PURE_READ:
        writes.add(LocalWriteDomain.REPORTS_ARTIFACTS)
        local_change = True
    elif side_effect == "credential_write":
        writes.update({LocalWriteDomain.CREDENTIALS, LocalWriteDomain.EVIDENCE})
        local_change = True
    elif side_effect == "local_destructive":
        writes.update(
            {
                LocalWriteDomain.WORKSPACE,
                LocalWriteDomain.EVIDENCE,
                LocalWriteDomain.REPORTS_ARTIFACTS,
            }
        )
        local_change = True
        local_destruction = True
    elif side_effect == "runtime_config_write":
        writes.add(LocalWriteDomain.RUNTIME_CONFIG)
        local_change = True
    elif side_effect == "job_control":
        writes.add(LocalWriteDomain.JOBS)
        local_change = True
        local_destruction = True
    elif side_effect == "authorization_config_write":
        writes.update({LocalWriteDomain.RUNTIME_CONFIG, LocalWriteDomain.WORKSPACE})
        local_change = True

    if entry["taskMode"] == "background_capable":
        writes.update({LocalWriteDomain.JOBS, LocalWriteDomain.REPORTS_ARTIFACTS})
        local_change = True
        local_destruction = True
        replay = Idempotency.NON_IDEMPOTENT
    if entry["scopeRequirement"] == "required":
        traffic.add(TrafficDestination.AUTHORIZED_TARGET)
        remote_state_change = True
    credential_access = str(entry["credentialAccess"])
    uses_credentials = credential_access in {"credential_use", "secret_state_write"}
    return ActionEffects(
        traffic=frozenset(traffic),
        local_writes=frozenset(writes),
        local_change=local_change,
        local_destruction=local_destruction,
        remote_state_change=remote_state_change,
        credential_use=uses_credentials,
        secret_use=uses_credentials,
        replay_safety=replay,
    )


def _effect_resolver(maximum: ActionEffects):
    def resolve(request: ActionRequest) -> ActionEffects:
        args = request.input.model_dump(by_alias=True)
        traffic = set(maximum.traffic)
        remote_change = maximum.remote_state_change
        traffic_disabled = bool(args.get("disableTraffic")) or args.get("httpBackend") == "disabled"
        if traffic_disabled:
            traffic.discard(TrafficDestination.AUTHORIZED_TARGET)
            remote_change = False
        writes = set(maximum.local_writes)
        if args.get("background") is False:
            writes.discard(LocalWriteDomain.JOBS)
        credential_keys = {
            key
            for key in args
            if key.lower().endswith("credentialid") or key == "profileId"
        }
        uses_credentials = maximum.credential_use and (
            not credential_keys or any(args.get(key) for key in credential_keys)
        )
        proxy_url = str(args.get("proxyUrl") or "")
        proxy_secret = bool(urlsplit(proxy_url).username or urlsplit(proxy_url).password) if proxy_url else False
        return ActionEffects(
            traffic=frozenset(traffic),
            local_writes=frozenset(writes),
            local_change=maximum.local_change,
            local_destruction=maximum.local_destruction,
            remote_state_change=remote_change,
            credential_use=uses_credentials,
            secret_use=uses_credentials or proxy_secret,
            replay_safety=maximum.replay_safety,
            resolution_notes=(f"traffic_enabled={not traffic_disabled}",),
        )

    return resolve


def _target_values(args: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        for key in ("url", "target", "requestUrl"):
            if candidate.get(key):
                values.append(str(candidate[key]))
    for key in ("target", "url", "requestUrl", "protectedUrl"):
        if args.get(key):
            values.append(str(args[key]))
    for key in ("targetUrls", "assets"):
        if isinstance(args.get(key), list):
            values.extend(str(value) for value in args[key] if value)
    return tuple(dict.fromkeys(values))


def _intent_resolver(action_id: str):
    def resolve(request: ActionRequest) -> AuthorizationIntent:
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        workspace_id = str(
            args.get("workspaceId")
            or request.context.workspace_id
            or workspace.default_workspace_id()
        )
        snapshot = ScopeSnapshot.for_workspace(workspace_id)
        canonical_targets: list[CanonicalTarget] = []
        for value in _target_values(args):
            try:
                canonical_targets.append(CanonicalTarget.from_url(value))
            except Exception:
                continue
        selectors = tuple(
            TargetSelector(target, "any", "canonical_action_input")
            for target in canonical_targets
        )
        follow_redirects = bool(args.get("followRedirects", True))
        envelope = TargetEnvelope(
            workspace_id,
            snapshot.digest,
            snapshot,
            selectors,
            tuple(canonical_targets),
            entire_workspace_scope=bool(args.get("includeInScopeHosts", False)),
            redirect_policy=RedirectPolicy(follow_redirects, 10 if follow_redirects else 0),
        )
        providers = ()
        if "httpBackend" in args or "proxyUrl" in args or "disableTraffic" in args:
            backend = "disabled" if args.get("disableTraffic") else str(args.get("httpBackend") or "direct")
            providers = (
                ProviderRoute.from_values(
                    backend,
                    args.get("proxyUrl"),
                    args.get("proxyCredentialId"),
                ),
            )
        method = str(args.get("method") or "GET").upper()
        credential_refs = tuple(
            str(value)
            for key, value in args.items()
            if value and (key.lower().endswith("credentialid") or key == "profileId")
        )
        return AuthorizationIntent(
            action_id=action_id,
            workspace_id=workspace_id,
            target_envelope=envelope,
            methods=(method,),
            credential_refs=credential_refs,
            providers=providers,
            lineage=ContinuationLineage(
                origin_action_id=action_id,
                origin_correlation_id=request.context.correlation_id,
            ),
        )

    return resolve


def _availability_resolver(entry: dict[str, Any]):
    probe = dict(entry.get("availability", {}))

    def resolve(request: ActionRequest) -> Availability:
        if not retained_legacy_implementation_bound():
            return Availability(
                False,
                "Retained implementation adapter is not bound.",
                "implementation_not_bound",
            )
        if probe.get("probe") != "executable":
            return Availability(True)
        if (
            request.context.execution_profile == "legacy"
            and request.input.model_dump().get("confirm") is not True
        ):
            return Availability(True)
        executable = str(probe.get("executable") or "")
        if shutil.which(executable):
            return Availability(True)
        return Availability(
            False,
            f"Optional executable is unavailable: {executable}",
            str(probe.get("reasonCode") or "missing_optional_binary"),
        )

    return resolve


def _register_generated_descriptors() -> None:
    existing = {str(descriptor.id) for descriptor in REGISTRY.descriptors()}
    deadline_tiers = {
        "fast": DeadlineTier.FAST,
        "status": DeadlineTier.STATUS,
        "default": DeadlineTier.DEFAULT,
    }
    for entry in action_inventory():
        action_id = str(entry["actionId"])
        if action_id in existing:
            continue
        document = InputContractDocument(
            json.dumps(entry["inputSchema"], separators=(",", ":"), ensure_ascii=False)
        )
        input_model = make_input_model(str(entry["inputModel"]), document)
        output_model = make_json_object_output_model(str(entry["outputModel"]))
        maximum = _maximum_effects(entry)
        idempotency = dict(entry["idempotency"])
        descriptor = ActionDescriptor(
            id=ActionId.parse(action_id),
            pack=str(entry["pack"]),
            title=str(entry["title"]),
            summary=str(entry["description"]),
            input_model=input_model,
            output_model=output_model,
            effects=maximum,
            effect_resolver=_effect_resolver(maximum),
            risk_class=RiskClass(str(entry["riskClass"])),
            scope_policy=ScopePolicy(ScopeRequirement(str(entry["scopeRequirement"]))),
            credential_policy=CredentialPolicy(
                CredentialRequirement(str(entry["credentialRequirement"])),
                CredentialAccess(str(entry["credentialAccess"])),
            ),
            task_policy=TaskPolicy(
                deadline_tiers[str(entry["deadlineTier"])],
                entry["taskMode"] == "background_capable",
                bool(entry["passiveRecordable"]),
            ),
            executor=RetainedLegacyExecutor(
                str(entry["legacyName"]),
                str(entry["serializer"]),
                input_model,
                output_model,
                confirm_declared=bool(entry["confirmDeclared"]),
            ),
            availability=_availability_resolver(entry),
            intent_resolver=_intent_resolver(action_id),
            legacy_aliases=(str(entry["legacyName"]),),
            legacy_serializer=str(entry["serializer"]),
            implementation_ref=str(entry["implementationTarget"]),
            approval_required=bool(entry["confirmDeclared"]),
            idempotency_policy=IdempotencyPolicy(
                Idempotency(str(idempotency["behaviour"])),
                condition=idempotency.get("condition"),
            ),
        )
        REGISTRY.register(descriptor)

    REGISTRY.set_descriptor_order(
        tuple(str(entry["actionId"]) for entry in action_inventory())
    )


_register_generated_descriptors()
