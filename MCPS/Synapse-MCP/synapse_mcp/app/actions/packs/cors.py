# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered CORS actions."""

from __future__ import annotations

from pydantic import ConfigDict, JsonValue

from synapse_mcp.adapters.web import cors
from synapse_mcp.core.errors import McpError

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import outcome_from_mcp_error, success_from_legacy_payload
from ..policies import (
    ActionEffects,
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Idempotency,
    LocalWriteDomain,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    TrafficDestination,
    TaskPolicy,
)
from ..registry import REGISTRY


CORS_EXECUTE_TEST_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"workspaceId":{"type":"string"},"candidate":{"type":"object","additionalProperties":true},"candidateId":{"type":"string"},"url":{"type":"string"},"method":{"type":"string","default":"GET"},"probeOrigin":{"type":"string"},"credentialId":{"type":"string"},"requestTimeout":{"type":"integer","minimum":1,"default":10},"httpBackend":{"type":"string","enum":["direct","proxy","disabled"],"default":"direct"},"proxyUrl":{"type":"string"},"disableTraffic":{"type":"boolean","default":false},"maxBodyBytes":{"type":"integer","minimum":0},"followRedirects":{"type":"boolean","default":true},"verifyTls":{"type":"boolean","default":true},"http2":{"type":"boolean","default":false},"confirm":{"type":"boolean"},"approvalId":{"type":"string"},"approvalReason":{"type":"string"},"riskTier":{"type":"string"}},"required":["confirm"]}'
)
CorsExecuteTestInput = make_input_model(
    "CorsExecuteTestInput",
    CORS_EXECUTE_TEST_INPUT_DOCUMENT,
)


class CorsExecuteTestOutput(ActionOutput):
    test: dict[str, JsonValue]
    ingestion: dict[str, JsonValue]
    action: dict[str, JsonValue]
    model_config = ConfigDict(strict=True, extra="allow")


CORS_MAX_EFFECTS = ActionEffects(
    traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
    local_writes=frozenset(
        {
            LocalWriteDomain.WORKSPACE,
            LocalWriteDomain.EVIDENCE,
        }
    ),
    local_change=True,
    remote_state_change=True,
    credential_use=True,
    secret_use=True,
    replay_safety=Idempotency.NON_IDEMPOTENT,
)


def resolve_cors_effects(request: ActionRequest) -> ActionEffects:
    args = request.input.model_dump(by_alias=True)
    traffic_enabled = not bool(args.get("disableTraffic")) and args.get("httpBackend", "direct") != "disabled"
    candidate = args.get("candidate") if isinstance(args.get("candidate"), dict) else {}
    method = str(candidate.get("method") or args.get("method", "GET")).upper()
    uses_credential = bool(args.get("credentialId"))
    return ActionEffects(
        traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}) if traffic_enabled else frozenset(),
        local_writes=CORS_MAX_EFFECTS.local_writes,
        local_change=True,
        remote_state_change=traffic_enabled and method in {"POST", "PUT", "PATCH", "DELETE"},
        credential_use=uses_credential,
        secret_use=uses_credential,
        replay_safety=Idempotency.NON_IDEMPOTENT,
        resolution_notes=(f"traffic_enabled={traffic_enabled}", f"method={method}"),
    )


class CorsExecuteTestExecutor:
    input_model = CorsExecuteTestInput
    output_model = CorsExecuteTestOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = cors.execute_test(args)
        except McpError as exc:
            return outcome_from_mcp_error(
                exc,
                confirm_declared=True,
                confirm_value=args.get("confirm"),
            )
        return success_from_legacy_payload(result)


CORS_EXECUTE_TEST = ActionDescriptor(
    id=ActionId.parse("cors.execute_test"),
    pack="cors",
    title="Execute bounded CORS test",
    summary="Send one bounded CORS Origin probe against an authorized in-scope target.",
    input_model=CorsExecuteTestInput,
    output_model=CorsExecuteTestOutput,
    effects=CORS_MAX_EFFECTS,
    effect_resolver=resolve_cors_effects,
    risk_class=RiskClass.MODERATE,
    scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
    credential_policy=CredentialPolicy(
        CredentialRequirement.OPTIONAL,
        CredentialAccess.CREDENTIAL_USE,
    ),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, False),
    executor=CorsExecuteTestExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(CORS_EXECUTE_TEST)
