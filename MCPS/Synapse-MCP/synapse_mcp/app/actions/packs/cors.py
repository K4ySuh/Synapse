# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered CORS actions."""

from __future__ import annotations

from pydantic import ConfigDict

from synapse_mcp.adapters.web import cors
from synapse_mcp.core.errors import McpError

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import outcome_from_mcp_error, success_from_legacy_payload
from ..policies import (
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Idempotency,
    IdempotencyPolicy,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    SideEffectClass,
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
    model_config = ConfigDict(extra="allow")


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
    side_effect_class=SideEffectClass.ACTIVE_PROBE,
    risk_class=RiskClass.MODERATE,
    scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
    credential_policy=CredentialPolicy(
        CredentialRequirement.OPTIONAL,
        CredentialAccess.CREDENTIAL_USE,
    ),
    idempotency_policy=IdempotencyPolicy(Idempotency.NON_IDEMPOTENT),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, False),
    executor=CorsExecuteTestExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(CORS_EXECUTE_TEST)
