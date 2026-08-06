# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered response-header and cookie analysis actions."""

from __future__ import annotations

from pydantic import ConfigDict

from synapse_mcp.adapters.web import headers_cookies
from synapse_mcp.core.errors import McpError

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import Success, outcome_from_mcp_error
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


HEADERS_COOKIES_ANALYZE_WORKSPACE_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"workspaceId":{"type":"string"},"target":{"type":"string"},"maxCandidates":{"type":"integer","minimum":1,"default":100},"dedupeScope":{"type":"string","enum":["host","endpoint"],"default":"host"},"ingest":{"type":"boolean","default":true}},"required":["workspaceId","target"]}'
)
HeadersCookiesAnalyzeWorkspaceInput = make_input_model(
    "HeadersCookiesAnalyzeWorkspaceInput",
    HEADERS_COOKIES_ANALYZE_WORKSPACE_INPUT_DOCUMENT,
)


class HeadersCookiesAnalyzeWorkspaceOutput(ActionOutput):
    model_config = ConfigDict(extra="allow")


class HeadersCookiesAnalyzeWorkspaceExecutor:
    input_model = HeadersCookiesAnalyzeWorkspaceInput
    output_model = HeadersCookiesAnalyzeWorkspaceOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = headers_cookies.analyze_workspace(args)
        except McpError as exc:
            return outcome_from_mcp_error(exc)
        return Success(payload=result)


HEADERS_COOKIES_ANALYZE_WORKSPACE = ActionDescriptor(
    id=ActionId.parse("headers_cookies.analyze_workspace"),
    pack="headers_cookies",
    title="Analyze response headers and cookies",
    summary="Passively analyze recorded response security headers and cookie flags for hygiene weaknesses.",
    input_model=HeadersCookiesAnalyzeWorkspaceInput,
    output_model=HeadersCookiesAnalyzeWorkspaceOutput,
    side_effect_class=SideEffectClass.PASSIVE_ANALYSIS,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, True),
    executor=HeadersCookiesAnalyzeWorkspaceExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(HEADERS_COOKIES_ANALYZE_WORKSPACE)
