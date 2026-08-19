# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered response-header and cookie analysis actions."""

from __future__ import annotations

from pydantic import ConfigDict, JsonValue

from synapse_mcp.adapters.web import headers_cookies
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
    IdempotencyPolicy,
    LocalWriteDomain,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
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
    adapter: str
    mode: str
    summary: str
    workspaceId: str
    target: str
    entities: dict[str, list[dict[str, JsonValue]]]
    recommendedTests: list[dict[str, JsonValue]]
    evidence: list[dict[str, JsonValue]]
    limitations: list[str]
    metadata: dict[str, JsonValue]
    candidateCount: int
    candidates: list[dict[str, JsonValue]]
    contextSummary: dict[str, int]
    ingestion: dict[str, JsonValue] | None = None
    model_config = ConfigDict(strict=True, extra="allow")


HEADERS_COOKIES_MAX_EFFECTS = ActionEffects(
    local_writes=frozenset({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE}),
    local_change=True,
    replay_safety=Idempotency.NON_IDEMPOTENT,
)


def resolve_headers_cookies_effects(request: ActionRequest) -> ActionEffects:
    writes = {LocalWriteDomain.EVIDENCE}
    if bool(request.input.ingest):
        writes.add(LocalWriteDomain.WORKSPACE)
    return ActionEffects(
        local_writes=frozenset(writes),
        local_change=True,
        replay_safety=Idempotency.NON_IDEMPOTENT,
        resolution_notes=(f"ingest={bool(request.input.ingest)}",),
    )


class HeadersCookiesAnalyzeWorkspaceExecutor:
    input_model = HeadersCookiesAnalyzeWorkspaceInput
    output_model = HeadersCookiesAnalyzeWorkspaceOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = headers_cookies.analyze_workspace(args)
        except McpError as exc:
            return outcome_from_mcp_error(exc)
        return success_from_legacy_payload(result)


HEADERS_COOKIES_ANALYZE_WORKSPACE = ActionDescriptor(
    id=ActionId.parse("headers_cookies.analyze_workspace"),
    pack="headers_cookies",
    title="Analyze response headers and cookies",
    summary="Passively analyze recorded response security headers and cookie flags for hygiene weaknesses.",
    input_model=HeadersCookiesAnalyzeWorkspaceInput,
    output_model=HeadersCookiesAnalyzeWorkspaceOutput,
    effects=HEADERS_COOKIES_MAX_EFFECTS,
    effect_resolver=resolve_headers_cookies_effects,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, True),
    executor=HeadersCookiesAnalyzeWorkspaceExecutor(),
    availability=Availability(available=True),
    legacy_aliases=("headers_cookies.analyze_workspace",),
    legacy_serializer="executor",
    implementation_ref="headers_cookies.analyze_workspace",
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
)

REGISTRY.register(HEADERS_COOKIES_ANALYZE_WORKSPACE)
