# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered workspace actions."""

from __future__ import annotations

from pydantic import ConfigDict

from synapse_mcp.core import workspace
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


WORKSPACE_SUMMARY_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"workspaceId":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50},"includeInventory":{"type":"boolean","default":false}},"required":["workspaceId"]}'
)
WorkspaceSummaryInput = make_input_model(
    "WorkspaceSummaryInput",
    WORKSPACE_SUMMARY_INPUT_DOCUMENT,
)

WORKSPACE_PREPARE_TARGET_CONTEXT_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"workspaceId":{"type":"string"},"target":{"type":"string"},"purpose":{"type":"string","default":"next_step_planning"},"maxTokens":{"type":"integer","minimum":100,"default":1500}},"required":["workspaceId","target"]}'
)
WorkspacePrepareTargetContextInput = make_input_model(
    "WorkspacePrepareTargetContextInput",
    WORKSPACE_PREPARE_TARGET_CONTEXT_INPUT_DOCUMENT,
)


class WorkspaceSummaryOutput(ActionOutput):
    model_config = ConfigDict(extra="allow")


class WorkspacePrepareTargetContextOutput(ActionOutput):
    model_config = ConfigDict(extra="allow")


class WorkspaceSummaryExecutor:
    input_model = WorkspaceSummaryInput
    output_model = WorkspaceSummaryOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = workspace.workspace_summary(
                args["workspaceId"],
                cursor=args.get("cursor"),
                limit=int(args.get("limit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            )
        except McpError as exc:
            return outcome_from_mcp_error(exc)
        return success_from_legacy_payload(result)


class WorkspacePrepareTargetContextExecutor:
    input_model = WorkspacePrepareTargetContextInput
    output_model = WorkspacePrepareTargetContextOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = workspace.prepare_target_context(
                args["workspaceId"],
                args["target"],
                args.get("purpose", "next_step_planning"),
                int(args.get("maxTokens", 1500)),
            )
        except McpError as exc:
            return outcome_from_mcp_error(exc)
        return success_from_legacy_payload(result)


WORKSPACE_SUMMARY = ActionDescriptor(
    id=ActionId.parse("workspace.summary"),
    pack="workspace",
    title="Workspace summary",
    summary="Summarize targets and normalized entity counts for one Synapse workspace.",
    input_model=WorkspaceSummaryInput,
    output_model=WorkspaceSummaryOutput,
    side_effect_class=SideEffectClass.READ_ONLY,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, False),
    executor=WorkspaceSummaryExecutor(),
    availability=Availability(available=True),
)

WORKSPACE_PREPARE_TARGET_CONTEXT = ActionDescriptor(
    id=ActionId.parse("workspace.prepare_target_context"),
    pack="workspace",
    title="Prepare target context",
    summary="Return compact target context assembled from normalized workspace entities and evidence references.",
    input_model=WorkspacePrepareTargetContextInput,
    output_model=WorkspacePrepareTargetContextOutput,
    side_effect_class=SideEffectClass.READ_ONLY,
    risk_class=RiskClass.NONE,
    scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
    credential_policy=CredentialPolicy(CredentialRequirement.NONE, CredentialAccess.NONE),
    idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, False, False),
    executor=WorkspacePrepareTargetContextExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(WORKSPACE_SUMMARY)
REGISTRY.register(WORKSPACE_PREPARE_TARGET_CONTEXT)
