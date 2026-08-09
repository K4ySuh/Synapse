# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered CORS actions."""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import ConfigDict, JsonValue

from synapse_mcp.adapters.web import cors
from synapse_mcp.core import workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import (
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    ExecutionPlanError,
    ProviderRoute,
    RedirectPolicy,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
)

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import ValidationFailure, outcome_from_mcp_error, success_from_legacy_payload
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
    uses_credential = bool(args.get("credentialId") or args.get("proxyCredentialId"))
    proxy_url = str(args.get("proxyUrl") or "")
    proxy_secret = bool(urlsplit(proxy_url).username or urlsplit(proxy_url).password) if proxy_url else False
    return ActionEffects(
        traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}) if traffic_enabled else frozenset(),
        local_writes=CORS_MAX_EFFECTS.local_writes,
        local_change=True,
        remote_state_change=traffic_enabled and method in {"POST", "PUT", "PATCH", "DELETE"},
        credential_use=uses_credential,
        secret_use=uses_credential or proxy_secret,
        replay_safety=Idempotency.NON_IDEMPOTENT,
        resolution_notes=(f"traffic_enabled={traffic_enabled}", f"method={method}"),
    )


def resolve_cors_intent(request: ActionRequest) -> AuthorizationIntent:
    args = request.input.model_dump(by_alias=True, exclude_unset=True)
    workspace_id = str(args.get("workspaceId") or request.context.workspace_id or workspace.default_workspace_id())
    snapshot = ScopeSnapshot.for_workspace(workspace_id)
    candidate = args.get("candidate") if isinstance(args.get("candidate"), dict) else {}
    target_url = str(candidate.get("url") or args.get("url") or "")
    follow_redirects = bool(args.get("followRedirects", True))
    exact_targets: tuple[TargetSelector, ...] = ()
    seeds: tuple[CanonicalTarget, ...] = ()
    entire_scope = False
    if target_url:
        target = CanonicalTarget.from_url(target_url)
        seeds = (target,)
        exact_targets = (
            TargetSelector(target, "any" if follow_redirects else "exact", "cors_probe_seed"),
        )
        # A dynamic cross-origin Location can name any current workspace-scope
        # target. Partial future grants can instead supply an exact envelope.
        entire_scope = follow_redirects
    backend = "disabled" if args.get("disableTraffic") is True else str(args.get("httpBackend") or "direct")
    provider = ProviderRoute.from_values(backend, args.get("proxyUrl"), args.get("proxyCredentialId"))
    method = str(candidate.get("method") or args.get("method") or "GET").upper()
    methods = tuple(sorted({method, *(("GET",) if follow_redirects else ())}))
    envelope = TargetEnvelope(
        workspace_id=workspace_id,
        scope_digest=snapshot.digest,
        scope_snapshot=snapshot,
        exact_targets=exact_targets,
        seeds=seeds,
        entire_workspace_scope=entire_scope,
        redirect_policy=RedirectPolicy(follow_redirects, int(args.get("maxRedirects") or 10) if follow_redirects else 0),
        expansion_reasons=("dynamic_redirect_within_frozen_workspace_scope",) if entire_scope else (),
    )
    return AuthorizationIntent(
        action_id="cors.execute_test",
        workspace_id=workspace_id,
        target_envelope=envelope,
        methods=methods,
        credential_refs=tuple(str(item) for item in (args.get("credentialId"), args.get("proxyCredentialId")) if item),
        providers=(provider,),
        lineage=ContinuationLineage(
            origin_action_id="cors.execute_test",
            origin_correlation_id=request.context.correlation_id,
        ),
    )


class CorsExecuteTestExecutor:
    input_model = CorsExecuteTestInput
    output_model = CorsExecuteTestOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        plan = request.context.execution_plan
        try:
            if plan is None:
                raise ExecutionPlanError("execution_plan_missing", "CORS execution requires a Registry execution plan.")
            plan.assert_runtime_input(args)
            result = cors.execute_test(args, execution_plan=plan)
        except ExecutionPlanError as exc:
            return ValidationFailure(str(exc), legacy_code=-32602, reason_code=exc.reason_code)
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
    intent_resolver=resolve_cors_intent,
)

REGISTRY.register(CORS_EXECUTE_TEST)
