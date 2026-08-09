# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered crawler actions."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ConfigDict, JsonValue, model_validator

from synapse_mcp.adapters.web import crawler_adapter
from synapse_mcp.core import workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import (
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    ExecutionPlanError,
    LocalOutputDestination,
    ProviderRoute,
    RedirectPolicy,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
    resolve_local_outputs,
)

from ..contracts import ActionOutput, InputContractDocument, make_input_model
from ..descriptor import ActionDescriptor, ActionRequest
from ..identity import ActionId
from ..outcomes import Success, ValidationFailure, legacy_payload_signals_error, outcome_from_mcp_error
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


CRAWLER_CRAWL_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"target":{"type":"string"},"maxPages":{"type":"integer","minimum":1,"maximum":1000,"default":200},"maxDepth":{"type":"integer","minimum":0,"maximum":10,"default":6},"requestTimeout":{"type":"integer","minimum":1,"maximum":60,"default":15},"delayMillis":{"type":"integer","minimum":0,"maximum":10000,"default":0},"userAgent":{"type":"string","default":"SynapseCrawler/0.1"},"credentialId":{"type":"string"},"workspaceId":{"type":"string"},"includeStatic":{"type":"boolean","default":false},"includeInScopeHosts":{"type":"boolean","default":true},"analyzeScripts":{"type":"boolean","default":true},"followGetForms":{"type":"boolean","default":true},"submitPostForms":{"type":"boolean","default":false},"httpBackend":{"type":"string","enum":["direct","proxy","disabled"],"default":"direct"},"proxyUrl":{"type":"string"},"disableTraffic":{"type":"boolean","default":false},"maxBodyBytes":{"type":"integer","minimum":0},"verifyTls":{"type":"boolean","default":true},"http2":{"type":"boolean","default":false},"output":{"type":"string"},"allowExternalOutput":{"type":"boolean"},"timeoutSeconds":{"type":"integer","minimum":30},"background":{"type":"boolean","default":true},"approvalId":{"type":"string"},"approvalReason":{"type":"string"},"riskTier":{"type":"string"},"confirm":{"type":"boolean"}},"required":["target","confirm"]}'
)
CrawlerCrawlInput = make_input_model(
    "CrawlerCrawlInput",
    CRAWLER_CRAWL_INPUT_DOCUMENT,
)


class CrawlerCrawlOutput(ActionOutput):
    target: str
    workspaceId: str
    background: bool
    status: str | None = None
    job: dict[str, JsonValue] | None = None
    source: dict[str, JsonValue] | None = None
    summary: dict[str, int] | None = None
    hosts: list[dict[str, JsonValue]] | None = None
    outputPath: str | None = None
    model_config = ConfigDict(strict=True, extra="allow")

    @model_validator(mode="after")
    def validate_result_family(self):
        if self.background:
            if not self.target or not self.workspaceId or self.job is None:
                raise ValueError("background crawl output requires target, workspaceId, and job")
        elif self.source is None or self.summary is None or self.hosts is None:
            raise ValueError("foreground crawl output requires source, summary, and hosts")
        return self


CRAWLER_MAX_EFFECTS = ActionEffects(
    traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
    local_writes=frozenset(
        {
            LocalWriteDomain.WORKSPACE,
            LocalWriteDomain.EVIDENCE,
            LocalWriteDomain.JOBS,
            LocalWriteDomain.REPORTS_ARTIFACTS,
        }
    ),
    local_change=True,
    local_destruction=True,
    remote_state_change=True,
    credential_use=True,
    secret_use=True,
    replay_safety=Idempotency.NON_IDEMPOTENT,
)


def resolve_crawler_effects(request: ActionRequest) -> ActionEffects:
    args = request.input.model_dump(by_alias=True)
    traffic_enabled = not bool(args.get("disableTraffic")) and args.get("httpBackend", "direct") != "disabled"
    background = bool(args.get("background", True))
    uses_credential = bool(args.get("credentialId") or args.get("proxyCredentialId"))
    writes = {LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE, LocalWriteDomain.REPORTS_ARTIFACTS}
    if background:
        writes.add(LocalWriteDomain.JOBS)
    output = str(args.get("output") or "")
    may_overwrite = not output or (bool(output) and Path(output).expanduser().resolve(strict=False).exists())
    proxy_url = str(args.get("proxyUrl") or "")
    proxy_secret = bool(urlsplit(proxy_url).username or urlsplit(proxy_url).password) if proxy_url else False
    return ActionEffects(
        traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}) if traffic_enabled else frozenset(),
        local_writes=frozenset(writes),
        local_change=True,
        local_destruction=may_overwrite or background,
        remote_state_change=traffic_enabled and bool(args.get("submitPostForms", False)),
        credential_use=uses_credential,
        secret_use=uses_credential or proxy_secret,
        replay_safety=Idempotency.NON_IDEMPOTENT,
        resolution_notes=(
            f"traffic_enabled={traffic_enabled}",
            f"background={background}",
            f"include_in_scope_hosts={bool(args.get('includeInScopeHosts', True))}",
            f"output_may_overwrite_or_prune={may_overwrite}",
            f"continuation_cleanup={background}",
        ),
    )


def resolve_crawler_intent(request: ActionRequest) -> AuthorizationIntent:
    args = request.input.model_dump(by_alias=True, exclude_unset=True)
    workspace_id = str(args.get("workspaceId") or request.context.workspace_id or workspace.default_workspace_id())
    snapshot = ScopeSnapshot.for_workspace(workspace_id)
    seed = CanonicalTarget.from_url(str(args["target"]))
    include_scope = bool(args.get("includeInScopeHosts", True))
    target_selector = TargetSelector(seed, "any", "crawler_seed_origin")
    envelope = TargetEnvelope(
        workspace_id=workspace_id,
        scope_digest=snapshot.digest,
        scope_snapshot=snapshot,
        exact_targets=(target_selector,),
        seeds=(seed,),
        entire_workspace_scope=include_scope,
        redirect_policy=RedirectPolicy(True, 10),
        expansion_reasons=("crawler_include_in_scope_hosts",) if include_scope else (),
    )
    host = seed.host
    suffix = f"{host}-crawler-crawl-sitemap.json"
    default_path = (
        workspace.target_path(workspace_id, host)
        / "outputs"
        / workspace.slug("sitemap")
        / workspace.timestamped_filename(suffix)
    )
    outputs = resolve_local_outputs(
        requested_path=str(args.get("output")) if args.get("output") else None,
        default_path=default_path,
        workspace_root=workspace.workspace_path(workspace_id),
        allow_external=bool(args.get("allowExternalOutput")),
    )
    if bool(args.get("background", True)):
        internal_root = (workspace.target_path(workspace_id, host) / "outputs" / "jobs").resolve(strict=False)
        internal_specs = (
            (internal_root / workspace.timestamped_filename("crawler-crawl-args.json"), "crawler.worker_args", True),
            (internal_root / workspace.timestamped_filename("crawler-crawl-result.json"), "crawler.worker_result", False),
            (internal_root / workspace.timestamped_filename("crawler-crawl-state.json"), "crawler.worker_state", True),
            (internal_root / workspace.timestamped_filename("crawler-crawl-plan.json"), "crawler.worker_plan", True),
        )
        outputs += tuple(
            LocalOutputDestination(
                str(path),
                purpose,
                True,
                "overwrite" if path.exists() else "create",
                may_prune,
            )
            for path, purpose, may_prune in internal_specs
        )
    backend = "disabled" if args.get("disableTraffic") is True else str(args.get("httpBackend") or "direct")
    provider = ProviderRoute.from_values(backend, args.get("proxyUrl"), args.get("proxyCredentialId"))
    methods = ("GET", "POST") if bool(args.get("submitPostForms")) else ("GET",)
    return AuthorizationIntent(
        action_id="crawler.crawl",
        workspace_id=workspace_id,
        target_envelope=envelope,
        methods=methods,
        credential_refs=tuple(str(item) for item in (args.get("credentialId"), args.get("proxyCredentialId")) if item),
        providers=(provider,),
        local_outputs=outputs,
        lineage=ContinuationLineage(
            origin_action_id="crawler.crawl",
            origin_correlation_id=request.context.correlation_id,
        ),
    )


class CrawlerCrawlExecutor:
    input_model = CrawlerCrawlInput
    output_model = CrawlerCrawlOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        plan = request.context.execution_plan
        try:
            if plan is None:
                raise ExecutionPlanError("execution_plan_missing", "Crawler execution requires a Registry execution plan.")
            plan.assert_runtime_input(args)
            result = crawler_adapter.crawl(
                args,
                execution_plan=plan,
                authorization_receipt=request.context.authorization_receipt,
            )
        except ExecutionPlanError as exc:
            return ValidationFailure(str(exc), legacy_code=-32602, reason_code=exc.reason_code)
        except McpError as exc:
            return outcome_from_mcp_error(
                exc,
                confirm_declared=True,
                confirm_value=args.get("confirm"),
            )
        canonical = json.loads(result)
        if not isinstance(canonical, dict):
            return Success(payload=canonical, legacy_payload=result)
        canonical.setdefault("target", str(args["target"]))
        canonical.setdefault("workspaceId", str(args.get("workspaceId") or workspace.default_workspace_id()))
        canonical.setdefault("background", bool(args.get("background", True)))
        return Success(
            payload=canonical,
            payload_signals_error=legacy_payload_signals_error(result),
            legacy_payload=result,
        )


CRAWLER_CRAWL = ActionDescriptor(
    id=ActionId.parse("crawler.crawl"),
    pack="crawler",
    title="Crawl authorized target",
    summary="Actively crawl one authorized in-scope HTTP(S) target and build a site map.",
    input_model=CrawlerCrawlInput,
    output_model=CrawlerCrawlOutput,
    effects=CRAWLER_MAX_EFFECTS,
    effect_resolver=resolve_crawler_effects,
    risk_class=RiskClass.MODERATE,
    scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
    credential_policy=CredentialPolicy(
        CredentialRequirement.OPTIONAL,
        CredentialAccess.CREDENTIAL_USE,
    ),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, True, False),
    executor=CrawlerCrawlExecutor(),
    availability=Availability(available=True),
    intent_resolver=resolve_crawler_intent,
)

REGISTRY.register(CRAWLER_CRAWL)
