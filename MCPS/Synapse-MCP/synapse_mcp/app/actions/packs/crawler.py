# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Registered crawler actions."""

from __future__ import annotations

from pydantic import ConfigDict

from synapse_mcp.adapters.web import crawler_adapter
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


CRAWLER_CRAWL_INPUT_DOCUMENT = InputContractDocument(
    source='{"type":"object","properties":{"target":{"type":"string"},"maxPages":{"type":"integer","minimum":1,"maximum":1000,"default":200},"maxDepth":{"type":"integer","minimum":0,"maximum":10,"default":6},"requestTimeout":{"type":"integer","minimum":1,"maximum":60,"default":15},"delayMillis":{"type":"integer","minimum":0,"maximum":10000,"default":0},"userAgent":{"type":"string","default":"SynapseCrawler/0.1"},"credentialId":{"type":"string"},"workspaceId":{"type":"string"},"includeStatic":{"type":"boolean","default":false},"includeInScopeHosts":{"type":"boolean","default":true},"analyzeScripts":{"type":"boolean","default":true},"followGetForms":{"type":"boolean","default":true},"submitPostForms":{"type":"boolean","default":false},"httpBackend":{"type":"string","enum":["direct","proxy","disabled"],"default":"direct"},"proxyUrl":{"type":"string"},"disableTraffic":{"type":"boolean","default":false},"maxBodyBytes":{"type":"integer","minimum":0},"verifyTls":{"type":"boolean","default":true},"http2":{"type":"boolean","default":false},"output":{"type":"string"},"allowExternalOutput":{"type":"boolean"},"timeoutSeconds":{"type":"integer","minimum":30},"background":{"type":"boolean","default":true},"approvalId":{"type":"string"},"approvalReason":{"type":"string"},"riskTier":{"type":"string"},"confirm":{"type":"boolean"}},"required":["target","confirm"]}'
)
CrawlerCrawlInput = make_input_model(
    "CrawlerCrawlInput",
    CRAWLER_CRAWL_INPUT_DOCUMENT,
)


class CrawlerCrawlOutput(ActionOutput):
    model_config = ConfigDict(extra="allow")


class CrawlerCrawlExecutor:
    input_model = CrawlerCrawlInput
    output_model = CrawlerCrawlOutput

    def __call__(self, request: ActionRequest):
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        try:
            result = crawler_adapter.crawl(args)
        except McpError as exc:
            return outcome_from_mcp_error(
                exc,
                confirm_declared=True,
                confirm_value=args.get("confirm"),
            )
        return Success(payload=result)


CRAWLER_CRAWL = ActionDescriptor(
    id=ActionId.parse("crawler.crawl"),
    pack="crawler",
    title="Crawl authorized target",
    summary="Actively crawl one authorized in-scope HTTP(S) target and build a site map.",
    input_model=CrawlerCrawlInput,
    output_model=CrawlerCrawlOutput,
    side_effect_class=SideEffectClass.ACTIVE_PROBE,
    risk_class=RiskClass.MODERATE,
    scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
    credential_policy=CredentialPolicy(
        CredentialRequirement.OPTIONAL,
        CredentialAccess.CREDENTIAL_USE,
    ),
    idempotency_policy=IdempotencyPolicy(Idempotency.NON_IDEMPOTENT),
    task_policy=TaskPolicy(DeadlineTier.DEFAULT, True, False),
    executor=CrawlerCrawlExecutor(),
    availability=Availability(available=True),
)

REGISTRY.register(CRAWLER_CRAWL)
