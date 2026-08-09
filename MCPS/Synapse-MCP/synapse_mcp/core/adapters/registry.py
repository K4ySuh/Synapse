# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable

from ..errors import McpError
from .base import SynapseAdapter
from .models import AdapterMetadata


class MetadataAdapter(SynapseAdapter):
    def __init__(self, metadata: AdapterMetadata):
        self.metadata = metadata


class ActionMetadataBridgeAdapter(MetadataAdapter):
    """Transitional discovery bridge for packs migrated to Action Registry v2."""

    def __init__(self, metadata: AdapterMetadata, action_ids: tuple[str, ...]):
        super().__init__(metadata)
        self.action_ids = action_ids
        self.metadata_provider: Callable[[tuple[str, ...]], dict[str, Any]] | None = None

    def capabilities(self) -> dict[str, Any]:
        if self.metadata_provider is None:
            raise McpError(-32000, "Action metadata provider is not configured for adapter discovery.")
        payload = self.metadata.as_dict()
        payload.update(self.metadata_provider(self.action_ids))
        return payload


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, SynapseAdapter] = {}

    def register(self, adapter: SynapseAdapter) -> None:
        name = adapter.metadata.name.strip()
        if not name:
            raise ValueError("Adapter name is required.")
        if name in self._adapters:
            raise ValueError(f"Adapter already registered: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> SynapseAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise McpError(-32602, f"Unknown adapter: {name}") from exc

    def list(self) -> list[dict[str, Any]]:
        return [self._summary(adapter.capabilities()) for adapter in self._adapters.values()]

    def capabilities(self, name: str) -> dict[str, Any]:
        return self.get(name).capabilities()

    def set_action_metadata_provider(
        self,
        provider: Callable[[tuple[str, ...]], dict[str, Any]],
    ) -> None:
        """Install the application-layer projection for migrated adapters."""

        for adapter in self._adapters.values():
            if isinstance(adapter, ActionMetadataBridgeAdapter):
                adapter.metadata_provider = provider

    @staticmethod
    def _summary(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": payload["name"],
            "category": payload["category"],
            "capabilities": payload["capabilities"],
            "sendsTraffic": payload["sendsTraffic"],
            "requiresConfirmation": payload["requiresConfirmation"],
            "requiresScope": payload["requiresScope"],
            "requiresCredentials": payload["requiresCredentials"],
            "touchesThirdParty": payload["touchesThirdParty"],
            "defaultRiskTier": payload["defaultRiskTier"],
            "executionMode": payload["executionMode"],
            "backgroundJobProvider": payload["backgroundJobProvider"],
            "executorTool": payload["executorTool"],
            "produces": payload["produces"],
            **({"operationalMetadataSource": payload["operationalMetadataSource"]} if "operationalMetadataSource" in payload else {}),
            **({"actions": payload["actions"]} if "actions" in payload else {}),
        }


def _metadata(**kwargs: Any) -> MetadataAdapter:
    return MetadataAdapter(AdapterMetadata(**kwargs))


def _action_metadata(*, action_ids: tuple[str, ...], **kwargs: Any) -> ActionMetadataBridgeAdapter:
    return ActionMetadataBridgeAdapter(AdapterMetadata(**kwargs), action_ids)


def build_default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    for adapter in [
        _metadata(
            name="spec_import",
            category="web",
            description="Passively imports OpenAPI/Swagger/Postman specifications and normalizes documented endpoints, parameters, and auth schemes into the workspace.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="info",
            produces=["endpoints", "parameters", "observations", "evidence"],
            limitations=[
                "Imports documented surface only; presence in a spec is not proof an endpoint is live.",
                "Documented endpoints are marked inferred and are not treated as observed traffic.",
            ],
        ),
        _metadata(
            name="sitemap",
            category="web",
            description="Builds a passive site map from offline Burp dump artifacts and can ingest normalized endpoint context.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="info",
            produces=["endpoints", "parameters", "observations", "evidence"],
            limitations=["Requires an existing offline Burp dump."],
        ),
        _action_metadata(
            action_ids=("crawler.crawl",),
            name="crawler",
            category="web",
            description="Actively crawls an authorized HTTP target with bounded depth/page limits and supports an authenticated extended POST-form mapping mode.",
            capabilities=["active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="async_default",
            background_job_provider="jobs",
            executor_tool="crawler.crawl",
            produces=["endpoints", "observations", "evidence"],
            limitations=["crawler.extended requires a prior crawler.crawl action, scoped credentials, and explicit confirmation before submitting POST forms."],
        ),
        _metadata(
            name="ffuf",
            category="web",
            description="Builds and runs constrained content discovery profiles against authorized targets.",
            capabilities=["command_building", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="async_default",
            background_job_provider="jobs",
            executor_tool="ffuf.run_profile",
            produces=["endpoints", "observations", "evidence"],
            limitations=["Execution is limited to named Synapse profiles."],
        ),
        _metadata(
            name="nuclei",
            category="web",
            description="Builds and runs adaptive Nuclei profiles using workspace context and operator-supplied constraints.",
            capabilities=["command_building", "active_testing", "result_ingestion", "finding_generation"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="medium",
            execution_mode="async_default",
            background_job_provider="jobs",
            executor_tool="nuclei.run_profile",
            produces=["observations", "candidate_findings", "evidence"],
            limitations=["Execution is limited by Synapse profile policy and explicit operator options."],
        ),
        _metadata(
            name="cve",
            category="web",
            description="Correlates fingerprinted components with multi-source CVE intelligence, stores candidate CVE exposure observations, and prepares bounded verification replays.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion", "finding_generation"],
            sends_traffic=True,
            requires_confirmation=True,
            touches_third_party=True,
            default_risk_tier="medium",
            execution_mode="sync_only",
            executor_tool="cve.execute_test",
            produces=["observations", "candidate_observations", "findings", "evidence"],
            limitations=[
                "Online intelligence sources can fail, rate-limit, or change schemas independently.",
                "Presence in NVD, Shodan, or a PoC index is not proof that the CVE is exploitable on this target.",
                "PoC and exploit references are stored as read-only intelligence and are never fetched or executed as code.",
            ],
        ),
        _metadata(
            name="sqli",
            category="web",
            description="Passively analyzes offline dump requests for SQL injection candidates and builds validated sqlmap commands.",
            capabilities=["passive_analysis", "command_building", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Synapse builds sqlmap commands but does not execute sqlmap."],
        ),
        _metadata(
            name="xss",
            category="web",
            description="Passively analyzes XSS sources, sinks, and reflections, and can run approved benign reflection probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            execution_mode="sync_only",
            executor_tool="xss.execute_test",
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation is limited to benign marker/tag reflection probes and does not execute browser JavaScript."],
        ),
        _action_metadata(
            action_ids=("headers_cookies.analyze_workspace",),
            name="headers_cookies",
            category="web",
            description="Passively analyzes recorded response security headers and cookie flags (CSP, HSTS, X-Frame-Options, HttpOnly/Secure/SameSite) for hygiene weaknesses.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=[
                "Analyzes only response metadata already in the workspace; coverage depends on a prior crawl or dump ingest.",
                "Cookie analysis uses names and flags only; cookie values are never stored or read.",
            ],
        ),
        _metadata(
            name="jwt",
            category="web",
            description="Offline structural analysis of a supplied JWT: alg=none, weak built-in HMAC secrets, kid injection surface, missing expiry, and privileged claims.",
            capabilities=["passive_analysis"],
            sends_traffic=False,
            default_risk_tier="info",
            execution_mode="sync_only",
            produces=["observations"],
            limitations=[
                "Offline structural analysis only; does not validate signatures against the server or forge tokens.",
                "The raw token and any matched secret value are never stored or echoed.",
            ],
        ),
        _metadata(
            name="csrf",
            category="web",
            description="Passively identifies state-changing forms that lack a recognized anti-CSRF token field, cross-referenced with weak cookie SameSite signals.",
            capabilities=["passive_analysis", "test_planning", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=[
                "Candidate-only; absence of a recognized token field is not proof of exploitable CSRF.",
                "Token detection is name-based; double-submit-cookie or header-token schemes may not be visible passively.",
            ],
        ),
        _action_metadata(
            action_ids=("cors.execute_test",),
            name="cors",
            category="web",
            description="Passively identifies permissive CORS responses and runs one approved bounded Origin-reflection probe.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="sync_only",
            executor_tool="cors.execute_test",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation is limited to bounded Origin-reflection probes against in-scope hosts after operator approval."],
        ),
        _metadata(
            name="insecure_deser",
            category="web",
            description="Passively detects recognizable serialized object blob markers in normalized parameters and cookie names without deserializing them.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=[
                "Signature-based prefix detection only; a recognizable blob is not proof of an unsafe deserializer, and signed/encrypted blobs may still be vulnerable or benign.",
            ],
        ),
        _metadata(
            name="xxe",
            category="web",
            description="Passively identifies XML/SOAP-accepting endpoints and can run approved benign in-band entity expansion probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            execution_mode="sync_only",
            executor_tool="xxe.execute_test",
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=[
                "Active validation uses only benign in-band entity expansion checks; it does not read files or trigger external entity callbacks.",
            ],
        ),
        _metadata(
            name="graphql",
            category="web",
            description="Passively identifies GraphQL endpoints and runs one approved introspection probe that can normalize schema operations and arguments into the workspace.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="sync_only",
            executor_tool="graphql.execute_test",
            produces=["endpoints", "parameters", "observations", "evidence"],
            limitations=[
                "Active introspection sends one bounded POST per candidate against in-scope hosts after operator approval; it does not execute discovered mutations.",
            ],
        ),
        _metadata(
            name="tls_posture",
            category="web",
            description="Passively normalizes TLS certificate and protocol posture observations from already-collected Shodan/perimeter SSL data.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=False,
            default_risk_tier="info",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=[
                "Normalizes TLS data already collected by shodan/perimeter ingestion; it performs no live TLS handshake. Deep cipher/protocol scanning belongs to external tools.",
            ],
        ),
        _metadata(
            name="ssrf",
            category="web",
            description="Passively identifies SSRF-like URL, host, webhook, proxy, import, preview, and callback surfaces, and can send approved external canary probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            execution_mode="sync_only",
            executor_tool="ssrf.execute_test",
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation requires an operator-controlled external callback URL and does not probe localhost, metadata, or private address ranges."],
        ),
        _metadata(
            name="open_redirect",
            category="web",
            description="Passively identifies redirect, return, continuation, SSO, OAuth, and callback surfaces, and can run approved harmless external redirect probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            execution_mode="sync_only",
            executor_tool="open_redirect.execute_test",
            default_risk_tier="low",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation uses harmless external URL payloads and captures redirects without following them by default."],
        ),
        _metadata(
            name="command_injection",
            category="web",
            description="Passively identifies likely command-execution inputs and can run one approved benign marker test.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="medium",
            execution_mode="sync_only",
            executor_tool="command_injection.execute_test",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation is limited to a single benign marker request."],
        ),
        _metadata(
            name="ssti",
            category="web",
            description="Identifies server-side template injection candidate surfaces and runs approved benign arithmetic probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="sync_only",
            executor_tool="ssti.execute_test",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation is limited to benign arithmetic and syntax-differential probes."],
        ),
        _metadata(
            name="lfi",
            category="web",
            description="Identifies LFI, RFI, path traversal, and file download candidate surfaces with approved benign file-handling probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="sync_only",
            executor_tool="lfi.execute_test",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["Active validation avoids sensitive system files and off-site RFI payloads by default."],
        ),
        _metadata(
            name="ssi",
            category="web",
            description="Identifies server-side include candidate surfaces and runs approved benign marker or SSI echo probes.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="sync_only",
            executor_tool="ssi.execute_test",
            produces=["observations", "candidate_observations", "evidence"],
            limitations=["SSI signals are often low-confidence unless response sink evidence is available."],
        ),
        _metadata(
            name="access_control",
            category="web",
            description="Maps object identifiers, user contexts, and BOLA/BOPLA/BFLA-style access-control test matrices, with approved cross-context replay.",
            capabilities=["passive_analysis", "test_planning", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="medium",
            execution_mode="sync_only",
            executor_tool="access_control.execute_matrix_test",
            produces=["observations", "candidate_observations", "evidence", "access_control_models"],
            limitations=["Replay requires explicit operator approval and stores sanitized response summaries rather than full response bodies."],
        ),
        _metadata(
            name="js_intelligence",
            category="web",
            description="Discovers, fetches, and statically analyzes JavaScript assets to enrich workspace endpoints, parameters, and application model signals.",
            capabilities=["passive_analysis", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="low",
            execution_mode="async_default",
            background_job_provider="jobs",
            produces=["javascript_assets", "endpoints", "parameters", "observations", "app_model", "app_map_report"],
            limitations=[
                "Only js.fetch_assets sends traffic; all other JS intelligence tools are passive workspace analysis.",
                "JavaScript is never executed.",
                "Derived endpoints are marked inferred and are not treated as directly observed traffic.",
            ],
        ),
        _metadata(
            name="nmap",
            category="network",
            description="Builds and runs constrained nmap profiles against authorized infrastructure targets.",
            capabilities=["command_building", "active_testing", "result_ingestion"],
            sends_traffic=True,
            requires_confirmation=True,
            default_risk_tier="medium",
            execution_mode="async_default",
            background_job_provider="jobs",
            executor_tool="nmap.run_profile",
            produces=["services", "observations", "evidence"],
            limitations=["Execution is limited to named Synapse profiles."],
        ),
        _metadata(
            name="shodan",
            category="network",
            description="Plans Shodan pivots and performs approved API-backed external exposure lookups with runtime-only API keys.",
            capabilities=["passive_analysis", "result_ingestion"],
            requires_scope=False,
            sends_traffic=True,
            requires_confirmation=True,
            touches_third_party=True,
            default_risk_tier="info",
            execution_mode="sync_only",
            produces=["services", "endpoints", "asset_relations", "dns_observations", "cve_candidates", "evidence"],
            limitations=[
                "Network-touching operations query Shodan or InternetDB rather than the assessed target, require confirmation, and may consume Shodan credits.",
                "Discovered assets are normalized separately from the query seed and remain external-intelligence candidates until the operator reviews authorization and relevance.",
            ],
        ),
        _metadata(
            name="pretext_generator",
            category="red_team",
            description="Normalizes phishing pretext candidates, preserves provenance links to source observations, and requires explicit operator approval before use.",
            capabilities=["result_ingestion"],
            sends_traffic=False,
            requires_confirmation=True,
            default_risk_tier="high",
            produces=["pretext_candidates"],
            limitations=[
                "Does not generate content itself; it normalizes already-generated candidate drafts.",
                "Draft candidates remain unapproved until an operator calls approve_pretext_candidate with confirmation.",
                "Pretext body content is internal-only and excluded from high-level report output.",
            ],
        ),
    ]:
        registry.register(adapter)
    return registry


default_registry = build_default_registry()
