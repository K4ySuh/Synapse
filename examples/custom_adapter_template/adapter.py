from __future__ import annotations

import json
from typing import Any

from synapse_mcp.core import evidence, workspace
from synapse_mcp.core.adapters import (
    AdapterMetadata,
    AdapterRegistry,
    AdapterResult,
    SynapseAdapter,
    WorkspaceEntityBundle,
    candidate_observation,
)


REQUIRED_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
}


class SecurityHeadersAdapter(SynapseAdapter):
    metadata = AdapterMetadata(
        name="security_headers_template",
        version="0.1.0",
        category="custom",
        description="Template adapter that passively flags endpoints with observed missing security headers.",
        capabilities=["passive_analysis", "test_planning", "result_ingestion"],
        requires_scope=True,
        sends_traffic=False,
        requires_confirmation=False,
        default_risk_tier="info",
        execution_mode="passive_only",
        produces=["observations", "evidence"],
        limitations=[
            "Only analyzes headers already present in workspace endpoint metadata.",
            "Does not send requests or confirm exploitability.",
        ],
    )

    def passive_analyze(self, args: dict[str, Any]) -> dict[str, Any]:
        workspace_id = args["workspaceId"]
        target = args["target"]
        wid = workspace.normalize_workspace_id(workspace_id)
        host = workspace.normalize_target(target)
        entities = workspace._load_target_entities(wid, host)
        observations = security_header_observations(entities.get("endpoints", []))
        result = AdapterResult(
            adapter=self.metadata.name,
            mode="passive_analysis",
            workspace_id=wid,
            target=host,
            summary=f"Identified {len(observations)} endpoint security-header observations.",
            entities=WorkspaceEntityBundle(observations=observations),
            limitations=list(self.metadata.limitations),
        )
        ingestion = None
        if args.get("ingest", True):
            ingestion = workspace.ingest_data(
                wid,
                host,
                "adapter_result",
                "passive_analysis",
                "json",
                json.dumps(result.as_ingest_payload(), indent=2, ensure_ascii=False),
                {"adapter": self.metadata.name},
            )
        evidence.log_event(
            "security_headers_template.passive_analyze",
            f"Analyzed security-header metadata for {host}.",
            {"workspaceId": wid, "target": host, "observationCount": len(observations), "ingested": bool(ingestion)},
        )
        return {**result.as_ingest_payload(), **({"ingestion": ingestion} if ingestion else {})}

    def plan(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "adapter": self.metadata.name,
            "sendsTraffic": False,
            "recommendedSteps": [
                "Review whether response headers were captured for each endpoint.",
                "Validate missing-header observations manually before promoting findings.",
                "If active validation is later added, enforce scope and confirm=true.",
            ],
        }


def security_header_observations(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        headers = endpoint.get("responseHeaders")
        if not isinstance(headers, dict):
            continue
        observed = {str(name).lower() for name in headers}
        missing = sorted(REQUIRED_SECURITY_HEADERS - observed)
        if not missing:
            continue
        observations.append(
            candidate_observation(
                candidate_type="security_headers_missing_candidate",
                value=endpoint.get("url", endpoint.get("path", "")),
                url=endpoint.get("url", ""),
                method=str(endpoint.get("method", "GET")).upper(),
                confidence="low",
                priority="low",
                priority_score=35,
                reason="Endpoint response metadata is missing one or more common browser security headers.",
                tags=["security-headers", "passive"],
                metadata={"missingHeaders": missing},
            ).as_dict()
        )
    return observations


def register_adapter(registry: AdapterRegistry) -> SecurityHeadersAdapter:
    adapter = SecurityHeadersAdapter()
    registry.register(adapter)
    return adapter
