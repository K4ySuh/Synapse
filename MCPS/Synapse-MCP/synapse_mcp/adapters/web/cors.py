# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import credentials, evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import priority_for_score, redact_headers, stable_slug, store_http_exchange_evidence
from .candidate_dedupe import collapse_host_wide
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url

DEFAULT_PROBE_ORIGIN = "https://synapse-cors-probe.invalid"


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("cors"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 50))
    context = workspace.prepare_target_context(workspace_id, target, purpose="cors_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
    }
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"adapter": "cors", "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "cors.analyze_workspace",
        f"Analyzed CORS candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        headers = endpoint.get("responseHeaders")
        if not isinstance(headers, dict):
            continue
        url = normalize_surface_url(endpoint.get("url", ""))
        if not url or is_candidate_noise_url(url):
            continue
        normalized_endpoint = {**endpoint, "url": url}
        lowered = {str(name).lower(): str(value) for name, value in headers.items()}
        acao = lowered.get("access-control-allow-origin")
        if not acao:
            continue
        candidate = _candidate_from_headers(normalized_endpoint, acao, _is_truthy(lowered.get("access-control-allow-credentials")))
        if candidate:
            candidates.setdefault(candidate["candidateId"], candidate)
    values = sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)
    return collapse_host_wide(values, subject_key="header")


def _candidate_from_headers(endpoint: dict[str, Any], acao: str, creds: bool) -> dict[str, Any] | None:
    host = urlsplit(str(endpoint.get("url", ""))).netloc.lower()
    acao_value = acao.strip()
    if acao_value == "*":
        score, reason = (60, "Access-Control-Allow-Origin is '*' together with credentials, which is invalid and high-risk if honored.") if creds \
            else (25, "Access-Control-Allow-Origin is '*'; review whether the endpoint should be publicly cross-origin readable.")
    elif acao_value.lower() == "null":
        score, reason = 70, "Access-Control-Allow-Origin is 'null', which sandboxed/file origins can forge."
    elif host and host in acao_value.lower():
        return None  # Same-origin ACAO is expected and not a finding.
    else:
        score, reason = (65, "A specific cross-origin is allowed with credentials; verify it is not reflecting arbitrary origins.") if creds \
            else (30, "A specific cross-origin is allowed; confirm the allowlist is intentional and not origin-reflected.")
    return _build_candidate(endpoint, acao_value, creds, score, reason)


def _build_candidate(endpoint: dict[str, Any], acao: str, creds: bool, score: int, reason: str) -> dict[str, Any]:
    url = str(endpoint.get("url", ""))
    return {
        "candidateId": f"cors_{stable_slug(url)}"[:170],
        "type": "cors_candidate",
        "url": url,
        "method": str(endpoint.get("method", "GET")).upper(),
        "header": acao,
        "observedAllowOrigin": acao,
        "allowCredentials": creds,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 65 else "low",
        "reasons": [reason],
        "testPlanSummary": "Send one approved probe with a crafted Origin and confirm whether it is reflected with credentials.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="cors_candidate",
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "CORS candidate identified.",
            tags=["cors", "misconfiguration-candidate"],
            metadata={
                "candidateId": candidate["candidateId"],
                "observedAllowOrigin": candidate.get("observedAllowOrigin", ""),
                "allowCredentials": candidate.get("allowCredentials", False),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
                "dedupeScope": candidate.get("dedupeScope", "endpoint"),
                "host": candidate.get("host", ""),
                "affectedUrls": candidate.get("affectedUrls", []),
                "affectedCount": candidate.get("affectedCount", 1 if candidate.get("url") else 0),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="cors",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} CORS candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis reads observed Access-Control-* headers only; reflection is confirmed by an approved active probe.",
        ],
        metadata={"observationCount": len(observations)},
    )


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = _coerce_candidate(args)
    probe_origin = str(args.get("probeOrigin") or DEFAULT_PROBE_ORIGIN)
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": str(candidate.get("method", "GET")).upper(),
        "sendsTraffic": False,
        "probeOrigin": probe_origin,
        "expectedSignals": [
            f"Access-Control-Allow-Origin in the response echoes the probe origin {probe_origin}.",
            "Access-Control-Allow-Credentials is 'true' alongside a reflected, 'null', or wildcard origin (high risk).",
        ],
        "guardrails": [
            "This helper builds a plan only; it does not send traffic.",
            "Run the probe only against explicitly authorized in-scope targets after operator approval (confirm=true).",
            "Use a benign, operator-controlled probe origin; do not exfiltrate cross-origin data.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running a CORS active probe requires confirm=true.")
    candidate = _coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    if not target_url:
        raise McpError(-32602, "A target url is required.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    probe_origin = str(args.get("probeOrigin") or DEFAULT_PROBE_ORIGIN)
    method = str(candidate.get("method", "GET")).upper()
    headers = {"User-Agent": "Synapse-MCP/0.1", "Origin": probe_origin}
    if args.get("credentialId"):
        credential = credentials.credential_for_target(str(args["credentialId"]), target_url)
        headers.update(credentials.headers_for_credential_target(credential, target_url))
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    response_payload = http_client.send(HttpRequest(url=target_url, method=method, headers=headers), policy=policy).as_dict()
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "cors_http_exchange",
        request={"url": target_url, "method": method, "headers": headers, "body": ""},
        response=response_payload,
        metadata={"adapter": "cors", "target": target_url, "probeOrigin": probe_origin, "approval": approval},
    )
    response_headers = {str(name).lower(): str(value) for name, value in response_payload.get("headers", {}).items()}
    acao = response_headers.get("access-control-allow-origin", "")
    creds = _is_truthy(response_headers.get("access-control-allow-credentials"))
    reflected = bool(acao) and acao.strip() == probe_origin
    null_or_wildcard = acao.strip().lower() in {"null", "*"}
    if (reflected or null_or_wildcard) and creds:
        assessment = "possible_cors_misconfiguration"
    elif reflected:
        assessment = "possible_cors_misconfiguration"
    else:
        assessment = "inconclusive"
    raw = {
        "candidate": candidate,
        "probeOrigin": probe_origin,
        "request": {"url": target_url, "method": method},
        "requestHeaders": redact_headers(headers),
        "response": {
            "status": response_payload.get("status"),
            "accessControlAllowOrigin": acao,
            "accessControlAllowCredentials": creds,
        },
        "exchangeEvidence": exchange_evidence,
        "originReflected": reflected,
        "assessment": assessment,
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "cors_test",
        "active_validation",
        "json",
        json.dumps(raw, indent=2, ensure_ascii=False),
        {"approval": approval, "target": target_url, "host": scope_result["host"]},
    )
    action = workspace.record_action(
        workspace_id,
        scope_result["host"],
        {
            "type": "active_validation",
            "tool": "cors.execute_test",
            "target": target_url,
            "method": method,
            "probeOrigin": probe_origin,
            "originReflected": reflected,
            "assessment": assessment,
            "exchangeEvidenceId": exchange_evidence.get("evidenceId", ""),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "cors.execute_test",
        f"Ran approved CORS probe against {scope_result['host']} with origin {probe_origin}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="origin_reflection_probe",
            description="Send one request with a crafted Origin header and check whether it is reflected with credentials.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="Use a single benign probe origin; inspect Access-Control-Allow-Origin/-Credentials only.",
        )
    ]


def _coerce_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    if "url" not in args:
        raise McpError(-32602, "Provide a candidate object or a url (with optional method).")
    return {
        "candidateId": args.get("candidateId", ""),
        "url": args["url"],
        "method": args.get("method", "GET"),
        "reasons": args.get("reasons", []),
    }


def _is_truthy(value: Any) -> bool:
    return str(value or "").strip().lower() == "true"
