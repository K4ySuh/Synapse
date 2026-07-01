# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import (
    build_http_request,
    build_manual_replay,
    coerce_candidate,
    priority_for_score,
    redact_headers,
    response_summary,
    stable_slug,
    store_http_exchange_evidence,
)
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url


SSI_PATH_MARKERS = (".shtml", ".shtm", ".stm", "server-parsed", "ssi", "include", "cms", "legacy")
SSI_PARAM_MARKERS = {"comment", "html", "body", "content", "message", "description", "footer", "header", "include", "template"}


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("ssi"), indent=2)


def passive_analyze(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 25))
    min_score = int(args.get("minScore", 25))
    context = workspace.prepare_target_context(workspace_id, target, purpose="ssi_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities, min_score)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": context_summary(context),
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
            {"adapter": "ssi", "minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "ssi.passive_analyze",
        f"Analyzed SSI candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        candidate = candidate_from_endpoint(endpoint)
        if candidate and candidate["priorityScore"] >= min_score:
            candidates[candidate["candidateId"]] = candidate
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        candidate = candidate_from_parameter(parameter)
        if candidate and candidate["priorityScore"] >= min_score:
            candidates[candidate["candidateId"]] = candidate
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        candidate = candidate_from_observation(observation)
        if candidate and candidate["priorityScore"] >= min_score:
            candidates.setdefault(candidate["candidateId"], candidate)
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def candidate_from_endpoint(endpoint: dict[str, Any]) -> dict[str, Any] | None:
    url = str(endpoint.get("url", ""))
    if is_candidate_noise_url(url):
        return None
    path = str(endpoint.get("path", "") or urlsplit(url).path).lower()
    content_types = json.dumps(endpoint.get("contentTypes", endpoint.get("contentType", ""))).lower()
    reasons = []
    score = 0
    if any(marker in path for marker in SSI_PATH_MARKERS):
        score += 50
        reasons.append("Endpoint path or extension suggests server-side include or server-parsed content.")
    if "text/html" in content_types:
        score += 10
        reasons.append("Endpoint appears to return HTML content where SSI output would be interpreted.")
    if not reasons:
        return None
    return build_candidate(url=url, method=str(endpoint.get("method", "GET")).upper(), parameter="", location="endpoint", score=score, reasons=reasons)


def candidate_from_parameter(parameter: dict[str, Any]) -> dict[str, Any] | None:
    name = str(parameter.get("name", "")).strip()
    url = normalize_surface_url(parameter.get("url", ""))
    if not name or not url:
        return None
    if is_candidate_noise_url(url):
        return None
    lower_name = name.lower()
    path = str(parameter.get("path", "") or urlsplit(url).path).lower()
    reasons = []
    score = 10
    if lower_name in SSI_PARAM_MARKERS or any(marker in lower_name for marker in SSI_PARAM_MARKERS):
        score += 35
        reasons.append("Parameter name suggests HTML, comment, template, include, or content rendering.")
    if any(marker in path for marker in SSI_PATH_MARKERS):
        score += 35
        reasons.append("Endpoint path suggests server-parsed SSI content.")
    if str(parameter.get("location", "")) in {"form", "body", "json"}:
        score += 10
        reasons.append("Parameter is submitted in a body/form context that may be rendered into HTML.")
    if not reasons:
        return None
    return build_candidate(url=url, method=str(parameter.get("method", "GET")).upper(), parameter=name, location=str(parameter.get("location", "query")), score=score, reasons=reasons)


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    value = observation_surface_url(observation)
    lower_text = json.dumps(observation, sort_keys=True).lower()
    if not value or not any(marker in lower_text for marker in ("html comment", "server-parsed", "ssi", "legacy apache", "legacy iis")):
        return None
    if is_candidate_noise_url(value):
        return None
    return build_candidate(
        url=value,
        method=str(observation.get("method", "GET")).upper(),
        parameter=str(observation.get("parameter", "")),
        location=str(observation.get("location", "unknown")),
        score=55,
        reasons=["Existing workspace observation suggests SSI-relevant HTML comment or server-parsed behavior."],
    )


def build_candidate(*, url: str, method: str, parameter: str, location: str, score: int, reasons: list[str]) -> dict[str, Any]:
    candidate_id = f"ssi_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    return {
        "candidateId": candidate_id[:160],
        "type": "ssi_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "priority": priority_for_score(score),
        "priorityScore": min(score, 100),
        "confidence": "medium" if score >= 70 else "low",
        "risk": "low",
        "tags": ["ssi", "server-side-includes"],
        "reasons": reasons,
        "testPlanSummary": "Use benign marker comments and safe SSI echo probes only after operator approval.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="ssi_candidate",
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            parameter=candidate["parameter"],
            location=candidate["location"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "SSI candidate identified.",
            tags=candidate.get("tags", []),
            metadata={
                "candidateId": candidate["candidateId"],
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="ssi",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} SSI candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "SSI is lower-confidence without response sink evidence.",
            "Active validation is limited to benign marker comments and safe echo probes.",
        ],
        metadata={"contextSummary": context_summary(context)},
    )


def plan_tests(args: dict[str, Any]) -> str:
    candidate = coerce_candidate(args, required_parameter=False)
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": candidate.get("parameter", ""),
        "location": candidate.get("location", "query"),
        "recommendedTests": [test.as_dict() for test in recommended_tests()],
        "safePayloads": safe_payloads(),
        "expectedSignals": [
            "Marker comment is reflected unchanged, indicating HTML sink behavior but not SSI execution.",
            "Safe SSI echo directive is removed or replaced by a server-side value.",
            "Server-side errors mention SSI, include directives, or server-parsed HTML.",
        ],
        "guardrails": [
            "Active tests require explicit operator approval and confirm=true.",
            "Do not use SSI exec, file include, command, or CGI directives.",
            "Treat marker reflection as sink evidence only, not confirmed SSI execution.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def prepare_replay(args: dict[str, Any]) -> str:
    replay = build_manual_replay(
        args,
        adapter="ssi",
        payloads=safe_payloads(),
        expected_signals=[
            "Marker comment is reflected unchanged, indicating HTML sink behavior but not SSI execution.",
            "Safe SSI echo directive is removed or replaced by a server-side value.",
            "Server-side errors mention SSI, include directives, or server-parsed HTML.",
        ],
        guardrails=[
            "Use only marker comments or the safe non-command SSI echo directive.",
            "Do not replay SSI exec, file include, command, or CGI directives.",
            "Treat marker reflection as sink evidence only, not confirmed SSI execution.",
        ],
    )
    return json.dumps(replay, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an SSI active test requires confirm=true.")
    candidate = coerce_candidate(args, required_parameter=False)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    if not parameter:
        raise McpError(-32602, "SSI active tests require a parameterized candidate.")
    payloads = [str(args["payload"])] if args.get("payload") else safe_payloads()
    allowed = set(safe_payloads())
    payloads = [payload for payload in payloads if payload in allowed][: int(args.get("maxPayloads", 2))]
    if not payloads:
        raise McpError(-32602, "SSI active tests only support built-in benign payloads.")
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    tests = []
    possible = False
    marker_reflected = False
    with http_client.session(policy) as session:
        for payload in payloads:
            built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
            response_payload = session.send(
                HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            ).as_dict()
            body = response_payload.get("body", "")
            reflected = payload in body
            executed_echo = payload.startswith("<!--#echo") and payload not in body and bool(body)
            possible = possible or executed_echo
            marker_reflected = marker_reflected or reflected
            exchange_evidence = store_http_exchange_evidence(
                workspace_id,
                scope_result["host"],
                "ssi_http_exchange",
                request={key: value for key, value in built.items() if not key.startswith("_")},
                response=response_payload,
                metadata={
                    "adapter": "ssi",
                    "target": target_url,
                    "parameter": parameter,
                    "payload": payload,
                    "approval": approval,
                },
            )
            tests.append(
                {
                    "request": {key: value for key, value in built.items() if key != "headers" and not key.startswith("_")},
                    "requestHeaders": redact_headers(built["headers"]),
                    "payload": payload,
                    "response": response_summary(response_payload),
                    "exchangeEvidence": exchange_evidence,
                    "markerReflected": reflected,
                    "safeEchoPossiblyExecuted": executed_echo,
                }
            )
    # An unreflected echo directive only indicates SSI execution when the benign
    # marker comment was reflected (proving the parameter reaches an HTML sink);
    # otherwise "not reflected" just means the input was never rendered at all.
    assessment = "possible_ssi" if (possible and marker_reflected) else ("html_sink_observed" if marker_reflected else "inconclusive")
    raw = {"candidate": candidate, "tests": tests, "assessment": assessment, "approval": approval}
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "ssi_test",
        "active_validation",
        "json",
        json.dumps(raw, indent=2, ensure_ascii=False),
        {"approval": approval, "target": target_url, "host": scope_result["host"], "parameter": parameter},
    )
    action = workspace.record_action(
        workspace_id,
        scope_result["host"],
        {
            "type": "active_validation",
            "tool": "ssi.execute_test",
            "target": target_url,
            "method": method,
            "parameter": parameter,
            "location": location,
            "assessment": raw["assessment"],
            "exchangeEvidenceIds": [item["exchangeEvidence"]["evidenceId"] for item in tests if item.get("exchangeEvidence")],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "ssi.execute_test",
        f"Ran approved benign SSI test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": raw["assessment"], "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="html_comment_marker_reflection",
            description="Check whether a harmless HTML comment marker reaches an HTML sink.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
        ),
        RecommendedTest(
            name="safe_ssi_echo_probe",
            description="Use a non-command SSI echo directive to detect server-side parsing without file or command access.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
        ),
    ]


def safe_payloads() -> list[str]:
    return ["<!-- synapse-ssi-marker -->", '<!--#echo var="DATE_LOCAL" -->']


def context_summary(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
        "parameterCount": context.get("parameters", {}).get("total", 0),
        "candidateFindingCount": len(context.get("candidateFindings", [])),
    }
