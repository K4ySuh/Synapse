# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, surface_candidate
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import (
    build_http_request,
    build_manual_replay,
    coerce_candidate,
    priority_for_score,
    record_surface_test_validation,
    redact_headers,
    response_summary,
    stable_slug,
    store_http_exchange_evidence,
)
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url


TEMPLATE_PARAM_MARKERS = {
    "template",
    "tpl",
    "view",
    "preview",
    "render",
    "message",
    "body",
    "content",
    "email",
    "email_body",
    "subject",
    "name",
    "title",
    "description",
    "markdown",
    "html",
}
TEMPLATE_PATH_MARKERS = ("template", "preview", "render", "view", "email", "markdown", "html", "cms", "page")
USER_PARAMETER_LOCATIONS = {"query", "body", "form", "path"}
# Distinctive template-engine error/identity fingerprints used to corroborate an
# SSTI verdict from a response. Bare engine words such as "template", "velocity",
# or "liquid" are deliberately excluded: they appear in ordinary page copy and
# would mark benign pages as possible SSTI. Only signatures that strongly imply a
# template engine raised or rendered an error are treated as a signal.
TEMPLATE_ERROR_SIGNATURES = (
    "jinja2",
    "templatesyntaxerror",
    "templatenotfound",
    "could not parse the remainder",
    "twig\\error",
    "twig_error",
    "freemarker.core",
    "org.apache.velocity",
    "velocityexception",
    "smarty_compiler",
    "nunjucks",
    "mako.exceptions",
    "handlebars.js",
)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("ssti"), indent=2)


def passive_analyze(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 25))
    min_score = int(args.get("minScore", 35))
    context = workspace.prepare_target_context(workspace_id, target, purpose="ssti_candidate_analysis", max_tokens=4000)
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
            {"adapter": "ssti", "minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "ssti.passive_analyze",
        f"Analyzed SSTI candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    endpoints_by_url = {item.get("url"): item for item in entities.get("endpoints", []) if isinstance(item, dict)}
    candidates: dict[str, dict[str, Any]] = {}
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        candidate = candidate_from_parameter(parameter, endpoints_by_url.get(parameter.get("url")))
        if candidate and candidate["priorityScore"] >= min_score:
            candidates[candidate["candidateId"]] = candidate
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        candidate = candidate_from_observation(observation)
        if candidate and candidate["priorityScore"] >= min_score:
            candidates.setdefault(candidate["candidateId"], candidate)
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def candidate_from_parameter(parameter: dict[str, Any], endpoint: dict[str, Any] | None) -> dict[str, Any] | None:
    name = str(parameter.get("name", "")).strip()
    url = normalize_surface_url(parameter.get("url", ""))
    if not name or not url:
        return None
    if is_candidate_noise_url(url):
        return None
    method = str(parameter.get("method", "") or (endpoint or {}).get("method", "GET")).upper()
    location = str(parameter.get("location", "query"))
    if location not in USER_PARAMETER_LOCATIONS:
        return None
    path = str(parameter.get("path", "") or urlsplit(url).path).lower()
    lower_name = name.lower()
    score = 10
    reasons = []
    if lower_name in TEMPLATE_PARAM_MARKERS or any(marker in lower_name for marker in TEMPLATE_PARAM_MARKERS):
        score += 45
        reasons.append("Parameter name suggests server-side template rendering surface.")
    if any(marker in path for marker in TEMPLATE_PATH_MARKERS):
        score += 25
        reasons.append("Endpoint path suggests rendering, preview, page, CMS, markdown, or template behavior.")
    if location in {"form", "body", "json"}:
        score += 10
        reasons.append("Parameter is submitted in a body/form context where server-side rendering is more likely.")
    value_preview = str(parameter.get("value", "") or parameter.get("valuePreview", ""))
    if any(marker in value_preview.lower() for marker in ("{{", "${", "<%=", "{%", "#{")):
        score += 30
        reasons.append("Observed value already resembles template syntax.")
    if not reasons:
        return None
    return build_candidate(url=url, method=method, parameter=name, location=location, score=min(score, 100), reasons=reasons, source="parameter")


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    value = observation_surface_url(observation)
    if not value:
        return None
    if is_candidate_noise_url(value):
        return None
    lower_text = json.dumps(observation, sort_keys=True).lower()
    if not any(marker in lower_text for marker in ("reflection", "reflected")):
        return None
    score = 55
    reasons = ["Existing workspace observation suggests reflection or rendering behavior."]
    parameter = str(observation.get("parameter", ""))
    return build_candidate(
        url=value,
        method=str(observation.get("method", "GET")).upper(),
        parameter=parameter,
        location=str(observation.get("location", "unknown")),
        score=score,
        reasons=reasons,
        source="observation",
    )


def build_candidate(*, url: str, method: str, parameter: str, location: str, score: int, reasons: list[str], source: str) -> dict[str, Any]:
    candidate_id = f"ssti_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    return {
        "candidateId": candidate_id[:160],
        "type": "ssti_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "source": source,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "risk": "medium" if score >= 70 else "low",
        "tags": ["ssti", "template-parameter"],
        "reasons": reasons,
        "testPlanSummary": "Use benign arithmetic and syntax-differential probes only after operator approval.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        surface_candidate(
            vuln_class="ssti",
            url=candidate["url"],
            method=candidate["method"],
            parameter=candidate["parameter"],
            location=candidate["location"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "SSTI candidate identified.",
            tags=candidate.get("tags", []),
            test_plan_summary=candidate.get("testPlanSummary", ""),
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="ssti",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} SSTI candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis identifies candidate rendering surfaces only.",
            "Active validation is limited to benign arithmetic and syntax-differential probes.",
        ],
        metadata={"contextSummary": context_summary(context)},
    )


def plan_tests(args: dict[str, Any]) -> str:
    candidate = coerce_candidate(args)
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": candidate.get("parameter", ""),
        "location": candidate.get("location", "query"),
        "recommendedTests": [test.as_dict() for test in recommended_tests()],
        "safePayloads": ssti_payloads(),
        "expectedSignals": [
            "The arithmetic expression is evaluated to 49 instead of returned literally.",
            "Different template syntaxes produce measurably different reflected output or server-side errors.",
            "A response error mentions template parsing, expression evaluation, or a template engine.",
        ],
        "guardrails": [
            "Active tests require explicit operator approval and confirm=true.",
            "Use only benign arithmetic or syntax-differential probes.",
            "Do not attempt file reads, environment access, object traversal, network callbacks, or code execution.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def prepare_replay(args: dict[str, Any]) -> str:
    replay = build_manual_replay(
        args,
        adapter="ssti",
        payloads=ssti_payloads(),
        expected_signals=[
            "The arithmetic expression is evaluated to 49 instead of returned literally.",
            "Different template syntaxes produce measurably different reflected output or server-side errors.",
            "A response error mentions template parsing, expression evaluation, or a template engine.",
        ],
        guardrails=[
            "Use only benign arithmetic or syntax-differential probes.",
            "Do not replay file reads, environment access, object traversal, network callbacks, or code execution.",
        ],
    )
    return json.dumps(replay, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an SSTI active test requires confirm=true.")
    candidate = coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    payloads = [str(args["payload"])] if args.get("payload") else ssti_payloads()
    payloads = [payload for payload in payloads if payload in ssti_payloads()][: int(args.get("maxPayloads", 3))]
    if not payloads:
        raise McpError(-32602, "SSTI active tests only support built-in benign payloads.")
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    tests = []
    possible = False
    with http_client.session(policy) as session:
        for payload in payloads:
            built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
            response_payload = session.send(
                HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            ).as_dict()
            body = response_payload.get("body", "")
            evaluated = "49" in body and payload not in body
            error_signal = template_error_signal(body)
            possible = possible or evaluated or error_signal
            exchange_evidence = store_http_exchange_evidence(
                workspace_id,
                scope_result["host"],
                "ssti_http_exchange",
                request={key: value for key, value in built.items() if not key.startswith("_")},
                response=response_payload,
                metadata={
                    "adapter": "ssti",
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
                    "evaluatedArithmetic": evaluated,
                    "templateErrorSignal": error_signal,
                }
            )
    raw = {
        "candidate": candidate,
        "tests": tests,
        "assessment": "possible_ssti" if possible else "inconclusive",
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "ssti_test",
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
            "tool": "ssti.execute_test",
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
    validation = record_surface_test_validation(
        workspace_id,
        scope_result["host"],
        vuln_class="ssti",
        url=target_url,
        method=method,
        parameter=parameter,
        location=location,
        interesting=possible,
        evidence_ids=[item["exchangeEvidence"]["evidenceId"] for item in tests if item.get("exchangeEvidence")],
    )
    evidence.log_event(
        "ssti.execute_test",
        f"Ran approved benign SSTI test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": raw["assessment"], "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action, "validation": validation}, indent=2)


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="arithmetic_expression_reflection_probe",
            description="Inject benign arithmetic template expressions and compare whether output is evaluated.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="Use arithmetic expressions that should evaluate to 49 if a template engine executes them.",
        ),
        RecommendedTest(
            name="template_syntax_differential_probe",
            description="Compare response behavior across common template syntaxes without accessing files or objects.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
        ),
    ]


def template_error_signal(body: str) -> bool:
    """Return True only when a response carries a distinctive template-engine
    error/identity fingerprint. Bare engine words (``template``, ``velocity``,
    ``liquid``) are intentionally not signals: they occur in ordinary page copy
    and would otherwise mark benign responses as possible SSTI."""
    lowered = str(body).lower()
    return any(marker in lowered for marker in TEMPLATE_ERROR_SIGNATURES)


def ssti_payloads() -> list[str]:
    return ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]


def context_summary(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
        "parameterCount": context.get("parameters", {}).get("total", 0),
        "candidateFindingCount": len(context.get("candidateFindings", [])),
    }
