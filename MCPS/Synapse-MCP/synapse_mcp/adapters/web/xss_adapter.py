# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import html
import json
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import priority_for_score, redact_value_preview, stable_slug
from .active_probe import build_http_request, coerce_candidate, redact_headers, response_summary, store_http_exchange_evidence
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url
from . import xss_analysis


XSS_NAME_HINTS = ("q", "query", "search", "term", "keyword", "name", "message", "comment", "review", "title", "text", "html", "url", "redirect", "return", "callback", "next")
XSS_PATH_HINTS = ("search", "profile", "comment", "review", "contact", "feedback", "message", "support", "account", "login", "redirect")
TEXTUAL_CONTENT_HINTS = ("text/html", "application/xhtml", "application/json", "text/xml", "application/xml")


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("xss"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = str(args["workspaceId"])
    target = str(args["target"])
    max_candidates = int(args.get("maxCandidates", 50))
    min_score = int(args.get("minScore", 55))
    context = workspace.prepare_target_context(workspace_id, target, purpose="xss_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_workspace_candidates(entities, target=target, min_score=min_score)[:max_candidates]
    result = build_workspace_adapter_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": context.get("parameters", {}).get("total", 0),
        },
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
            {"adapter": "xss", "maxCandidates": max_candidates, "minScore": min_score},
        )
    evidence.log_event(
        "xss.analyze_workspace",
        f"Analyzed workspace parameters for XSS candidates on {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def analyze_dump(args: dict[str, Any]) -> str:
    result = json.loads(
        xss_analysis.analyze_burp_dump(
            {
                "dumpPath": args["dumpPath"],
                "onlyInteresting": args.get("onlyInteresting", True),
                "maxFindingsPerResponse": args.get("maxFindingsPerResponse", 12),
                "includeTestCode": args.get("includeTestCode", True),
            }
        )
    )
    ingestion = None
    if args.get("ingest", False):
        workspace_id = args.get("workspaceId")
        target = args.get("target")
        if not workspace_id or not target:
            raise McpError(-32602, "workspaceId and target are required when ingest=true.")
        adapter_result = build_adapter_result(str(workspace_id), str(target), result)
        ingestion = workspace.ingest_data(
            str(workspace_id),
            str(target),
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps({**adapter_result.as_ingest_payload(), "analysis": result}, indent=2, ensure_ascii=False),
            {"adapter": "xss", "dumpPath": args["dumpPath"]},
        )
    if ingestion:
        result["ingestion"] = ingestion
    return json.dumps(result, indent=2)


def generate_test_code(args: dict[str, Any]) -> str:
    return xss_analysis.generate_test_code(args)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an XSS active reflection test requires confirm=true.")
    candidate = resolve_execute_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    marker = xss_marker(args.get("marker") or candidate.get("candidateId") or parameter or "xss")
    allowed = xss_payloads(marker)
    payloads = [str(args["payload"])] if args.get("payload") else allowed[: int(args.get("maxPayloads", 2))]
    payloads = [payload for payload in payloads if payload in allowed]
    if not payloads:
        raise McpError(-32602, "XSS active tests only support built-in benign marker payloads.")
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    tests = []
    raw_tag_reflected = False
    marker_reflected = False
    encoded_reflected = False
    with http_client.session(policy) as session:
        for payload in payloads:
            built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
            response_payload = session.send(
                HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            ).as_dict()
            body = str(response_payload.get("body", "") or "")
            reflected_payload = payload in body
            reflected_marker = marker in body
            reflected_encoded = html.escape(payload, quote=True) in body
            raw_tag_reflected = raw_tag_reflected or (reflected_payload and "<synapse-xss" in payload)
            marker_reflected = marker_reflected or reflected_marker
            encoded_reflected = encoded_reflected or reflected_encoded
            exchange_evidence = store_http_exchange_evidence(
                workspace_id,
                scope_result["host"],
                "xss_http_exchange",
                request={key: value for key, value in built.items() if not key.startswith("_")},
                response=response_payload,
                metadata={
                    "adapter": "xss",
                    "target": target_url,
                    "parameter": parameter,
                    "payload": payload,
                    "marker": marker,
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
                    "rawPayloadReflected": reflected_payload,
                    "markerReflected": reflected_marker,
                    "encodedPayloadReflected": reflected_encoded,
                }
            )
    if raw_tag_reflected:
        assessment = "possible_xss"
    elif marker_reflected:
        assessment = "reflection_observed"
    elif encoded_reflected:
        assessment = "encoded_reflection_observed"
    else:
        assessment = "inconclusive"
    raw = {
        "candidate": candidate,
        "tests": tests,
        "marker": marker,
        "assessment": assessment,
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "xss_test",
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
            "tool": "xss.execute_test",
            "target": target_url,
            "method": method,
            "parameter": parameter,
            "location": location,
            "assessment": assessment,
            "exchangeEvidenceIds": [item["exchangeEvidence"]["evidenceId"] for item in tests if item.get("exchangeEvidence")],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "xss.execute_test",
        f"Ran approved benign XSS reflection test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def resolve_execute_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    if args.get("candidateId") and not args.get("url"):
        workspace_id = str(args.get("workspaceId") or workspace.default_workspace_id())
        target = str(args.get("target") or "")
        if target:
            entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
            for observation in entities.get("observations", []):
                if not isinstance(observation, dict):
                    continue
                if observation.get("type") != "xss_candidate" or observation.get("candidateId") != args.get("candidateId"):
                    continue
                return {
                    "candidateId": observation.get("candidateId", ""),
                    "url": observation.get("url") or _url_from_value(observation.get("value", "")),
                    "method": observation.get("method", "GET"),
                    "parameter": observation.get("parameter", ""),
                    "location": observation.get("location", "query"),
                    "reasons": observation.get("reasons", []),
                }
        raise McpError(-32602, f"XSS candidate not found: {args.get('candidateId')}")
    return coerce_candidate(args)


def _url_from_value(value: Any) -> str:
    for part in str(value or "").split():
        if part.startswith(("http://", "https://")):
            return part
    return ""


def xss_marker(value: Any) -> str:
    slug = stable_slug(value).replace("-", "_").replace(".", "_").upper()
    return f"SYNAPSE_XSS_{slug}"[:80]


def xss_payloads(marker: str) -> list[str]:
    return [
        f'"><synapse-xss data-token="{marker}"></synapse-xss>',
        marker,
    ]


def find_workspace_candidates(entities: dict[str, list[dict[str, Any]]], *, target: str = "", min_score: int = 55) -> list[dict[str, Any]]:
    endpoints = [item for item in entities.get("endpoints", []) if isinstance(item, dict)]
    endpoint_by_url = {str(item.get("url", "")): item for item in endpoints if str(item.get("url", "")).strip()}
    allowed_hosts = allowed_target_hosts(target)
    candidates: dict[str, dict[str, Any]] = {}
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name", "") or "").strip()
        url = normalize_surface_url(parameter.get("url", ""))
        if not name or not url:
            continue
        if is_candidate_noise_url(url):
            continue
        if allowed_hosts and not url_matches_target_host(url, allowed_hosts):
            continue
        endpoint = endpoint_by_url.get(url, {})
        score, reasons = score_workspace_parameter(parameter, endpoint)
        if score < min_score:
            continue
        candidate_id = "xss_" + stable_slug(f"{url}|{parameter.get('method', '')}|{parameter.get('location', '')}|{name}")
        candidates.setdefault(
            candidate_id,
            {
                "candidateId": candidate_id,
                "type": "xss_candidate",
                "url": url,
                "method": str(parameter.get("method") or endpoint.get("method") or "GET").upper(),
                "parameter": name,
                "location": str(parameter.get("location") or "query"),
                "path": str(parameter.get("path") or endpoint.get("path") or urlsplit(url).path or "/"),
                "priority": priority_for_score(score),
                "confidence": "medium" if score >= 75 else "low",
                "priorityScore": score,
                "reason": "; ".join(reasons) or "Workspace parameter is a candidate XSS input.",
                "valuePreview": redact_value_preview(name, str(parameter.get("valuePreview", "") or "")),
                "tags": ["xss", "workspace-candidate"],
            },
        )
    return sorted(candidates.values(), key=lambda item: int(item.get("priorityScore", 0) or 0), reverse=True)


def allowed_target_hosts(target: str) -> set[str]:
    hosts = {workspace.normalize_target(target)}
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    if parsed.hostname:
        hosts.add(parsed.hostname.lower())
    return {host for host in hosts if host}


def url_matches_target_host(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    if not parsed.hostname:
        return url.startswith("/")
    return parsed.hostname.lower() in allowed_hosts


def score_workspace_parameter(parameter: dict[str, Any], endpoint: dict[str, Any]) -> tuple[int, list[str]]:
    score = 30
    reasons = ["User-controllable workspace parameter observed."]
    name = str(parameter.get("name", "") or "").lower()
    location = str(parameter.get("location", "") or "query").lower()
    method = str(parameter.get("method") or endpoint.get("method") or "GET").upper()
    path = str(parameter.get("path") or endpoint.get("path") or "").lower()
    if location in {"query", "body", "json", "form"}:
        score += 20
        reasons.append(f"Parameter is in {location} input.")
    if any(hint in name for hint in XSS_NAME_HINTS):
        score += 20
        reasons.append("Parameter name is commonly reflected or rendered.")
    content_types = endpoint.get("contentTypes", []) if isinstance(endpoint.get("contentTypes"), list) else []
    if any(any(hint in str(content_type).lower() for hint in TEXTUAL_CONTENT_HINTS) for content_type in content_types):
        score += 15
        reasons.append("Endpoint has textual response content type.")
    if any(hint in path for hint in XSS_PATH_HINTS):
        score += 10
        reasons.append("Endpoint path is commonly user-facing or reflective.")
    if method in {"POST", "PUT", "PATCH"}:
        score += 10
        reasons.append("State-changing method may render submitted content.")
    return min(score, 100), reasons


def build_workspace_adapter_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="xss_candidate",
            value=f"{candidate['method']} {candidate['url']}",
            url=str(candidate.get("url", "")),
            method=str(candidate.get("method", "")),
            parameter=str(candidate.get("parameter", "")),
            location=str(candidate.get("location", "")),
            confidence=str(candidate.get("confidence", "low")),
            priority=str(candidate.get("priority", "low")),
            priority_score=int(candidate.get("priorityScore", 0) or 0),
            reason=str(candidate.get("reason", "Workspace parameter is a candidate XSS input.")),
            tags=["xss", "workspace-candidate"],
            metadata={
                "candidateId": candidate.get("candidateId", ""),
                "path": candidate.get("path", ""),
                "valuePreview": candidate.get("valuePreview", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="xss",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(observations)} XSS candidate parameters from workspace data.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Workspace XSS analysis is passive and does not replay browser payloads.",
            "Candidates require operator review and approved validation before promotion.",
        ],
        metadata={
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": context.get("parameters", {}).get("total", 0),
        },
    )


def build_adapter_result(workspace_id: str, target: str, analysis: dict[str, Any]) -> AdapterResult:
    observations = []
    for item in analysis.get("results", []):
        if not isinstance(item, dict):
            continue
        method = str(item.get("requestLine", "")).split(" ", 1)[0].upper() or "GET"
        request_line = str(item.get("requestLine", ""))
        for candidate in item.get("injectionCandidates", []):
            if not isinstance(candidate, dict):
                continue
            score = int(candidate.get("score", 0) or 0)
            observations.append(
                candidate_observation(
                    candidate_type="xss_candidate",
                    value=request_line,
                    method=method,
                    parameter=str(candidate.get("name", "")),
                    location=str(candidate.get("location", "")),
                    confidence="medium" if score >= 75 else "low",
                    priority="high" if score >= 85 else ("medium" if score >= 60 else "low"),
                    priority_score=score,
                    reason=str(candidate.get("reason", "XSS candidate identified from offline request and response analysis.")),
                    tags=["xss", "manual-test-candidate"],
                    metadata={
                        "candidateId": f"xss_{item.get('id')}_{candidate.get('location', '')}_{candidate.get('name', '')}",
                        "historyId": item.get("id"),
                        "host": item.get("host", ""),
                        "requestFile": item.get("requestFile", ""),
                        "responseFile": item.get("responseFile", ""),
                        "requestLine": request_line,
                        "likelyContext": candidate.get("likelyContext", "unknown"),
                        "valuePreview": candidate.get("valuePreview", ""),
                    },
                )
            )
        for reflection in item.get("reflections", []):
            if not isinstance(reflection, dict):
                continue
            observations.append(
                candidate_observation(
                    candidate_type="xss_reflection",
                    value=request_line,
                    method=method,
                    parameter=str(reflection.get("name", "")),
                    location=str(reflection.get("location", "")),
                    confidence="medium",
                    priority="high" if reflection.get("risk") == "high" else "medium",
                    priority_score=80 if reflection.get("risk") == "high" else 65,
                    reason=f"Parameter value is reflected in {reflection.get('context', 'unknown')} context.",
                    tags=["xss", "reflection"],
                    metadata={
                        "historyId": item.get("id"),
                        "requestFile": item.get("requestFile", ""),
                        "responseFile": item.get("responseFile", ""),
                        "context": reflection.get("context", "unknown"),
                        "valuePreview": reflection.get("valuePreview", ""),
                    },
                )
            )
        for sink in item.get("htmlSinks", []):
            if not isinstance(sink, dict):
                continue
            observations.append(
                candidate_observation(
                    candidate_type="xss_sink",
                    value=request_line,
                    method=method,
                    confidence="low",
                    priority="high" if sink.get("risk") == "high" else "medium",
                    priority_score=75 if sink.get("risk") == "high" else 55,
                    reason=f"HTML parser identified a {sink.get('type', 'sink')} sink in the response.",
                    tags=["xss", "html-sink"],
                    metadata={
                        "historyId": item.get("id"),
                        "requestFile": item.get("requestFile", ""),
                        "responseFile": item.get("responseFile", ""),
                        "sink": sink,
                    },
                )
            )
    return AdapterResult(
        adapter="xss",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(observations)} XSS-relevant observations from offline dump analysis.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "XSS dump analysis is passive and does not replay browser payloads.",
            "Generated helpers are for manual operator testing only.",
        ],
        metadata={
            "dumpDir": analysis.get("dumpDir", ""),
            "analyzedRequests": analysis.get("analyzedRequests", 0),
            "aggregateTechnologies": analysis.get("aggregateTechnologies", []),
            "aggregatePossibleBackends": analysis.get("aggregatePossibleBackends", []),
        },
    )
