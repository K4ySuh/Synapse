# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from ...core import credentials, evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import redact_headers, response_summary, stable_slug, store_http_exchange_evidence
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url

XML_CONTENT_TYPES = {"application/xml", "text/xml", "application/soap+xml", "image/svg+xml"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("xxe"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 50))
    context = workspace.prepare_target_context(workspace_id, target, purpose="xxe_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": len(entities.get("parameters", [])),
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
            {"adapter": "xxe", "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "xxe.analyze_workspace",
        f"Analyzed XXE candidates for {workspace.normalize_target(target)}.",
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
    endpoints = [endpoint for endpoint in entities.get("endpoints", []) if isinstance(endpoint, dict)]
    endpoint_index = {(str(endpoint.get("method", "GET")).upper(), str(endpoint.get("url", ""))): endpoint for endpoint in endpoints}

    for endpoint in endpoints:
        signal = _endpoint_xml_signal(endpoint)
        if not signal:
            continue
        candidate = _build_candidate(endpoint, signal)
        candidates.setdefault(candidate["candidateId"], candidate)

    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        signal = _parameter_xml_signal(parameter)
        if not signal:
            continue
        method = str(parameter.get("method", "GET")).upper()
        url = normalize_surface_url(parameter.get("url", ""))
        if not url or is_candidate_noise_url(url):
            continue
        endpoint = endpoint_index.get((method, url), {"url": url, "method": method, "path": urlsplit(url).path or "/"})
        candidate = _build_candidate(endpoint, signal)
        candidates.setdefault(candidate["candidateId"], candidate)

    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        signal = _observation_soap_signal(observation)
        if not signal:
            continue
        url = observation_surface_url(observation)
        if not url or is_candidate_noise_url(url):
            continue
        method = str(observation.get("method", "GET")).upper()
        endpoint = endpoint_index.get((method, url), {"url": url, "method": method, "path": urlsplit(url).path or "/"})
        candidate = _build_candidate(endpoint, signal)
        candidates.setdefault(candidate["candidateId"], candidate)

    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def _endpoint_xml_signal(endpoint: dict[str, Any]) -> str:
    for content_type in endpoint.get("requestContentTypes", []) if isinstance(endpoint.get("requestContentTypes"), list) else []:
        if _is_xml_content_type(str(content_type)):
            return f"Endpoint documents an {content_type} request body."
    path = str(endpoint.get("path", "") or urlsplit(str(endpoint.get("url", ""))).path).lower()
    url = str(endpoint.get("url", "")).lower()
    if path.endswith(".wsdl") or url.endswith("?wsdl") or "?wsdl" in url:
        return "Endpoint path indicates a SOAP/WSDL surface."
    tags = endpoint.get("tags", []) if isinstance(endpoint.get("tags"), list) else []
    if any(str(tag).lower() in {"soap", "wsdl"} for tag in tags):
        return "Endpoint metadata marks this surface as SOAP/WSDL."
    return ""


def _parameter_xml_signal(parameter: dict[str, Any]) -> str:
    location = str(parameter.get("location", "")).lower()
    preview = str(parameter.get("valuePreview", "") or parameter.get("value", "")).lstrip()
    if location in {"body", "xml"} and _looks_like_xml(preview):
        return "Body parameter preview begins with XML-like markup."
    return ""


def _observation_soap_signal(observation: dict[str, Any]) -> str:
    obs_type = str(observation.get("type", "")).lower()
    value = str(observation.get("value", ""))
    lowered = value.lower()
    if lowered.endswith(".wsdl") or lowered.endswith("?wsdl") or "?wsdl" in lowered:
        return "Observation indicates a SOAP/WSDL endpoint."
    if obs_type == "documented_auth_scheme" and str(observation.get("schemeType", "")).lower() == "soap":
        return "Specification metadata marks this API as SOAP."
    tags = observation.get("tags", []) if isinstance(observation.get("tags"), list) else []
    if any(str(tag).lower() in {"soap", "wsdl"} for tag in tags):
        return "Observation metadata marks this surface as SOAP/WSDL."
    return ""


def _is_xml_content_type(content_type: str) -> bool:
    lowered = content_type.split(";", 1)[0].strip().lower()
    return lowered in XML_CONTENT_TYPES or bool(re.match(r"^application/.*\+xml$", lowered))


def _looks_like_xml(value: str) -> bool:
    return value.startswith("<?xml") or bool(re.match(r"^<[A-Za-z_][\w:.-]*(?:\s|>|/>)", value))


def _build_candidate(endpoint: dict[str, Any], signal: str) -> dict[str, Any]:
    url = str(endpoint.get("url", ""))
    method = str(endpoint.get("method", "GET")).upper()
    high = method in STATE_CHANGING_METHODS and _unauthenticated_reachable(endpoint)
    score = 82 if high else 60
    priority = "high" if high else "medium"
    return {
        "candidateId": f"xxe_{stable_slug(method)}_{stable_slug(url)}"[:170],
        "type": "xxe_candidate",
        "url": url,
        "method": method,
        "priority": priority,
        "priorityScore": score,
        "confidence": "medium" if high else "low",
        "reasons": [signal],
        "testPlanSummary": "Manual validation only: use benign non-resolving XML entity checks after explicit approval and scope review.",
    }


def _unauthenticated_reachable(endpoint: dict[str, Any]) -> bool:
    if endpoint.get("hasAuthorization") or endpoint.get("authBoundary"):
        return False
    schemes = endpoint.get("authorizationSchemes")
    return not isinstance(schemes, list) or not schemes


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="xxe_candidate",
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "XML-accepting endpoint identified.",
            tags=["xxe", "xml-input"],
            metadata={
                "candidateId": candidate["candidateId"],
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="xxe",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} XML parser candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Candidate-only; accepting XML is not proof the parser resolves external entities.",
            "Active XXE validation is limited to benign in-band entity expansion checks after operator approval.",
        ],
        metadata={"observationCount": len(observations), "contextEndpointCount": context.get("knownEndpoints", {}).get("total", 0)},
    )


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = args.get("candidate")
    if not isinstance(candidate, dict):
        if "url" not in args:
            raise McpError(-32602, "Provide a candidate object or a url (with optional method).")
        candidate = {"url": args["url"], "method": args.get("method", "POST"), "reasons": args.get("reasons", [])}
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": str(candidate.get("method", "POST")).upper(),
        "sendsTraffic": False,
        "manualReproductionOutline": [
            "Prepare a benign XML body containing a non-resolving external entity reference controlled by the operator.",
            "Prepare an in-band echo check that references an entity value and confirms only parser behavior, not data theft.",
            "Compare the response with a baseline XML request and record only the parser signal and response metadata.",
        ],
        "expectedSignals": [
            "The server returns parser errors or echo behavior indicating entity processing.",
            "The server does not need to disclose local files or contact internal systems to validate parser behavior.",
        ],
        "guardrails": [
            "This helper produces a manual outline only; it does not send traffic.",
            "Run any active XML entity test only after explicit operator approval and exact target scope validation.",
            "Use benign non-resolving or operator-controlled OOB identifiers only.",
            "Do not attempt internal file disclosure, internal SSRF, network pivoting, or destructive parser behavior.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an XXE active entity expansion test requires confirm=true.")
    candidate = _coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    if not target_url:
        raise McpError(-32602, "A target url is required.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(args.get("method") or candidate.get("method") or "POST").upper()
    if method in {"GET", "HEAD"}:
        raise McpError(-32602, "XXE active tests require a body-capable method such as POST, PUT, or PATCH.")
    marker = xxe_marker(args.get("marker") or candidate.get("candidateId") or target_url)
    payload = str(args.get("payload") or benign_entity_payload(marker))
    if payload != benign_entity_payload(marker):
        raise McpError(-32602, "XXE active tests only support the built-in benign in-band entity payload.")
    headers = {"User-Agent": "Synapse-MCP/0.1", "Content-Type": "application/xml", "Accept": "*/*"}
    if args.get("credentialId"):
        credential = credentials.credential_for_target(str(args["credentialId"]), target_url)
        headers.update(credentials.headers_for_credential_target(credential, target_url))
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    response_payload = http_client.send(
        HttpRequest(url=target_url, method=method, headers=headers, body=payload.encode("utf-8")),
        policy=policy,
    ).as_dict()
    assessment = assess_xxe_response(response_payload, marker)
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "xxe_http_exchange",
        request={"url": target_url, "method": method, "headers": headers, "body": payload},
        response=response_payload,
        metadata={"adapter": "xxe", "target": target_url, "marker": marker, "approval": approval},
    )
    raw = {
        "candidate": candidate,
        "request": {"url": target_url, "method": method},
        "requestHeaders": redact_headers(headers),
        "marker": marker,
        "response": response_summary(response_payload),
        "exchangeEvidence": exchange_evidence,
        "assessment": assessment,
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "xxe_test",
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
            "tool": "xxe.execute_test",
            "target": target_url,
            "method": method,
            "assessment": assessment,
            "exchangeEvidenceId": exchange_evidence.get("evidenceId", ""),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "xxe.execute_test",
        f"Ran approved benign XXE entity expansion test against {scope_result['host']}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def _coerce_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    if "url" not in args:
        raise McpError(-32602, "Provide a candidate object or a url (with optional method).")
    return {"candidateId": args.get("candidateId", ""), "url": args["url"], "method": args.get("method", "POST"), "reasons": args.get("reasons", [])}


def xxe_marker(value: Any) -> str:
    slug = stable_slug(value).replace("-", "_").replace(".", "_").upper()
    return f"SYNAPSE_XXE_{slug}"[:80]


def benign_entity_payload(marker: str) -> str:
    return f'<?xml version="1.0"?><!DOCTYPE synapse [<!ENTITY synapse "{marker}">]><synapse>&synapse;</synapse>'


def assess_xxe_response(response_payload: dict[str, Any], marker: str) -> str:
    body = str(response_payload.get("body", "") or "")
    lowered = body.lower()
    if marker in body and "&synapse;" not in body:
        return "xml_entity_expansion_observed"
    if any(signal in lowered for signal in ("doctype", "entity", "external entity", "dtd", "xml parser", "saxparse", "xmlexception")):
        return "xml_parser_signal"
    return "inconclusive"
