# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ...core import evidence, workspace
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import build_http_request, coerce_candidate, redact_headers, response_summary, stable_slug, store_http_exchange_evidence
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url


REDIRECT_PARAM_MARKERS = {
    "next",
    "return",
    "return_url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "continue",
    "continue_url",
    "destination",
    "dest",
    "url",
    "uri",
    "target",
    "to",
    "callback",
    "relaystate",
    "goto",
    "forward",
}
REDIRECT_PATH_MARKERS = (
    "redirect",
    "return",
    "continue",
    "callback",
    "url",
)
STRICT_REDIRECT_MARKERS = ("redirect", "return", "url", "continue", "callback")
ABSOLUTE_URL_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 25))
    min_score = int(args.get("minScore", 35))
    context = workspace.prepare_target_context(workspace_id, target, purpose="open_redirect_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities, min_score)[:max_candidates]
    payload = {
        "workspaceId": workspace.normalize_workspace_id(workspace_id),
        "target": workspace.normalize_target(target),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": context.get("parameters", {}).get("total", 0),
            "interestingCandidateCount": len(context.get("interestingCandidates", [])),
        },
    }
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            "open_redirect_analysis",
            "candidate_analysis",
            "json",
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "open_redirect.analyze_workspace",
        f"Analyzed open redirect candidates for {workspace.normalize_target(target)}.",
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
    path = urlsplit(url).path.lower()
    lower_name = name.lower()
    value_preview = str(parameter.get("value", "") or parameter.get("valuePreview", ""))
    score = 10
    reasons = []
    has_redirect_signal = False
    if _has_redirect_signal(lower_name):
        has_redirect_signal = True
        score += 45
        reasons.append("Parameter name suggests redirect, return, continuation, target, or destination behavior.")
    if any(marker in path for marker in REDIRECT_PATH_MARKERS):
        has_redirect_signal = True
        score += 25
        reasons.append("Endpoint path suggests authentication, callback, continuation, or redirect workflow.")
    if ABSOLUTE_URL_RE.search(value_preview):
        has_redirect_signal = True
        score += 25
        reasons.append("Observed value resembles an absolute or protocol-relative URL.")
    if method == "GET":
        score += 10
        reasons.append("GET redirect parameters are directly testable through navigation without submitting state-changing forms.")
    if location == "form":
        score += 5
        reasons.append("Parameter appears in a form workflow that may redirect after submission.")
    if not has_redirect_signal:
        return None
    return build_candidate(
        url=url,
        method=method,
        parameter=name,
        location=location,
        score=min(score, 100),
        reasons=reasons,
        source="parameter",
    )


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    value = observation_surface_url(observation)
    if not value:
        return None
    if is_candidate_noise_url(value):
        return None
    method = str(observation.get("method", "GET")).upper()
    path = urlsplit(value).path.lower()
    input_names = [str(item) for item in observation.get("inputNames", []) if item]
    score = 0
    reasons = []
    if any(marker in path for marker in REDIRECT_PATH_MARKERS):
        score += 35
        reasons.append("Form or endpoint path suggests authentication, continuation, callback, or redirect behavior.")
    interesting_inputs = [
        name
        for name in input_names
        if _has_redirect_signal(name.lower())
    ]
    if interesting_inputs:
        score += 40
        reasons.append(f"Form inputs look redirect-relevant: {', '.join(sorted(interesting_inputs)[:5])}.")
    if not reasons:
        return None
    return build_candidate(
        url=value,
        method=method,
        parameter=sorted(interesting_inputs)[0] if interesting_inputs else "",
        location="form",
        score=min(score, 100),
        reasons=reasons,
        source="observation",
    )


def build_candidate(
    *,
    url: str,
    method: str,
    parameter: str,
    location: str,
    score: int,
    reasons: list[str],
    source: str,
) -> dict[str, Any]:
    candidate_id = f"open_redirect_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    return {
        "candidateId": candidate_id[:160],
        "type": "open_redirect_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "source": source,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reasons": reasons,
        "testPlanSummary": "Manual validation only: use a harmless external URL and confirm whether the response redirects off-site.",
    }


def _has_redirect_signal(value: str) -> bool:
    text = value.lower()
    return any(marker in text for marker in STRICT_REDIRECT_MARKERS)


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = args.get("candidate")
    if not isinstance(candidate, dict):
        if not all(key in args for key in ("url", "method")):
            raise McpError(-32602, "Provide a candidate object or url/method/parameter fields.")
        candidate = {
            "candidateId": args.get("candidateId", ""),
            "url": args["url"],
            "method": args["method"],
            "parameter": args.get("parameter", ""),
            "location": args.get("location", ""),
            "reasons": args.get("reasons", []),
            "priority": args.get("priority", "unknown"),
        }
    external_url = args.get("externalUrl", "https://example.org/")
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": candidate.get("parameter", ""),
        "location": candidate.get("location", ""),
        "priority": candidate.get("priority", "unknown"),
        "safeManualPayloads": payloads(external_url),
        "expectedSignals": [
            "HTTP 3xx Location header points to the supplied external URL or protocol-relative variant.",
            "Client-side navigation target changes to the supplied external URL.",
            "Application reflects or normalizes the URL in a way that suggests a redirect allowlist bypass may be possible.",
        ],
        "guardrails": [
            "Use only harmless external domains controlled by or approved for the test.",
            "Do not combine redirect testing with credential theft, token capture, or phishing flows.",
            "Treat candidate matches as hypotheses until a response or browser navigation confirms off-site redirect behavior.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an open redirect active test requires confirm=true.")
    candidate = coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    external_url = normalize_external_url(args.get("externalUrl") or "https://example.org/")
    allowed_payloads = payloads(external_url)
    payload = str(args.get("payload") or allowed_payloads[0])
    if payload not in allowed_payloads:
        raise McpError(-32602, "Open redirect active tests only support built-in harmless external URL payloads.")
    built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
    timeout = int(args.get("requestTimeout", 10))
    policy_args = dict(args)
    policy_args["followRedirects"] = False
    policy = HttpClientPolicy.from_args(policy_args, timeout_seconds=timeout)
    approval = approval_metadata(args)
    response_payload = http_client.send(
        HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
        policy=policy,
    ).as_dict()
    assessment, location_header = assess_redirect(response_payload, allowed_payloads)
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "open_redirect_http_exchange",
        request={key: value for key, value in built.items() if not key.startswith("_")},
        response=response_payload,
        metadata={
            "adapter": "open_redirect",
            "target": target_url,
            "parameter": parameter,
            "payload": payload,
            "approval": approval,
        },
    )
    raw = {
        "candidate": candidate,
        "request": {key: value for key, value in built.items() if key != "headers" and not key.startswith("_")},
        "requestHeaders": redact_headers(built["headers"]),
        "payload": payload,
        "response": response_summary(response_payload),
        "location": location_header,
        "exchangeEvidence": exchange_evidence,
        "assessment": assessment,
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "open_redirect_test",
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
            "tool": "open_redirect.execute_test",
            "target": target_url,
            "method": method,
            "parameter": parameter,
            "location": location,
            "assessment": assessment,
            "exchangeEvidenceId": exchange_evidence.get("evidenceId", ""),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "open_redirect.execute_test",
        f"Ran approved open redirect test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def assess_redirect(response_payload: dict[str, Any], allowed_payloads: list[str]) -> tuple[str, str]:
    headers = response_payload.get("headers", {})
    header_map = {str(name).lower(): str(value) for name, value in headers.items()} if isinstance(headers, dict) else {}
    location_header = header_map.get("location", "")
    status = int(response_payload.get("status") or 0)
    if 300 <= status < 400 and redirects_to_payload_host(location_header, allowed_payloads):
        return "open_redirect_observed", location_header
    if location_header:
        return "redirect_observed", location_header
    return "inconclusive", location_header


def redirects_to_payload_host(location_header: str, allowed_payloads: list[str]) -> bool:
    if not location_header:
        return False
    normalized_location = location_header if "://" in location_header else (f"https:{location_header}" if location_header.startswith("//") else "")
    if not normalized_location:
        return False
    location_host = urlsplit(normalized_location).hostname or ""
    for payload in allowed_payloads:
        payload_url = payload if "://" in payload else f"https:{payload}" if payload.startswith("//") else f"https://{payload}"
        if location_host and location_host == (urlsplit(payload_url).hostname or ""):
            return True
    return False


def payloads(external_url: str) -> list[str]:
    clean = normalize_external_url(external_url)
    host = urlsplit(clean if "://" in clean else f"https://{clean}").netloc or "example.org"
    return [clean, f"//{host}/", f"https://{host}/%2f.."]


def normalize_external_url(external_url: Any) -> str:
    clean = str(external_url or "").strip() or "https://example.org/"
    parsed = urlsplit(clean if "://" in clean else f"https://{clean}")
    try:
        parsed.port
    except ValueError as exc:
        raise McpError(-32602, "Open redirect externalUrl must be an absolute http(s) URL with a valid external host.") from exc
    host = parsed.hostname or ""
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise McpError(-32602, "Open redirect externalUrl must be an absolute http(s) URL with a valid external host.")
    if parsed.username or parsed.password:
        raise McpError(-32602, "Open redirect externalUrl must not include credentials.")
    validate_external_host(host)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def validate_external_host(host: str) -> None:
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".localhost") or lowered.endswith(".local"):
        raise McpError(-32602, "Open redirect externalUrl must use an external host, not localhost, metadata, or local-only names.")
    try:
        ip = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        if "." not in lowered:
            raise McpError(-32602, "Open redirect externalUrl must use an external host, not a single-label local name.")
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise McpError(-32602, "Open redirect externalUrl must use an external host, not private or special-purpose IP space.")


def priority_for_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def stable_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip().lower()).strip("-")
    return slug or "candidate"
