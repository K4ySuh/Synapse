# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import build_http_request, coerce_candidate, record_surface_test_validation, redact_headers, response_summary, store_http_exchange_evidence
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url


# Precision controls (Phase 4): only emit candidates with a real signal, and cap how
# many a single host/class can produce so passive analysis can't flood the workspace.
DEFAULT_MIN_SCORE = 45
MAX_CANDIDATES_PER_HOST = 12

URL_PARAM_MARKERS = {
    "url",
    "uri",
    "link",
    "target",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "return",
    "return_url",
    "next",
    "callback",
    "webhook",
    "endpoint",
    "feed",
    "proxy",
    "image",
    "avatar",
    "file",
    "path",
    "host",
    "domain",
    "site",
    "fetch",
}
SSRF_PATH_MARKERS = (
    "fetch",
    "proxy",
    "webhook",
    "callback",
    "import",
    "export",
    "upload",
    "download",
    "preview",
    "render",
    "image",
    "avatar",
    "feed",
    "oembed",
    "url",
    "redirect",
)
PRIVATE_TARGET_HINTS = ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google.internal", "::1")
URL_VALUE_RE = re.compile(r"^(?:https?|ftp|file|gopher)://", re.IGNORECASE)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", MAX_CANDIDATES_PER_HOST))
    min_score = int(args.get("minScore", DEFAULT_MIN_SCORE))
    context = workspace.prepare_target_context(workspace_id, target, purpose="ssrf_candidate_analysis", max_tokens=4000)
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
            "ssrf_analysis",
            "candidate_analysis",
            "json",
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "ssrf.analyze_workspace",
        f"Analyzed SSRF candidates for {workspace.normalize_target(target)}.",
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
    score = 10
    reasons = []
    if lower_name in URL_PARAM_MARKERS or any(marker in lower_name for marker in URL_PARAM_MARKERS):
        score += 40
        reasons.append("Parameter name suggests a URL, host, redirect, callback, file, or fetch target.")
    if any(marker in path for marker in SSRF_PATH_MARKERS):
        score += 25
        reasons.append("Endpoint path suggests server-side fetch, proxy, webhook, import/export, rendering, or URL handling.")
    if method in {"POST", "PUT", "PATCH"}:
        score += 10
        reasons.append("State-changing method commonly carries server-side integration parameters.")
    if location in {"form", "json", "body"}:
        score += 10
        reasons.append("Parameter is in a submitted body/form context rather than passive navigation only.")
    value_preview = str(parameter.get("value", "") or parameter.get("valuePreview", ""))
    if URL_VALUE_RE.search(value_preview) or any(hint in value_preview.lower() for hint in PRIVATE_TARGET_HINTS):
        score += 30
        reasons.append("Observed value already resembles a URL or private/internal target.")
    if not reasons:
        return None
    score = min(score, 100)
    return build_candidate(
        url=url,
        method=method,
        parameter=name,
        location=location,
        score=score,
        reasons=reasons,
        source="parameter",
    )


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    category = str(observation.get("category", ""))
    value = observation_surface_url(observation)
    method = str(observation.get("method", "GET")).upper()
    input_names = [str(item) for item in observation.get("inputNames", []) if item]
    path = urlsplit(value).path.lower()
    score = 0
    reasons = []
    if category == "high_value_form" or observation.get("type") == "post_form_candidate":
        score += 45
        reasons.append("Discovered form represents a high-value workflow that may pass server-side integration targets.")
    if any(marker in path for marker in SSRF_PATH_MARKERS):
        score += 30
        reasons.append("Form or endpoint action path suggests URL fetching or integration behavior.")
    interesting_inputs = [name for name in input_names if name.lower() in URL_PARAM_MARKERS or any(marker in name.lower() for marker in URL_PARAM_MARKERS)]
    if interesting_inputs:
        score += 35
        reasons.append(f"Form inputs look SSRF-relevant: {', '.join(sorted(interesting_inputs)[:5])}.")
    if not reasons or not value:
        return None
    if is_candidate_noise_url(value):
        return None
    parameter = sorted(interesting_inputs)[0] if interesting_inputs else ""
    return build_candidate(
        url=value,
        method=method,
        parameter=parameter,
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
    candidate_id = f"ssrf_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    return {
        "candidateId": candidate_id[:140],
        "type": "ssrf_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "source": source,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reasons": reasons,
        "testPlanSummary": "Manual SSRF validation only: use collaborator/canary URL payloads and verify outbound interaction before any internal-address probes.",
    }


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
    parameter = str(candidate.get("parameter", ""))
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": parameter,
        "location": candidate.get("location", ""),
        "priority": candidate.get("priority", "unknown"),
        "safeManualPayloads": safe_payloads(args.get("callbackBaseUrl", "https://<collaborator-or-canary-domain>"), parameter),
        "expectedSignals": [
            "Out-of-band DNS or HTTP interaction to the operator-controlled callback domain.",
            "Application response changes indicating the server attempted to retrieve the supplied URL.",
            "Server-side error messages referencing URL fetch, DNS resolution, connection refused, or blocked protocols.",
        ],
        "guardrails": [
            "Do not probe cloud metadata, localhost, private RFC1918 ranges, or internal hostnames until an operator approves that exact active test.",
            "Start with a unique external canary URL per candidate so evidence can be attributed.",
            "Do not treat Shodan/OSINT exposure or parameter names as confirmed SSRF without an observed server-side interaction.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an SSRF active canary probe requires confirm=true.")
    candidate = coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    callback_payloads = active_callback_payloads(args, parameter)
    payload = str(args.get("payload") or callback_payloads[0])
    if payload not in callback_payloads:
        raise McpError(-32602, "SSRF active tests only support the approved callback URL payloads for this run.")
    validate_callback_url(payload)
    built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    approval = approval_metadata(args)
    response_payload = http_client.send(
        HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
        policy=policy,
    ).as_dict()
    assessment = assess_ssrf_response(response_payload, payload)
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "ssrf_http_exchange",
        request={key: value for key, value in built.items() if not key.startswith("_")},
        response=response_payload,
        metadata={
            "adapter": "ssrf",
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
        "exchangeEvidence": exchange_evidence,
        "assessment": assessment,
        "approval": approval,
        "verificationRequired": "Confirm any out-of-band DNS/HTTP interaction in the operator-controlled callback system before treating this as confirmed SSRF.",
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "ssrf_test",
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
            "tool": "ssrf.execute_test",
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
    # SSRF is confirmed out-of-band: only an in-band fetch signal confirms; otherwise the
    # class stays inconclusive (a null in-band response does not refute the candidate).
    ssrf_outcome = "confirmed" if assessment == "possible_ssrf_behavior" else "inconclusive"
    validation = record_surface_test_validation(
        workspace_id,
        scope_result["host"],
        vuln_class="ssrf",
        url=target_url,
        method=method,
        parameter=parameter,
        location=location,
        outcome=ssrf_outcome,
        evidence_ids=[exchange_evidence.get("evidenceId", "")],
    )
    evidence.log_event(
        "ssrf.execute_test",
        f"Ran approved SSRF canary probe against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action, "validation": validation}, indent=2)


def active_callback_payloads(args: dict[str, Any], parameter: str) -> list[str]:
    exact = str(args.get("callbackUrl") or "").strip()
    if exact:
        validate_callback_url(exact)
        return [exact]
    callback_base = str(args.get("callbackBaseUrl") or "").strip()
    if not callback_base:
        raise McpError(-32602, "SSRF active tests require callbackBaseUrl or callbackUrl for an operator-controlled external canary.")
    payload_list = safe_payloads(callback_base, parameter)
    for payload in payload_list:
        validate_callback_url(payload)
    return payload_list


def validate_callback_url(callback_url: str) -> None:
    parsed = urlsplit(callback_url)
    host = parsed.hostname or ""
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        raise McpError(-32602, "SSRF callback URL must be an absolute http(s) URL.")
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".localhost") or lowered.endswith(".local"):
        raise McpError(-32602, "SSRF callback URL must not target localhost, metadata, or local-only names.")
    try:
        ip = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise McpError(-32602, "SSRF callback URL must use an external operator-controlled host, not private or special-purpose IP space.")


def assess_ssrf_response(response_payload: dict[str, Any], payload: str) -> str:
    body = str(response_payload.get("body", "") or "")
    lowered = body.lower()
    host = (urlsplit(payload).hostname or "").lower()
    fetch_markers = (
        "fetch",
        "request",
        "connect",
        "connection",
        "dns",
        "resolve",
        "getaddrinfo",
        "enotfound",
        "econnrefused",
        "timeout",
        "blocked",
    )
    if host and host in lowered and any(marker in lowered for marker in fetch_markers):
        return "possible_ssrf_behavior"
    if payload in body or (host and host in lowered):
        return "url_value_observed"
    return "oob_verification_required"


def safe_payloads(callback_base_url: str, parameter: str) -> list[str]:
    base = callback_base_url.rstrip("/") or "https://<collaborator-or-canary-domain>"
    token = stable_slug(parameter or "ssrf")
    return [
        f"{base}/ssrf/{token}",
        f"http://{urlsplit(base).netloc or '<collaborator-or-canary-domain>'}/ssrf/{token}",
    ]


def priority_for_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def stable_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip().lower()).strip("-")
    return slug or "candidate"
