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
from .surface_hygiene import canonical_surface_url, is_candidate_noise_url, normalize_surface_parameter, normalize_surface_url, observation_surface_url


STRONG_REDIRECT_PARAMETERS = {
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
    "callback",
    "relaystate",
    "goto",
    "forward",
}
AMBIGUOUS_URL_PARAMETERS = {"url", "uri", "target", "to"}
REDIRECT_ROUTE_TOKENS = {
    "redirect",
    "return",
    "continue",
    "callback",
    "forward",
    "goto",
}
AUTH_ROUTE_TOKENS = {"auth", "login", "logon", "logout", "oauth", "signin", "signout", "sso"}
SEARCH_CONFIG_TOKENS = {"search", "filter", "query", "facet", "configuration", "config"}
SEARCH_CONFIG_PARAMETER_NAMES = {"baseurl", "searchurl", "urlbase", "urlbasesearchstring", "urlsearchconfig"}
CLIENT_NAVIGATION_PATTERNS = (
    "window.location",
    "location.assign",
    "location.replace",
    "location.href",
    "document.location",
    "router.push",
    "navigate(",
)
ABSOLUTE_URL_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 25))
    min_score = int(args.get("minScore", 35))
    context = workspace.prepare_target_context(workspace_id, target, purpose="open_redirect_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    surfaces = find_surfaces(entities)
    candidates = [item for item in surfaces if item.get("isReportable") and item["priorityScore"] >= min_score][:max_candidates]
    classifications = [item for item in surfaces if not item.get("isReportable")][:max_candidates]
    payload = {
        "workspaceId": workspace.normalize_workspace_id(workspace_id),
        "target": workspace.normalize_target(target),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "classificationCount": len(classifications),
        "classifications": classifications,
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
    reconciliation = reconcile_open_redirect_observations(workspace_id, target, {item["candidateId"] for item in candidates})
    evidence.log_event(
        "open_redirect.analyze_workspace",
        f"Analyzed open redirect candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "classificationCount": len(classifications),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, "observationReconciliation": reconciliation, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    return [item for item in find_surfaces(entities) if item.get("isReportable") and item["priorityScore"] >= min_score]


def find_surfaces(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    endpoints_by_surface = index_endpoints(entities.get("endpoints", []))
    surfaces: dict[str, dict[str, Any]] = {}
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        method = str(parameter.get("method", "GET") or "GET").upper()
        endpoint = endpoints_by_surface.get((method, canonical_route(parameter.get("url", ""))), {})
        surface = candidate_from_parameter(parameter, endpoint)
        if surface:
            existing = surfaces.get(surface["candidateId"])
            if existing is None or (surface.get("isReportable") and not existing.get("isReportable")) or surface["priorityScore"] > existing["priorityScore"]:
                surfaces[surface["candidateId"]] = surface
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        surface = candidate_from_observation(observation)
        if surface:
            surfaces.setdefault(surface["candidateId"], surface)
    return sorted(surfaces.values(), key=lambda item: item["priorityScore"], reverse=True)


def index_endpoints(endpoints: Any) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for endpoint in endpoints if isinstance(endpoints, list) else []:
        if not isinstance(endpoint, dict):
            continue
        method = str(endpoint.get("method", "GET") or "GET").upper()
        route = canonical_route(endpoint.get("url", ""))
        if not route:
            continue
        current = indexed.setdefault((method, route), {"url": route, "method": method})
        for field in ("statusCodes", "redirectLocations", "observedRequests", "responseHeaders", "navigationSignals"):
            value = endpoint.get(field)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                existing = current.get(field, []) if isinstance(current.get(field), list) else []
                current[field] = existing + [item for item in value if item not in existing]
            elif isinstance(value, dict):
                current[field] = {**(current.get(field, {}) if isinstance(current.get(field), dict) else {}), **value}
            else:
                current.setdefault(field, value)
        for field in ("status", "path", "source", "sourceAsset", "reason"):
            if endpoint.get(field) not in (None, ""):
                current.setdefault(field, endpoint[field])
    return indexed


def candidate_from_parameter(parameter: dict[str, Any], endpoint: dict[str, Any] | None) -> dict[str, Any] | None:
    name = str(parameter.get("name", "")).strip()
    url = normalize_surface_url(parameter.get("url", ""))
    if not name or not url:
        return None
    if is_candidate_noise_url(url):
        return None
    method = str(parameter.get("method", "") or (endpoint or {}).get("method", "GET")).upper()
    location = str(parameter.get("location", "query"))
    path = urlsplit(url).path
    path_tokens = semantic_tokens(path)
    normalized_name = normalize_surface_parameter(name)
    value_preview = str(parameter.get("value", "") or parameter.get("valuePreview", ""))
    score = 10
    reasons: list[str] = []
    signals: list[str] = []
    strong_parameter = normalized_name in STRONG_REDIRECT_PARAMETERS
    ambiguous_parameter = normalized_name in AMBIGUOUS_URL_PARAMETERS
    observed_redirect = endpoint_has_redirect_response(endpoint or {})
    client_navigation = endpoint_has_client_navigation({"parameter": parameter, "endpoint": endpoint or {}})
    redirect_route = bool(path_tokens & REDIRECT_ROUTE_TOKENS)
    auth_continuation = bool(path_tokens & AUTH_ROUTE_TOKENS) and (strong_parameter or ambiguous_parameter)
    absolute_value = bool(ABSOLUTE_URL_RE.search(value_preview))
    if is_oembed_surface(path, normalized_name) and not observed_redirect and not client_navigation:
        return build_classification(
            url=url,
            method=method,
            parameter=name,
            location=location,
            classification="server_side_fetch_embed",
            reason="WordPress oEmbed URL input is server-side fetch/embed semantics, not navigation/continuation behavior.",
            candidate_for=["ssrf"],
        )
    if is_search_configuration(path_tokens, normalized_name, parameter) and not observed_redirect and not client_navigation and not redirect_route:
        return build_classification(
            url=url,
            method=method,
            parameter=name,
            location=location,
            classification="search_configuration",
            reason="Search/form URL configuration lacks an observed redirect response or client navigation sink.",
        )
    if strong_parameter:
        score += 35
        signals.append("continuation_parameter")
        reasons.append("Parameter is an exact redirect/return/continuation concept.")
    elif ambiguous_parameter:
        score += 10
        reasons.append("Parameter is a generic URL/target concept and needs endpoint behavior corroboration.")
    if observed_redirect:
        score += 60
        signals.append("observed_redirect_response")
        reasons.append("Observed endpoint evidence contains a redirect status or Location header.")
    if client_navigation:
        score += 50
        signals.append("client_navigation_sink")
        reasons.append("Stored endpoint/JavaScript context contains a client navigation sink.")
    if redirect_route:
        score += 35
        signals.append("redirect_route")
        reasons.append("Endpoint route has explicit redirect/return/continuation semantics.")
    elif auth_continuation:
        score += 30
        signals.append("authentication_continuation_route")
        reasons.append("Authentication route and continuation parameter jointly imply post-authentication navigation.")
    if ABSOLUTE_URL_RE.search(value_preview):
        score += 10
        reasons.append("Observed value is absolute, but value shape alone is not treated as redirect behavior.")
    if method == "GET":
        score += 5
        reasons.append("GET redirect parameters are directly testable through navigation without submitting state-changing forms.")
    if location == "form":
        score += 5
        reasons.append("Parameter appears in a form workflow that may redirect after submission.")
    reportable = bool(signals) or strong_parameter
    if not reportable:
        if ambiguous_parameter or absolute_value:
            return build_classification(
                url=url,
                method=method,
                parameter=name,
                location=location,
                classification="ambiguous_url_input",
                reason="Generic URL input lacks a Location response, client navigation sink, redirect route, or authentication continuation semantic.",
                candidate_for=["ssrf"] if absolute_value else [],
            )
        return None
    return build_candidate(
        url=url,
        method=method,
        parameter=name,
        location=location,
        score=min(score, 100),
        reasons=reasons,
        source="parameter",
        signals=signals,
    )


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    value = observation_surface_url(observation)
    if not value:
        return None
    if is_candidate_noise_url(value):
        return None
    method = str(observation.get("method", "GET")).upper()
    path = urlsplit(value).path
    path_tokens = semantic_tokens(path)
    input_names = [str(item) for item in observation.get("inputNames", []) if item]
    score = 0
    reasons = []
    if path_tokens & REDIRECT_ROUTE_TOKENS:
        score += 35
        reasons.append("Form or endpoint path suggests authentication, continuation, callback, or redirect behavior.")
    interesting_inputs = [
        name
        for name in input_names
        if normalize_surface_parameter(name) in STRONG_REDIRECT_PARAMETERS
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
        signals=["redirect_route"] if path_tokens & REDIRECT_ROUTE_TOKENS else ["continuation_parameter"],
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
    signals: list[str] | None = None,
) -> dict[str, Any]:
    route = canonical_route(url)
    normalized_parameter = normalize_surface_parameter(parameter)
    candidate_id = f"open_redirect_{stable_slug(method)}_{stable_slug(route)}_{stable_slug(location)}_{stable_slug(normalized_parameter or location)}"
    return {
        "candidateId": candidate_id[:160],
        "type": "open_redirect_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "source": source,
        "canonicalRoute": route,
        "redirectSignals": signals or [],
        "isReportable": True,
        "analysisEligible": True,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reasons": reasons,
        "testPlanSummary": "Manual validation only: use a harmless external URL and confirm whether the response redirects off-site.",
    }


def build_classification(
    *,
    url: str,
    method: str,
    parameter: str,
    location: str,
    classification: str,
    reason: str,
    candidate_for: list[str] | None = None,
) -> dict[str, Any]:
    route = canonical_route(url)
    normalized_parameter = normalize_surface_parameter(parameter)
    classification_id = f"open_redirect_classification_{stable_slug(method)}_{stable_slug(route)}_{stable_slug(location)}_{stable_slug(normalized_parameter or location)}"
    return {
        "candidateId": classification_id[:160],
        "type": "open_redirect_surface_classification",
        "url": url,
        "canonicalRoute": route,
        "method": method,
        "parameter": parameter,
        "location": location,
        "classification": classification,
        "candidateFor": candidate_for or [],
        "suggestedAdapter": "ssrf" if "ssrf" in (candidate_for or []) else "",
        "priority": "low",
        "priorityScore": 20,
        "confidence": "high" if classification in {"server_side_fetch_embed", "search_configuration"} else "medium",
        "reason": reason,
        "reasons": [reason],
        "isReportable": False,
        "analysisEligible": False,
    }


def canonical_route(value: Any) -> str:
    canonical = canonical_surface_url(value)
    parsed = urlsplit(canonical)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def semantic_tokens(value: Any) -> set[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(value or ""))
    return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", text)}


def endpoint_has_redirect_response(endpoint: dict[str, Any]) -> bool:
    statuses: set[int] = set()
    for value in (endpoint.get("statusCodes", []) if isinstance(endpoint.get("statusCodes"), list) else [endpoint.get("statusCodes")]) + [endpoint.get("status")]:
        try:
            statuses.add(int(value))
        except (TypeError, ValueError):
            pass
    observed_locations: list[Any] = []
    for request in endpoint.get("observedRequests", []) if isinstance(endpoint.get("observedRequests"), list) else []:
        if not isinstance(request, dict):
            continue
        for value in (request.get("status"), request.get("statusCode")):
            try:
                statuses.add(int(value))
            except (TypeError, ValueError):
                pass
        observed_locations.extend([request.get("location"), request.get("redirectLocation")])
    response_headers = endpoint.get("responseHeaders", {})
    has_location = bool(endpoint.get("redirectLocations")) or any(observed_locations) or (
        isinstance(response_headers, dict) and any(str(name).lower() == "location" and value for name, value in response_headers.items())
    )
    return has_location or any(300 <= status < 400 for status in statuses)


def endpoint_has_client_navigation(context: dict[str, Any]) -> bool:
    serialized = json.dumps(context, ensure_ascii=False, sort_keys=True).lower()
    return any(pattern in serialized for pattern in CLIENT_NAVIGATION_PATTERNS)


def is_oembed_surface(path: str, parameter: str) -> bool:
    return parameter == "url" and "oembed" in semantic_tokens(path)


def is_search_configuration(path_tokens: set[str], parameter: str, record: dict[str, Any]) -> bool:
    name_tokens = semantic_tokens(parameter)
    input_type = str(record.get("inputType", "") or "").lower()
    config_like_name = parameter in AMBIGUOUS_URL_PARAMETERS or parameter in SEARCH_CONFIG_PARAMETER_NAMES or bool(name_tokens & SEARCH_CONFIG_TOKENS) or "base" in name_tokens
    return bool(path_tokens & SEARCH_CONFIG_TOKENS) and config_like_name and input_type in {"", "hidden", "text", "url"}


def reconcile_open_redirect_observations(workspace_id: str, target: str, active_candidate_ids: set[str]) -> dict[str, int]:
    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    path = workspace.target_entity_path(wid, host, "observations")
    observations = workspace._read_json(path, [])
    if not isinstance(observations, list):
        return {"active": len(active_candidate_ids), "suppressed": 0}
    suppressed = 0
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("type") != "open_redirect_candidate":
            continue
        if str(observation.get("candidateId", "")) in active_candidate_ids:
            continue
        if observation.get("isReportable") is False:
            continue
        observation["isReportable"] = False
        observation["analysisEligible"] = False
        observation["reportableDecision"] = {
            "isReportable": False,
            "reviewer": "open_redirect_reconciliation",
            "reason": "Candidate is absent from the current semantic open-redirect snapshot.",
        }
        suppressed += 1
    if suppressed:
        workspace._write_json(path, observations)
    return {"active": len(active_candidate_ids), "suppressed": suppressed}


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
