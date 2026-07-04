# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, surface_candidate
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import (
    build_http_request,
    coerce_candidate,
    priority_for_score,
    record_surface_test_validation,
    redact_headers,
    response_summary,
    stable_slug,
    store_http_exchange_evidence,
)
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url, observation_surface_url


# Precision controls (Phase 4): only emit candidates with a real signal, and cap how
# many a single host/class can produce so passive analysis can't flood the workspace.
DEFAULT_MIN_SCORE = 45
MAX_CANDIDATES_PER_HOST = 12

FILE_PARAM_MARKERS = {
    "file",
    "path",
    "page",
    "template",
    "include",
    "inc",
    "view",
    "document",
    "doc",
    "download",
    "attachment",
    "lang",
    "locale",
    "theme",
    "skin",
    "resource",
    "url",
    "uri",
    "redirect",
    "next",
}
FILE_PATH_MARKERS = ("download", "file", "include", "template", "view", "resource", "asset", "locale", "theme", "upload", "config", "configuration")
LOCAL_VALUE_MARKERS = ("../", "..\\", "/", "\\", ".php", ".jsp", ".aspx", ".html", ".txt", ".pdf")
REMOTE_VALUE_RE = re.compile(r"^(?:https?|file)://", re.IGNORECASE)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("lfi"), indent=2)


def passive_analyze(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", MAX_CANDIDATES_PER_HOST))
    min_score = int(args.get("minScore", DEFAULT_MIN_SCORE))
    context = workspace.prepare_target_context(workspace_id, target, purpose="lfi_rfi_candidate_analysis", max_tokens=4000)
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
            {"adapter": "lfi", "minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "lfi.passive_analyze",
        f"Analyzed LFI/RFI candidates for {workspace.normalize_target(target)}.",
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
    path = str(parameter.get("path", "") or urlsplit(url).path).lower()
    lower_name = name.lower()
    value_preview = str(parameter.get("value", "") or parameter.get("valuePreview", ""))
    score = 10
    reasons = []
    file_signal = False
    if lower_name in FILE_PARAM_MARKERS or any(marker in lower_name for marker in FILE_PARAM_MARKERS):
        file_signal = True
        score += 45
        reasons.append("Parameter name suggests file, path, include, view, download, locale, theme, or resource behavior.")
    if any(marker in path for marker in FILE_PATH_MARKERS):
        file_signal = True
        score += 25
        reasons.append("Endpoint path suggests file retrieval, include, template, resource, locale, or theme behavior.")
    if any(marker in value_preview.lower() for marker in LOCAL_VALUE_MARKERS):
        file_signal = True
        score += 30
        reasons.append("Observed value resembles a file path, extension, or traversal sequence.")
    if REMOTE_VALUE_RE.search(value_preview):
        file_signal = True
        score += 25
        reasons.append("Observed value resembles a local or remote URI.")
    if location in {"form", "body", "json"}:
        score += 10
        reasons.append("Parameter is submitted in a body/form context where server-side file handling is plausible.")
    if not file_signal:
        return None
    return build_candidate(url=url, method=method, parameter=name, location=location, value_preview=value_preview, score=min(score, 100), reasons=reasons)


def candidate_from_observation(observation: dict[str, Any]) -> dict[str, Any] | None:
    value = observation_surface_url(observation)
    lower_text = json.dumps(observation, sort_keys=True).lower()
    if not value or not any(marker in lower_text for marker in ("download", "file", "path", "include", "sensitive_file")):
        return None
    if is_candidate_noise_url(value):
        return None
    return build_candidate(
        url=value,
        method=str(observation.get("method", "GET")).upper(),
        parameter=str(observation.get("parameter", "")),
        location=str(observation.get("location", "unknown")),
        value_preview="",
        score=60,
        reasons=["Existing workspace observation suggests file download or file handling behavior."],
    )


def build_candidate(*, url: str, method: str, parameter: str, location: str, value_preview: str, score: int, reasons: list[str]) -> dict[str, Any]:
    candidate_type = classify_candidate(parameter, value_preview)
    candidate_id = f"{candidate_type}_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    return {
        "candidateId": candidate_id[:170],
        "type": candidate_type,
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "risk": "medium" if score >= 70 else "low",
        "tags": ["lfi", "rfi", "path-traversal", "file-handling"],
        "reasons": reasons,
        "testPlanSummary": "Use benign path normalization and known public-file probes only after operator approval.",
    }


def classify_candidate(parameter: str, value_preview: str) -> str:
    lower_name = parameter.lower()
    lower_value = value_preview.lower()
    if REMOTE_VALUE_RE.search(value_preview) or lower_name in {"url", "uri", "redirect", "next"}:
        return "rfi_candidate"
    if "download" in lower_name or "attachment" in lower_name:
        return "file_download_candidate"
    if "../" in lower_value or "..\\" in lower_value:
        return "path_traversal_candidate"
    return "lfi_candidate"


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        surface_candidate(
            vuln_class="lfi",
            url=candidate["url"],
            method=candidate["method"],
            parameter=candidate["parameter"],
            location=candidate["location"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "File-handling candidate identified.",
            subtype=candidate.get("type", ""),
            tags=candidate.get("tags", []),
            test_plan_summary=candidate.get("testPlanSummary", ""),
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="lfi",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} LFI/RFI/file-handling candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis does not confirm file inclusion or traversal.",
            "Active validation is limited to benign known-file and path-normalization probes.",
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
        "safePayloads": safe_payloads(),
        "expectedSignals": [
            "Path-normalized payload returns the same public resource as the direct public-file payload.",
            "Response status, content type, or body length changes consistently for path-like payloads.",
            "Server-side errors mention path normalization, include restrictions, or denied file access.",
        ],
        "guardrails": [
            "Active tests require explicit operator approval and confirm=true.",
            "Do not request /etc/passwd, Windows system files, application secrets, backups, or credentials.",
            "Do not use off-site RFI URLs unless the operator approves a specific callback URL.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running an LFI/RFI active test requires confirm=true.")
    candidate = coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    payloads = [str(args["payload"])] if args.get("payload") else safe_payloads()
    allowed = set(safe_payloads())
    payloads = [payload for payload in payloads if payload in allowed][: int(args.get("maxPayloads", 3))]
    if not payloads:
        raise McpError(-32602, "LFI/RFI active tests only support built-in benign payloads.")
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    tests = []
    with http_client.session(policy) as session:
        for payload in payloads:
            built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
            response_payload = session.send(
                HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            ).as_dict()
            exchange_evidence = store_http_exchange_evidence(
                workspace_id,
                scope_result["host"],
                "lfi_http_exchange",
                request={key: value for key, value in built.items() if not key.startswith("_")},
                response=response_payload,
                metadata={
                    "adapter": "lfi",
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
                }
            )
    interesting = len({item["response"].get("status") for item in tests}) > 1 or len({item["response"].get("bodyLength") for item in tests}) > 1
    raw = {
        "candidate": candidate,
        "tests": tests,
        "assessment": "file_handling_behavior_observed" if interesting else "inconclusive",
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "lfi_test",
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
            "tool": "lfi.execute_test",
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
        vuln_class="lfi",
        url=target_url,
        method=method,
        parameter=parameter,
        location=location,
        interesting=interesting,
        evidence_ids=[item["exchangeEvidence"]["evidenceId"] for item in tests if item.get("exchangeEvidence")],
    )
    evidence.log_event(
        "lfi.execute_test",
        f"Ran approved benign LFI/RFI test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": raw["assessment"], "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action, "validation": validation}, indent=2)


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="path_normalization_checks",
            description="Compare direct and normalized public-file paths without requesting sensitive files.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="Use built-in benign payloads such as robots.txt and ./robots.txt.",
        ),
        RecommendedTest(
            name="benign_traversal_probe",
            description="Check whether shallow traversal changes behavior using only public-file targets.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
        ),
    ]


def safe_payloads() -> list[str]:
    return ["robots.txt", "./robots.txt", "../robots.txt"]


def context_summary(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
        "parameterCount": context.get("parameters", {}).get("total", 0),
        "candidateFindingCount": len(context.get("candidateFindings", [])),
    }
