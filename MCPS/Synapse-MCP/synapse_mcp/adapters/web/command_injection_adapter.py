# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib import parse

from ...core import evidence, fingerprint, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import (
    build_http_request,
    build_manual_replay,
    priority_for_score,
    redact_headers,
    response_summary,
    stable_slug,
    store_http_exchange_evidence,
)
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url


COMMAND_PARAM_MARKERS = {
    "cmd",
    "command",
    "exec",
    "execute",
    "shell",
    "process",
    "run",
    "script",
    "ping",
    "lookup",
    "nslookup",
    "traceroute",
    "trace",
    "host",
    "hostname",
    "domain",
    "ip",
    "address",
    "target",
}
COMMAND_PATH_MARKERS = (
    "cmd",
    "command",
    "exec",
    "shell",
    "process",
    "run",
    "script",
    "ping",
    "lookup",
    "dns",
    "trace",
    "diagnostic",
    "network",
    "admin",
)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 25))
    min_score = int(args.get("minScore", 35))
    organization = args.get("organization", "unknown-org")
    context = workspace.prepare_target_context(workspace_id, target, purpose="command_injection_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    os_context = infer_os_context(target, organization)
    candidates = find_candidates(entities, min_score, os_context)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context, os_context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "osContext": os_context,
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
            {"adapter": "command_injection", "minScore": min_score, "maxCandidates": max_candidates, "organization": organization},
        )
    evidence.log_event(
        "command_injection.analyze_workspace",
        f"Analyzed command injection candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "osFamily": os_context["family"],
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def infer_os_context(target: str, organization: str = "unknown-org") -> dict[str, Any]:
    result = fingerprint.read_host_fingerprint(target, organization)
    possible = {}
    if result.get("exists") and isinstance(result.get("fingerprint"), dict):
        possible = result["fingerprint"].get("possibleOs", {}) if isinstance(result["fingerprint"].get("possibleOs"), dict) else {}
    family = "unknown"
    confidence = "low"
    if possible:
        family = str(max(possible.items(), key=lambda item: int(item[1]))[0]).lower()
        confidence = "medium"
        if len(possible) == 1:
            confidence = "high"
    return {
        "family": family if family in {"unix", "windows"} else "unknown",
        "confidence": confidence if family in {"unix", "windows"} else "low",
        "source": "fingerprint.json" if result.get("exists") else "none",
        "fingerprintPath": result.get("path", ""),
        "possibleOs": possible,
    }


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int, os_context: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints_by_url = {item.get("url"): item for item in entities.get("endpoints", []) if isinstance(item, dict)}
    candidates: dict[str, dict[str, Any]] = {}
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        candidate = candidate_from_parameter(parameter, endpoints_by_url.get(parameter.get("url")), os_context)
        if candidate and candidate["priorityScore"] >= min_score:
            candidates[candidate["candidateId"]] = candidate
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def candidate_from_parameter(parameter: dict[str, Any], endpoint: dict[str, Any] | None, os_context: dict[str, Any]) -> dict[str, Any] | None:
    name = str(parameter.get("name", "")).strip()
    url = normalize_surface_url(parameter.get("url", ""))
    if not name or not url:
        return None
    if is_candidate_noise_url(url):
        return None
    method = str(parameter.get("method", "") or (endpoint or {}).get("method", "GET")).upper()
    location = str(parameter.get("location", "query"))
    path = str(parameter.get("path", "") or parse.urlsplit(url).path).lower()
    lower_name = name.lower()
    score = 10
    reasons = []
    if lower_name in COMMAND_PARAM_MARKERS or any(marker in lower_name for marker in COMMAND_PARAM_MARKERS):
        score += 45
        reasons.append("Parameter name suggests command, process, shell, network diagnostic, host, or target input.")
    if any(marker in path for marker in COMMAND_PATH_MARKERS):
        score += 30
        reasons.append("Endpoint path suggests command execution, diagnostics, network lookup, scripting, or admin tooling.")
    if location in {"form", "body", "json"}:
        score += 10
        reasons.append("Parameter is in a submitted body/form context where server-side processing is more likely.")
    if method in {"POST", "PUT", "PATCH"}:
        score += 10
        reasons.append("State-changing method may wrap server-side workflow execution.")
    if not reasons:
        return None
    score = min(score, 100)
    return build_candidate(url=url, method=method, parameter=name, location=location, score=score, reasons=reasons, os_context=os_context)


def build_candidate(*, url: str, method: str, parameter: str, location: str, score: int, reasons: list[str], os_context: dict[str, Any]) -> dict[str, Any]:
    candidate_id = f"command_injection_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(parameter or location)}"
    family = os_context.get("family", "unknown")
    return {
        "candidateId": candidate_id[:160],
        "type": "command_injection_candidate",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "osFamily": family,
        "osConfidence": os_context.get("confidence", "low"),
        "reasons": reasons,
        "payloadPreview": benign_payloads(family, "SYNAPSE_TOKEN")[:3],
        "testPlanSummary": "Benign validation only: inject an echo-style marker payload and look for marker reflection or command-output side effects.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any], os_context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="command_injection_candidate",
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            parameter=candidate["parameter"],
            location=candidate["location"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "Command injection candidate identified.",
            tags=["command-injection", "active-validation-candidate"],
            metadata={
                "candidateId": candidate["candidateId"],
                "osFamily": candidate.get("osFamily", "unknown"),
                "osConfidence": candidate.get("osConfidence", "low"),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="command_injection",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} command injection candidate surfaces.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis identifies command-like input surfaces only.",
            "Active validation is limited to benign echo-style marker payloads.",
        ],
        metadata={"contextSummary": context_summary(context), "osContext": os_context},
    )


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = coerce_candidate(args)
    family = str(args.get("osFamily") or candidate.get("osFamily") or "unknown").lower()
    token = stable_token(args.get("marker") or candidate.get("candidateId") or candidate.get("parameter") or "cmdi")
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": candidate.get("method", "GET"),
        "parameter": candidate.get("parameter", ""),
        "location": candidate.get("location", ""),
        "osFamily": family if family in {"unix", "windows"} else "unknown",
        "safeManualPayloads": benign_payloads(family, token),
        "expectedSignals": [
            f"Response body contains the marker {token}.",
            "Response behavior changes in a way consistent with command parsing, without destructive side effects.",
            "Server-side errors mention shell metacharacters, command parsing, or blocked command execution.",
        ],
        "guardrails": [
            "Use only benign echo-style marker payloads generated for the inferred OS family.",
            "Do not run file reads, network callbacks, delays, shells, privilege checks, or destructive commands.",
            "Treat lack of marker reflection as inconclusive unless corroborated by other evidence.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def prepare_replay(args: dict[str, Any]) -> str:
    candidate = coerce_candidate(args)
    family = str(args.get("osFamily") or candidate.get("osFamily") or "unknown").lower()
    token = stable_token(args.get("marker") or candidate.get("candidateId") or candidate.get("parameter") or "cmdi")
    replay = build_manual_replay(
        {**args, "candidate": candidate},
        adapter="command_injection",
        payloads=benign_payloads(family, token),
        expected_signals=[
            f"Response body contains the marker {token}.",
            "Response behavior changes in a way consistent with command parsing, without destructive side effects.",
            "Server-side errors mention shell metacharacters, command parsing, or blocked command execution.",
        ],
        guardrails=[
            "Use only the generated echo-style marker payloads.",
            "Do not replay file reads, network callbacks, delays, shells, privilege checks, or destructive commands.",
        ],
    )
    replay["osFamily"] = family if family in {"unix", "windows"} else "unknown"
    replay["marker"] = token
    return json.dumps(replay, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running a command injection execution test requires confirm=true.")
    candidate = coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    if not target_url or not parameter:
        raise McpError(-32602, "A target url and parameter are required.")
    family = str(args.get("osFamily") or candidate.get("osFamily") or "unknown").lower()
    marker = stable_token(args.get("marker") or f"synapse-{int(time.time())}")
    allowed_payloads = benign_payloads(family, marker)
    payload = str(args.get("payload") or allowed_payloads[0])
    if payload not in allowed_payloads:
        raise McpError(-32602, "Command injection active tests only support built-in benign payloads.")
    built = build_http_request(target_url, method, parameter, location, payload, args.get("credentialId"))
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    approval = approval_metadata(args)
    response_payload = http_client.send(
        HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
        policy=policy,
    ).as_dict()
    body = str(response_payload.get("body", "") or "")
    # Distinguish executed command output (a standalone marker emitted by echo) from
    # the app merely reflecting the literal payload back: a reflected "echo <marker>"
    # contains the marker too, but always as part of "echo <marker>". Counting lets a
    # response that both reflects and executes still register the executed occurrence.
    observed = body.count(marker) > body.count(f"echo {marker}")
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "command_injection_http_exchange",
        request={key: value for key, value in built.items() if not key.startswith("_")},
        response=response_payload,
        metadata={
            "adapter": "command_injection",
            "target": target_url,
            "parameter": parameter,
            "payload": payload,
            "marker": marker,
            "approval": approval,
        },
    )
    raw = {
        "candidate": candidate,
        "request": {key: value for key, value in built.items() if key != "headers" and not key.startswith("_")},
        "requestHeaders": redact_headers(built["headers"]),
        "payload": payload,
        "marker": marker,
        "osFamily": family if family in {"unix", "windows"} else "unknown",
        "response": response_summary(response_payload),
        "exchangeEvidence": exchange_evidence,
        "observedMarker": observed,
        "assessment": "possible_command_injection" if observed else "inconclusive",
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "command_injection_test",
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
            "tool": "command_injection.execute_test",
            "target": target_url,
            "method": method,
            "parameter": parameter,
            "location": location,
            "osFamily": raw["osFamily"],
            "observedMarker": observed,
            "assessment": raw["assessment"],
            "exchangeEvidenceId": exchange_evidence.get("evidenceId", ""),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "command_injection.execute_test",
        f"Ran benign command injection test against {scope_result['host']} parameter {parameter}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "observedMarker": observed, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def coerce_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    if not all(key in args for key in ("url", "method", "parameter")):
        raise McpError(-32602, "Provide a candidate object or url/method/parameter fields.")
    return {
        "candidateId": args.get("candidateId", ""),
        "url": args["url"],
        "method": args["method"],
        "parameter": args["parameter"],
        "location": args.get("location", "query"),
        "osFamily": args.get("osFamily", "unknown"),
        "reasons": args.get("reasons", []),
    }


def benign_payloads(os_family: str, token: str) -> list[str]:
    family = os_family.lower()
    if family == "windows":
        return [f"& echo {token}", f"| echo {token}", f"&& echo {token}"]
    if family == "unix":
        return [f"; echo {token}", f"| echo {token}", f"&& echo {token}"]
    return [f"; echo {token}", f"& echo {token}", f"| echo {token}"]


def stable_token(value: Any) -> str:
    return ("SYNAPSE_" + re.sub(r"[^A-Z0-9]+", "_", str(value).upper()).strip("_"))[:64]


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="echo_marker_parameter_probe",
            description="Inject one benign echo-style marker payload and look only for marker output or parser errors.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="Use OS-aware echo markers generated by Synapse; do not use file, network, timing, shell, or destructive commands.",
        )
    ]


def context_summary(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
        "parameterCount": context.get("parameters", {}).get("total", 0),
        "interestingCandidateCount": len(context.get("interestingCandidates", [])),
    }
