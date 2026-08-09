# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import credentials, evidence, scope, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.execution import ExecutionPlan
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
    surfaces = find_surfaces(entities)
    all_candidates = surfaces["candidates"]
    candidates = all_candidates[:max_candidates]
    classifications = surfaces["classifications"][:max_candidates]
    result = build_result(workspace_id, target, candidates, classifications, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "classificationCount": len(classifications),
        "classifications": classifications,
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
    reconciliation = (
        reconcile_cors_observations(workspace_id, target, {item["candidateId"] for item in all_candidates})
        if ingestion
        else {"active": len(all_candidates), "suppressed": 0}
    )
    evidence.log_event(
        "cors.analyze_workspace",
        f"Analyzed CORS candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "classificationCount": len(classifications),
            "ingested": bool(ingestion),
            "reconciliation": reconciliation,
        },
    )
    return json.dumps({**payload, "reconciliation": reconciliation, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return find_surfaces(entities)["candidates"]


def find_surfaces(entities: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    candidates: dict[str, dict[str, Any]] = {}
    classifications: dict[str, dict[str, Any]] = {}
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
        surface = _surface_from_headers(normalized_endpoint, acao, _is_truthy(lowered.get("access-control-allow-credentials")))
        if not surface:
            continue
        destination = candidates if surface.get("isReportable") else classifications
        destination.setdefault(surface["candidateId"], surface)
    reportable = collapse_host_wide(list(candidates.values()), subject_key="policyKey")
    informational = collapse_host_wide(list(classifications.values()), subject_key="policyKey")
    return {"candidates": reportable, "classifications": informational}


def _surface_from_headers(endpoint: dict[str, Any], acao: str, creds: bool) -> dict[str, Any] | None:
    acao_value = acao.strip()
    if acao_value == "*":
        if creds:
            return _build_surface(
                endpoint,
                acao_value,
                creds,
                10,
                "invalid_noncredentialed_wildcard",
                "Wildcard Access-Control-Allow-Origin cannot authorize a credentialed browser read; the response remains public only to non-credentialed CORS requests.",
                reportable=False,
            )
        return _build_surface(
            endpoint,
            acao_value,
            creds,
            5,
            "public_wildcard_read",
            "Wildcard Access-Control-Allow-Origin permits a public non-credentialed cross-origin read; assess response sensitivity separately.",
            reportable=False,
        )
    elif acao_value.lower() == "null":
        if creds:
            return _build_surface(
                endpoint,
                acao_value,
                creds,
                75,
                "credentialed_null_origin_policy_candidate",
                "The response permits credentialed reads from the attacker-controllable null origin; validate the exact endpoint and sensitive response context.",
                reportable=True,
            )
        return _build_surface(
            endpoint,
            acao_value,
            creds,
            15,
            "public_null_origin_read",
            "The response permits a non-credentialed read from the null origin; no credentialed data access is demonstrated.",
            reportable=False,
        )
    elif _normalize_origin(endpoint.get("url", "")) == _normalize_origin(acao_value):
        return None  # Same-origin ACAO is expected and not a finding.
    if creds:
        observed_reflection = _observed_cross_origin_match(endpoint, acao_value)
        return _build_surface(
            endpoint,
            acao_value,
            creds,
            80 if observed_reflection else 20,
            "observed_credentialed_origin_reflection_candidate" if observed_reflection else "credentialed_fixed_origin_policy",
            "An observed cross-origin request was answered with that exact origin and credential acceptance; validate response sensitivity and arbitrary-origin behavior."
            if observed_reflection
            else "A specific cross-origin is allowed with credentials, but the workspace does not establish attacker control or dynamic reflection.",
            reportable=observed_reflection,
        )
    return _build_surface(
        endpoint,
        acao_value,
        creds,
        10,
        "public_fixed_origin_read",
        "A specific cross-origin can read the response without credentials; the observed policy alone does not demonstrate sensitive data access.",
        reportable=False,
    )


def _build_surface(
    endpoint: dict[str, Any],
    acao: str,
    creds: bool,
    score: int,
    verdict_code: str,
    reason: str,
    *,
    reportable: bool,
) -> dict[str, Any]:
    url = str(endpoint.get("url", ""))
    return {
        "candidateId": f"cors_{stable_slug(url)}_{stable_slug(verdict_code)}"[:170],
        "type": "cors_candidate" if reportable else "cors_policy_classification",
        "url": url,
        "method": str(endpoint.get("method", "GET")).upper(),
        "header": acao,
        "policyKey": f"{verdict_code}|{acao.lower()}|credentials={str(creds).lower()}",
        "verdictCode": verdict_code,
        "observedAllowOrigin": acao,
        "allowCredentials": creds,
        "isReportable": reportable,
        "analysisEligible": reportable,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if reportable else "high",
        "reasons": [reason],
        "testPlanSummary": "Send one approved probe with a crafted Origin and require an exact allowed origin plus credential acceptance before reporting a credentialed-read candidate." if reportable else "No vulnerability validation is queued from this policy alone.",
    }


def build_result(
    workspace_id: str,
    target: str,
    candidates: list[dict[str, Any]],
    classifications: list[dict[str, Any]],
    context: dict[str, Any],
) -> AdapterResult:
    candidate_observations = [
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
                "verdictCode": candidate.get("verdictCode", ""),
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
    classification_observations = [
        {
            "type": "cors_policy_classification",
            "value": item["url"],
            "url": item["url"],
            "method": item["method"],
            "confidence": item["confidence"],
            "priority": "info",
            "priorityScore": int(item["priorityScore"]),
            "reason": item["reasons"][0],
            "reasons": item["reasons"],
            "tags": ["cors", "browser-semantics", "informational"],
            "candidateId": item["candidateId"],
            "verdictCode": item["verdictCode"],
            "observedAllowOrigin": item["observedAllowOrigin"],
            "allowCredentials": item["allowCredentials"],
            "isReportable": False,
            "analysisEligible": False,
            "dedupeScope": item.get("dedupeScope", "endpoint"),
            "host": item.get("host", ""),
            "affectedUrls": item.get("affectedUrls", []),
            "affectedCount": item.get("affectedCount", 1 if item.get("url") else 0),
        }
        for item in classifications
    ]
    observations = [*candidate_observations, *classification_observations]
    return AdapterResult(
        adapter="cors",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} CORS candidate surfaces and {len(classifications)} informational policies.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis reads observed Access-Control-* headers only; reflection is confirmed by an approved active probe.",
        ],
        metadata={"observationCount": len(observations), "classificationCount": len(classifications)},
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
            "Access-Control-Allow-Credentials is 'true' alongside the exact attacker-controlled probe origin.",
            "Wildcard plus credentials is recorded as non-reportable because browsers reject credentialed wildcard reads.",
        ],
        "guardrails": [
            "This helper builds a plan only; it does not send traffic.",
            "Run the probe only against explicitly authorized in-scope targets after operator approval (confirm=true).",
            "Use a benign, operator-controlled probe origin; do not exfiltrate cross-origin data.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(
    args: dict[str, Any],
    *,
    execution_plan: ExecutionPlan | None = None,
    authorization_receipt: object | None = None,
) -> str:
    require_confirmed(
        args,
        "Running a CORS active probe requires confirm=true.",
        authorization=authorization_receipt,
    )
    candidate = _coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    if not target_url:
        raise McpError(-32602, "A target url is required.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    if execution_plan is not None:
        execution_plan.intent.target_envelope.require(target_url)
        scope_result = scope.check_target_in_scope(
            target_url,
            execution_plan.intent.target_envelope.scope_snapshot.to_dict(),
        )
        if not scope_result.get("inScope"):
            snapshot = execution_plan.intent.target_envelope.scope_snapshot
            if snapshot.source == "workspace":
                raise McpError(-32002, f"Target is not in authorized scope for workspace {workspace.normalize_workspace_id(workspace_id)}: {scope_result.get('host', '')}")
            raise McpError(-32002, f"Target is not in authorized scope: {scope_result.get('host', '')}")
    else:
        scope_result = require_in_scope(target_url, workspace_id)
    probe_origin = str(args.get("probeOrigin") or DEFAULT_PROBE_ORIGIN)
    method = str(candidate.get("method", "GET")).upper()
    headers = {"User-Agent": "Synapse-MCP/0.1", "Origin": probe_origin}
    target_header_resolver = None
    if args.get("credentialId"):
        credential_id = str(args["credentialId"])
        credentials.credential_for_target(credential_id, target_url)
        target_header_resolver = lambda url: credentials.target_headers_with_coverage(credential_id, url)
    approval = approval_metadata(args, authorization=authorization_receipt)
    timeout = int(args.get("requestTimeout", 10))
    proxy_headers: dict[str, str] = {}
    if args.get("proxyCredentialId"):
        proxy_url = str(args.get("proxyUrl") or "")
        if not proxy_url:
            raise McpError(-32602, "proxyCredentialId requires proxyUrl.")
        proxy_credential = credentials.credential_for_provider(str(args["proxyCredentialId"]), proxy_url)
        proxy_headers = credentials.proxy_headers_for_credential_target(proxy_credential, proxy_url)
    policy = HttpClientPolicy.from_args(
        args,
        timeout_seconds=timeout,
        execution_plan=execution_plan,
        proxy_headers=proxy_headers,
    )
    policy.target_header_resolver = target_header_resolver
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
    verdict = browser_cors_verdict(target_url, probe_origin, acao, creds)
    reflected = bool(verdict["originReflected"])
    assessment = "possible_cors_misconfiguration" if verdict["isReportable"] else str(verdict["code"])
    raw = {
        "candidate": candidate,
        "probeOrigin": probe_origin,
        "request": {"url": target_url, "method": method},
        "requestHeaders": redact_headers(headers),
        **(
            {"credentialCoverage": response_payload.get("credentialCoverage", [])}
            if args.get("credentialId")
            else {}
        ),
        "response": {
            "status": response_payload.get("status"),
            "accessControlAllowOrigin": acao,
            "accessControlAllowCredentials": creds,
        },
        "exchangeEvidence": exchange_evidence,
        "originReflected": reflected,
        "verdict": verdict,
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
            "corsVerdict": verdict["code"],
            "browserAllowsRead": verdict["browserAllowsRead"],
            "browserAllowsCredentialedRead": verdict["browserAllowsCredentialedRead"],
            "isReportable": verdict["isReportable"],
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


def browser_cors_verdict(target_url: str, probe_origin: str, acao: str, creds: bool) -> dict[str, Any]:
    """Apply browser CORS response-sharing semantics to one approved probe."""
    allowed = str(acao or "").strip()
    requested = _normalize_origin(probe_origin)
    target_origin = _normalize_origin(target_url)
    allowed_normalized = _normalize_origin(allowed)
    wildcard = allowed == "*"
    exact_origin = bool(allowed and requested and allowed_normalized == requested)
    cross_origin = bool(requested and requested != target_origin)
    attacker_origin_allowed = exact_origin and cross_origin
    reflected = attacker_origin_allowed and requested != "null"

    if not allowed:
        code = "no_cors_access"
        reason = "The response omitted Access-Control-Allow-Origin, so a browser does not share it cross-origin."
        browser_read = False
        credentialed_read = False
        reportable = False
        origin_kind = "none"
    elif wildcard:
        code = "invalid_noncredentialed_wildcard" if creds else "public_wildcard_read"
        reason = (
            "Wildcard Access-Control-Allow-Origin with credentials does not authorize a credentialed browser read; only a non-credentialed public read is possible."
            if creds
            else "Wildcard Access-Control-Allow-Origin permits only a public non-credentialed cross-origin read."
        )
        browser_read = True
        credentialed_read = False
        reportable = False
        origin_kind = "wildcard"
    elif attacker_origin_allowed and creds:
        code = "credentialed_cross_origin_read_candidate"
        reason = "The exact attacker-controlled probe origin is allowed with credentials, so a browser can issue a credentialed cross-origin read."
        browser_read = True
        credentialed_read = True
        reportable = True
        origin_kind = "null" if requested == "null" else "exact_probe_origin"
    elif attacker_origin_allowed:
        code = "origin_allowed_without_credentials"
        reason = "The exact attacker-controlled probe origin is allowed, but credentials are not accepted; assess any publicly readable response data separately."
        browser_read = True
        credentialed_read = False
        reportable = False
        origin_kind = "null" if requested == "null" else "exact_probe_origin"
    elif exact_origin:
        code = "same_origin_policy"
        reason = "The allowed origin matches the target origin rather than an attacker-controlled cross-origin probe."
        browser_read = True
        credentialed_read = bool(creds)
        reportable = False
        origin_kind = "same_origin"
    else:
        code = "fixed_allowlist_not_probe_origin"
        reason = "Access-Control-Allow-Origin does not allow the supplied probe origin; the browser blocks that cross-origin read."
        browser_read = False
        credentialed_read = False
        reportable = False
        origin_kind = "null" if allowed_normalized == "null" else "fixed_origin"

    return {
        "code": code,
        "reason": reason,
        "observedAllowOrigin": allowed,
        "probeOrigin": probe_origin,
        "allowedOriginKind": origin_kind,
        "originReflected": reflected,
        "attackerControlledOriginAllowed": attacker_origin_allowed,
        "credentialAcceptance": bool(creds),
        "browserAllowsRead": browser_read,
        "browserAllowsCredentialedRead": credentialed_read,
        "isReportable": reportable,
    }


def _normalize_origin(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower() == "null":
        return "null"
    parsed = urlsplit(text)
    if not parsed.scheme or not parsed.hostname:
        return text.lower()
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return text.lower()
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = host if port is None or default_port else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _observed_cross_origin_match(endpoint: dict[str, Any], acao: str) -> bool:
    allowed = _normalize_origin(acao)
    target_origin = _normalize_origin(endpoint.get("url", ""))
    header_sets: list[dict[str, Any]] = []
    for field in ("requestHeaders", "headers"):
        values = endpoint.get(field)
        if isinstance(values, dict):
            header_sets.append(values)
    observed_requests = endpoint.get("observedRequests", [])
    if isinstance(observed_requests, list):
        for request in observed_requests:
            if not isinstance(request, dict):
                continue
            for field in ("requestHeaders", "headers"):
                values = request.get(field)
                if isinstance(values, dict):
                    header_sets.append(values)
    for headers in header_sets:
        origin = next((value for name, value in headers.items() if str(name).lower() == "origin"), "")
        normalized = _normalize_origin(origin)
        if normalized and normalized != target_origin and normalized == allowed:
            return True
    return False


def reconcile_cors_observations(workspace_id: str, target: str, active_candidate_ids: set[str]) -> dict[str, int]:
    path = workspace.target_entity_path(workspace_id, target, "observations")
    observations = workspace._read_json(path, [])
    if not isinstance(observations, list):
        return {"active": len(active_candidate_ids), "suppressed": 0}
    suppressed = 0
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("type") != "cors_candidate":
            continue
        if str(observation.get("candidateId", "")) in active_candidate_ids:
            continue
        if observation.get("isReportable") is False:
            continue
        observation["isReportable"] = False
        observation["analysisEligible"] = False
        observation["reportableDecision"] = {
            "isReportable": False,
            "reviewer": "cors_browser_semantics_reconciliation",
            "reason": "Candidate is absent from the current browser-semantic CORS snapshot.",
        }
        suppressed += 1
    if suppressed:
        workspace._write_json(path, observations)
    return {"active": len(active_candidate_ids), "suppressed": suppressed}
