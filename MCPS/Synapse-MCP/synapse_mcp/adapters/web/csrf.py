# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from .active_probe import priority_for_score, stable_slug

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Substrings that indicate an anti-CSRF token field is present on a form.
CSRF_TOKEN_MARKERS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "requestverificationtoken",
    "csrfmiddlewaretoken",
    "anti-forgery",
    "antiforgery",
    "nonce",
)
HIGH_VALUE_ACTION_MARKERS = (
    "login", "logout", "password", "passwd", "email", "account", "admin", "user",
    "profile", "settings", "transfer", "payment", "delete", "update", "create", "register",
)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("csrf"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 50))
    min_score = int(args.get("minScore", 35))
    context = workspace.prepare_target_context(workspace_id, target, purpose="csrf_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities, min_score)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "weakSameSiteObserved": _weak_samesite_observed(entities),
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
            {"adapter": "csrf", "minScore": min_score, "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "csrf.analyze_workspace",
        f"Analyzed CSRF candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    forms = _collect_forms(entities)
    weak_samesite = _weak_samesite_observed(entities)
    candidates: dict[str, dict[str, Any]] = {}
    for (method, action), input_names in forms.items():
        if any(_is_token_field(name) for name in input_names):
            continue
        candidate = _build_candidate(method, action, sorted(input_names), weak_samesite)
        if candidate["priorityScore"] >= min_score:
            candidates.setdefault(candidate["candidateId"], candidate)
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def _collect_forms(entities: dict[str, list[dict[str, Any]]]) -> dict[tuple[str, str], set[str]]:
    forms: dict[tuple[str, str], set[str]] = {}
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        obs_type = str(observation.get("type", ""))
        if obs_type not in {"form_endpoint", "post_form_candidate"} and not (
            obs_type == "sitemap_finding_candidate" and observation.get("category") == "high_value_form"
        ):
            continue
        action = str(observation.get("value", ""))
        if not action:
            continue
        method = str(observation.get("method", "") or ("POST" if obs_type == "post_form_candidate" else "GET")).upper()
        if method not in STATE_CHANGING_METHODS:
            continue
        names = {str(name) for name in observation.get("inputNames", []) if name}
        forms.setdefault((method, action), set()).update(names)
    # Supplement input names from normalized form parameters.
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict) or str(parameter.get("location", "")) != "form":
            continue
        method = str(parameter.get("method", "GET")).upper()
        action = str(parameter.get("url", ""))
        if method in STATE_CHANGING_METHODS and (method, action) in forms and parameter.get("name"):
            forms[(method, action)].add(str(parameter["name"]))
    return forms


def _is_token_field(name: str) -> bool:
    lowered = str(name).lower()
    return any(marker in lowered for marker in CSRF_TOKEN_MARKERS)


def _weak_samesite_observed(entities: dict[str, list[dict[str, Any]]]) -> bool:
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        for cookie in endpoint.get("responseCookieFlags", []) if isinstance(endpoint.get("responseCookieFlags"), list) else []:
            if isinstance(cookie, dict):
                same_site = str(cookie.get("sameSite", "")).lower()
                if not same_site or same_site == "none":
                    return True
    return False


def _build_candidate(method: str, action: str, input_names: list[str], weak_samesite: bool) -> dict[str, Any]:
    path = urlsplit(action).path.lower()
    score = 40
    reasons = ["State-changing form has no recognized anti-CSRF token field."]
    if any(marker in path for marker in HIGH_VALUE_ACTION_MARKERS):
        score += 20
        reasons.append("Form action targets a sensitive authentication/account/admin workflow.")
    if weak_samesite:
        score += 15
        reasons.append("Session cookies on this target use weak or absent SameSite, broadening CSRF exposure.")
    score = min(score, 100)
    return {
        "candidateId": f"csrf_{stable_slug(method)}_{stable_slug(action)}"[:170],
        "type": "csrf_candidate",
        "url": action,
        "method": method,
        "location": "form",
        "inputNames": input_names,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reasons": reasons,
        "testPlanSummary": "Manual validation only: confirm the form lacks server-validated anti-CSRF protection before reporting.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="csrf_candidate",
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            location="form",
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "CSRF candidate identified.",
            tags=["csrf", "missing-anti-csrf-token"],
            metadata={
                "candidateId": candidate["candidateId"],
                "inputNames": candidate.get("inputNames", []),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="csrf",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} CSRF candidate forms.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Candidate-only; absence of a recognized token field is not proof of exploitable CSRF.",
            "Token detection is name-based; double-submit-cookie or header-token schemes may not be visible passively.",
        ],
        metadata={"observationCount": len(observations)},
    )


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = args.get("candidate")
    if not isinstance(candidate, dict):
        if "url" not in args:
            raise McpError(-32602, "Provide a candidate object or a url (with optional method/inputNames).")
        candidate = {
            "url": args["url"],
            "method": args.get("method", "POST"),
            "inputNames": args.get("inputNames", []),
        }
    method = str(candidate.get("method", "POST")).upper()
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": method,
        "inputNames": candidate.get("inputNames", []),
        "sendsTraffic": False,
        "manualReproductionOutline": [
            "Confirm whether the request succeeds when the anti-CSRF token (if any) is removed or reused across sessions.",
            "Construct an off-origin auto-submitting form targeting the action with the observed field names.",
            "Verify the action is performed using only ambient session cookies (no custom headers required).",
        ],
        "expectedSignals": [
            "The state-changing action completes from an unrelated origin using only cookies.",
            "Removing or replaying a token does not change the outcome (token not server-validated).",
        ],
        "guardrails": [
            "This helper produces a manual outline only; it does not send traffic or submit any form.",
            "Validate only against explicitly authorized in-scope targets after operator approval.",
            "Do not ride a real victim session or chain CSRF testing with credential capture or phishing.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)
