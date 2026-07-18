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
from .active_probe import priority_for_score, stable_slug
from .surface_hygiene import normalize_surface_url

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_TOKEN_NAMES = {
    "csrftoken",
    "xsrftoken",
    "authenticitytoken",
    "requesttoken",
    "requestverificationtoken",
    "csrfmiddlewaretoken",
    "antiforgerytoken",
    "formtoken",
    "formkey",
    "securitytoken",
    "sectok",
}
HIGH_VALUE_ACTION_MARKERS = (
    "password", "passwd", "email", "account", "admin", "user", "profile",
    "settings", "transfer", "payment", "delete", "update", "create",
)
LOGIN_MARKERS = {"login", "signin", "signon", "session"}
RECOVERY_MARKERS = {"recover", "recovery", "forgot", "reset", "lostpassword", "forgotpassword"}
REGISTRATION_MARKERS = {"register", "registration", "signup", "createaccount", "join"}
LOGOUT_MARKERS = {"logout", "signout"}


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
    surfaces = find_surfaces(entities, min_score, args.get("workflowContexts"))
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
    reconciliation = (
        reconcile_csrf_observations(workspace_id, target, {item["candidateId"] for item in all_candidates})
        if ingestion
        else {"active": len(all_candidates), "suppressed": 0}
    )
    evidence.log_event(
        "csrf.analyze_workspace",
        f"Analyzed CSRF candidates for {workspace.normalize_target(target)}.",
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


def find_candidates(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    return find_surfaces(entities, min_score)["candidates"]


def find_surfaces(
    entities: dict[str, list[dict[str, Any]]],
    min_score: int,
    workflow_contexts: Any = None,
) -> dict[str, list[dict[str, Any]]]:
    forms = _collect_forms(entities)
    weak_samesite = _weak_samesite_observed(entities)
    candidates: dict[str, dict[str, Any]] = {}
    classifications: dict[str, dict[str, Any]] = {}
    contexts = _index_workflow_contexts(entities, workflow_contexts)
    for (method, action), form in forms.items():
        input_names = sorted(form["inputNames"])
        token_fields = [name for name in input_names if _is_token_field(name)]
        workflow_type = _classify_workflow(action, input_names)
        workflow_context = contexts.get(_form_identity(action), {})
        if token_fields:
            item = _build_classification(
                method,
                action,
                input_names,
                workflow_type,
                "recognized_token_field",
                f"Recognized anti-CSRF token field(s): {', '.join(token_fields)}.",
                token_fields=token_fields,
            )
            classifications.setdefault(item["candidateId"], item)
            continue
        disposition = _workflow_disposition(workflow_type, workflow_context, action)
        if not disposition["reportable"]:
            item = _build_classification(
                method,
                action,
                input_names,
                workflow_type,
                disposition["code"],
                disposition["reason"],
                prerequisites=disposition["prerequisites"],
            )
            classifications.setdefault(item["candidateId"], item)
            continue
        candidate = _build_candidate(
            method,
            action,
            input_names,
            weak_samesite,
            workflow_type,
            disposition,
        )
        if candidate["priorityScore"] >= min_score:
            candidates.setdefault(candidate["candidateId"], candidate)
    return {
        "candidates": sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True),
        "classifications": sorted(classifications.values(), key=lambda item: (item["workflowType"], item["url"])),
    }


def _collect_forms(entities: dict[str, list[dict[str, Any]]]) -> dict[tuple[str, str], dict[str, Any]]:
    forms: dict[tuple[str, str], dict[str, Any]] = {}
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
        record = forms.setdefault((method, action), {"inputNames": set()})
        record["inputNames"].update(names)
    # Supplement input names from normalized form parameters.
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict) or str(parameter.get("location", "")) != "form":
            continue
        method = str(parameter.get("method", "GET")).upper()
        action = str(parameter.get("url", ""))
        if method in STATE_CHANGING_METHODS and (method, action) in forms and parameter.get("name"):
            forms[(method, action)]["inputNames"].add(str(parameter["name"]))
    return forms


def _is_token_field(name: str) -> bool:
    raw = str(name or "").strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if compact in CSRF_TOKEN_NAMES:
        return True
    if raw in {"_token", "_csrf", "_xsrf", "_wpnonce", "wp_nonce"}:
        return True
    if compact.endswith("nonce") and compact not in {"announce", "prononce"}:
        return True
    return ("csrf" in compact or "xsrf" in compact or "antiforgery" in compact) and "token" in compact


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


def _form_identity(action: str) -> str:
    return normalize_surface_url(action) or str(action or "")


def _index_workflow_contexts(entities: dict[str, list[dict[str, Any]]], supplied: Any) -> dict[str, dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for observation in entities.get("observations", []):
        if isinstance(observation, dict) and observation.get("type") == "csrf_workflow_context":
            records.append(observation)
    if isinstance(supplied, list):
        records.extend(item for item in supplied if isinstance(item, dict))
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        action = record.get("url") or record.get("action") or record.get("value")
        identity = _form_identity(str(action or ""))
        if not identity:
            continue
        current = indexed.setdefault(identity, {})
        for key, value in record.items():
            if value not in (None, "", [], {}):
                current[key] = value
    return indexed


def _workflow_tokens(action: str) -> set[str]:
    path = urlsplit(action).path.lower()
    raw_tokens = {token for token in re.split(r"[^a-z0-9]+", path) if token}
    compact = re.sub(r"[^a-z0-9]+", "", path)
    return raw_tokens | ({compact} if compact else set())


def _classify_workflow(action: str, input_names: list[str]) -> str:
    tokens = _workflow_tokens(action)
    compact_inputs = {re.sub(r"[^a-z0-9]+", "", str(name).lower()) for name in input_names}
    if tokens & LOGOUT_MARKERS:
        return "logout"
    if tokens & RECOVERY_MARKERS:
        return "account_recovery"
    if tokens & REGISTRATION_MARKERS:
        return "registration"
    if tokens & LOGIN_MARKERS or ({"username", "password"} <= compact_inputs) or ({"email", "password"} <= compact_inputs):
        return "login"
    return "authenticated_state_change"


def _workflow_disposition(workflow_type: str, context: dict[str, Any], action: str) -> dict[str, Any]:
    if workflow_type == "authenticated_state_change":
        return {
            "reportable": True,
            "code": "authenticated_state_change_candidate",
            "reason": "Authenticated state-changing form has no recognized anti-CSRF token field.",
            "prerequisites": {},
        }
    if workflow_type == "logout":
        return {
            "reportable": False,
            "code": "logout_csrf_impact_gap",
            "reason": "Logout is an authentication workflow, but no concrete security impact beyond session termination is recorded.",
            "prerequisites": {"concreteUnauthorizedImpact": False},
        }
    if workflow_type == "login":
        scenario = context.get("attackerAccountScenario")
        credential_id = context.get("baselineCredentialId") or context.get("credentialId")
        approval_id = context.get("approvalId")
        baseline_approved = context.get("credentialedBaselineApproved") is True
        credential_valid = _credential_reference_valid(str(credential_id or ""), action)
        satisfied = isinstance(scenario, str) and bool(scenario.strip()) and credential_valid and bool(approval_id) and baseline_approved
        prerequisites = {
            "attackerAccountScenario": bool(isinstance(scenario, str) and scenario.strip()),
            "credentialedBaselineApproved": baseline_approved,
            "baselineCredentialId": str(credential_id or ""),
            "baselineCredentialReferenceValid": credential_valid,
            "approvalId": str(approval_id or ""),
        }
        return {
            "reportable": satisfied,
            "code": "login_csrf_candidate" if satisfied else "login_csrf_prerequisite_gap",
            "reason": "Login form lacks a recognized token and has an approved attacker-account/session-switch baseline."
            if satisfied
            else "Untokenized login is not reportable without a credible attacker-account/session-switch scenario and an approved credentialed baseline reference.",
            "prerequisites": prerequisites,
        }
    impact = context.get("unauthorizedStateChangeImpact")
    evidence_ids = context.get("impactEvidenceIds") if isinstance(context.get("impactEvidenceIds"), list) else []
    satisfied = isinstance(impact, str) and bool(impact.strip()) and bool(evidence_ids)
    workflow_label = "recovery" if workflow_type == "account_recovery" else "registration"
    return {
        "reportable": satisfied,
        "code": f"{workflow_label}_csrf_candidate" if satisfied else f"{workflow_label}_csrf_impact_gap",
        "reason": f"Untokenized {workflow_label} workflow has a concrete unauthorized state-change impact with evidence."
        if satisfied
        else f"Untokenized {workflow_label} workflow is not reportable without a concrete unauthorized state-change impact and evidence reference.",
        "prerequisites": {
            "unauthorizedStateChangeImpact": bool(isinstance(impact, str) and impact.strip()),
            "impactEvidenceIds": [str(item) for item in evidence_ids if item],
        },
    }


def _credential_reference_valid(credential_id: str, action: str) -> bool:
    if not credential_id:
        return False
    try:
        record = credentials.get_credential(credential_id)
    except McpError:
        return False
    host = (urlsplit(action).hostname or "").lower()
    return bool(host and host in {str(item).lower() for item in record.get("scopes", [])})


def _build_candidate(
    method: str,
    action: str,
    input_names: list[str],
    weak_samesite: bool,
    workflow_type: str,
    disposition: dict[str, Any],
) -> dict[str, Any]:
    path = urlsplit(action).path.lower()
    score = 55 if workflow_type in {"login", "account_recovery", "registration"} else 40
    reasons = [str(disposition["reason"])]
    if any(marker in path for marker in HIGH_VALUE_ACTION_MARKERS):
        score += 20
        reasons.append("Form action targets a sensitive account or administrative workflow.")
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
        "workflowType": workflow_type,
        "workflowDisposition": disposition["code"],
        "prerequisites": disposition["prerequisites"],
        "isReportable": True,
        "analysisEligible": True,
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reasons": reasons,
        "testPlanSummary": _test_plan_summary(workflow_type),
    }


def _build_classification(
    method: str,
    action: str,
    input_names: list[str],
    workflow_type: str,
    code: str,
    reason: str,
    *,
    token_fields: list[str] | None = None,
    prerequisites: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "candidateId": f"csrf_{stable_slug(method)}_{stable_slug(action)}_{stable_slug(code)}"[:170],
        "type": "csrf_form_classification",
        "url": action,
        "method": method,
        "location": "form",
        "inputNames": input_names,
        "tokenFields": token_fields or [],
        "workflowType": workflow_type,
        "workflowDisposition": code,
        "prerequisites": prerequisites or {},
        "priority": "info",
        "priorityScore": 0,
        "confidence": "high",
        "reasons": [reason],
        "isReportable": False,
        "analysisEligible": False,
    }


def _test_plan_summary(workflow_type: str) -> str:
    if workflow_type == "login":
        return "Manual validation only: use the approved attacker-account baseline to verify a session switch without capturing credentials."
    if workflow_type in {"account_recovery", "registration"}:
        return "Manual validation only: verify the recorded unauthorized state-change impact without affecting third-party accounts."
    return "Manual validation only: confirm the form lacks server-validated anti-CSRF protection before reporting."


def build_result(
    workspace_id: str,
    target: str,
    candidates: list[dict[str, Any]],
    classifications: list[dict[str, Any]],
    context: dict[str, Any],
) -> AdapterResult:
    candidate_observations = [
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
                "workflowType": candidate.get("workflowType", "authenticated_state_change"),
                "workflowDisposition": candidate.get("workflowDisposition", ""),
                "prerequisites": candidate.get("prerequisites", {}),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    classification_observations = [
        {
            "type": "csrf_form_classification",
            "value": item["url"],
            "url": item["url"],
            "method": item["method"],
            "location": "form",
            "inputNames": item["inputNames"],
            "tokenFields": item.get("tokenFields", []),
            "workflowType": item["workflowType"],
            "workflowDisposition": item["workflowDisposition"],
            "prerequisites": item.get("prerequisites", {}),
            "confidence": "high",
            "priority": "info",
            "priorityScore": 0,
            "reason": item["reasons"][0],
            "reasons": item["reasons"],
            "candidateId": item["candidateId"],
            "isReportable": False,
            "analysisEligible": False,
            "tags": ["csrf", "workflow-classification"],
        }
        for item in classifications
    ]
    observations = [*candidate_observations, *classification_observations]
    return AdapterResult(
        adapter="csrf",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} CSRF candidate forms and {len(classifications)} non-reportable workflow classifications.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Candidate-only; absence of a recognized token field is not proof of exploitable CSRF.",
            "Token detection is name-based; double-submit-cookie or header-token schemes may not be visible passively.",
            "Login, recovery, and registration forms remain non-reportable until their workflow-specific prerequisites are recorded.",
        ],
        metadata={"observationCount": len(observations), "classificationCount": len(classifications)},
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
    workflow_type = str(candidate.get("workflowType", "authenticated_state_change"))
    if workflow_type == "login":
        outline = [
            "Confirm the recorded approval and credential reference for the attacker-controlled baseline account.",
            "Using only the approved test accounts, determine whether an off-origin login changes the victim browser session into the attacker-controlled account.",
            "Verify the documented session-switch/account-confusion impact without collecting credentials or involving a third-party session.",
        ]
        expected_signals = [
            "The browser session changes to the approved attacker-controlled account after the cross-origin login submission.",
            "The server does not require a validated anti-CSRF token or equivalent login-intent binding.",
        ]
    elif workflow_type in {"account_recovery", "registration"}:
        outline = [
            "Review the recorded unauthorized state-change impact and its evidence references before testing.",
            "Construct an off-origin form using only approved test identities and the observed field names.",
            "Verify only the recorded recovery/registration impact; stop if the flow would affect an unrelated account or send external messages.",
        ]
        expected_signals = [
            "The recorded unauthorized recovery/registration state change completes from an unrelated origin.",
            "The server does not require a validated anti-CSRF token or equivalent user-intent proof.",
        ]
    else:
        outline = [
            "Confirm whether the request succeeds when the anti-CSRF token (if any) is removed or reused across sessions.",
            "Construct an off-origin auto-submitting form targeting the action with the observed field names.",
            "Verify the action is performed using only ambient session cookies (no custom headers required).",
        ]
        expected_signals = [
            "The state-changing action completes from an unrelated origin using only cookies.",
            "Removing or replaying a token does not change the outcome (token not server-validated).",
        ]
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": method,
        "inputNames": candidate.get("inputNames", []),
        "workflowType": workflow_type,
        "prerequisites": candidate.get("prerequisites", {}),
        "sendsTraffic": False,
        "manualReproductionOutline": outline,
        "expectedSignals": expected_signals,
        "guardrails": [
            "This helper produces a manual outline only; it does not send traffic or submit any form.",
            "Validate only against explicitly authorized in-scope targets after operator approval.",
            "Do not ride a real victim session or chain CSRF testing with credential capture or phishing.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def reconcile_csrf_observations(workspace_id: str, target: str, active_candidate_ids: set[str]) -> dict[str, int]:
    path = workspace.target_entity_path(workspace_id, target, "observations")
    observations = workspace._read_json(path, [])
    if not isinstance(observations, list):
        return {"active": len(active_candidate_ids), "suppressed": 0}
    suppressed = 0
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("type") != "csrf_candidate":
            continue
        if str(observation.get("candidateId", "")) in active_candidate_ids:
            continue
        if observation.get("isReportable") is False:
            continue
        observation["isReportable"] = False
        observation["analysisEligible"] = False
        observation["reportableDecision"] = {
            "isReportable": False,
            "reviewer": "csrf_workflow_reconciliation",
            "reason": "Candidate is absent from the current token-aware, workflow-specific CSRF snapshot.",
        }
        suppressed += 1
    if suppressed:
        workspace._write_json(path, observations)
    return {"active": len(active_candidate_ids), "suppressed": suppressed}
