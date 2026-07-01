# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from uuid import uuid4

from ... import __version__ as SYNAPSE_VERSION
from ...core import evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, compare_http_responses, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import redact_headers, stable_slug, store_http_exchange_evidence
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url


# Roles that denote an unauthenticated actor; contexts with these roles never
# require a credentialId for replay.
ANONYMOUS_ROLES = {"anonymous", "guest", "public", "unauthenticated"}

# User-Agent for access-control replay traffic, tied to the package version.
USER_AGENT = f"Synapse-MCP/{SYNAPSE_VERSION}"

# Total wall-clock budget for a replay across all contexts. Each context still
# uses its own fresh client so cookies never leak between authorization
# contexts; the budget bounds total time so a few slow contexts cannot push the
# call past the MCP tool deadline. Override per call with totalBudgetSeconds.
DEFAULT_REPLAY_BUDGET_SECONDS = 30.0

# Replay callers must never pass secret-bearing headers directly; secrets flow
# through credentialId-bound contexts. These benign headers are always allowed.
ALLOWED_DIRECT_HEADERS = {"accept", "content-type", "user-agent", "origin", "referer"}
BLOCKED_HEADER_MARKERS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "session",
    "credential",
    "jwt",
    "csrf",
    "api-key",
    "x-api-key",
)
ERROR_JSON_KEY_MARKERS = {"error", "errors", "err", "exception", "fault", "message", "mensaje", "codigo", "code"}
ERROR_JSON_VALUE_MARKERS = (
    "error",
    "err_",
    "cam_err",
    "missing",
    "invalid",
    "required",
    "failed",
    "failure",
    "denied",
    "unauthorized",
    "forbidden",
    "not found",
    "exception",
    "faltante",
    "invalido",
    "inválido",
)
DATA_BEARING_JSON_KEYS = {
    "data",
    "result",
    "results",
    "items",
    "records",
    "rows",
    "content",
    "payload",
    "object",
    "user",
    "account",
    "tenant",
    "permissions",
    "roles",
}
SUCCESS_JSON_KEYS = {"success", "ok", "authenticated", "authorized", "valid"}
SUCCESS_STATUS_VALUES = {"ok", "success", "completed", "complete", "active", "valid", "authorized"}


ID_NAME_TO_OBJECT = {
    "id": "object",
    "uuid": "object",
    "guid": "object",
    "user_id": "user",
    "userid": "user",
    "uid": "user",
    "account_id": "account",
    "customer_id": "customer",
    "client_id": "client",
    "tenant_id": "tenant",
    "org_id": "organization",
    "organization_id": "organization",
    "project_id": "project",
    "document_id": "document",
    "doc_id": "document",
    "invoice_id": "invoice",
    "order_id": "order",
    "file_id": "file",
}
RESOURCE_SEGMENTS = {
    "users": "user",
    "user": "user",
    "accounts": "account",
    "account": "account",
    "customers": "customer",
    "clients": "client",
    "tenants": "tenant",
    "orgs": "organization",
    "organizations": "organization",
    "projects": "project",
    "documents": "document",
    "docs": "document",
    "invoices": "invoice",
    "orders": "order",
    "basket": "basket",
    "baskets": "basket",
    "cart": "basket",
    "carts": "basket",
    "files": "file",
    "admin": "admin",
}
FUNCTION_PATH_MARKERS = ("admin", "manage", "settings", "role", "permission", "invite", "export", "delete", "upload", "billing")
API_COLLECTION_PREFIXES = {"api", "rest"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("access_control"), indent=2)


def identify_objects(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 100))
    min_score = int(args.get("minScore", 25))
    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    entities = workspace._load_target_entities(wid, host)
    objects = extract_object_identifiers(entities, min_score)[:max_candidates]
    stored = merge_access_control_items(wid, host, "objects", objects, "objectId")
    observations = [
        candidate_observation(
            candidate_type="access_control_object_candidate",
            value=item["endpointPattern"],
            url=item["url"],
            method=item["method"],
            parameter=item.get("identifierName", ""),
            location=item["location"],
            confidence=item["confidence"],
            priority=item["priority"],
            priority_score=item["priorityScore"],
            reason=item["reason"],
            tags=["access-control", item["objectType"], item["testClass"]],
            metadata={
                "objectId": item["objectId"],
                "objectType": item["objectType"],
                "identifierName": item["identifierName"],
                "identifierValueShape": item["identifierValueShape"],
                "endpointPattern": item["endpointPattern"],
                "testClass": item["testClass"],
            },
        )
        for item in objects
    ]
    result = AdapterResult(
        adapter="access_control",
        mode="passive_analysis",
        workspace_id=wid,
        target=host,
        summary=f"Identified {len(objects)} access-control object/function candidates.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Object values are reduced to value shapes and endpoint patterns.",
            "Request replay is available only through access_control.execute_matrix_test with explicit operator approval.",
        ],
    )
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            wid,
            host,
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps(result.as_ingest_payload(), indent=2, ensure_ascii=False),
            {"adapter": "access_control", "objectCount": len(objects)},
        )
    evidence.log_event(
        "access_control.identify_objects",
        f"Identified {len(objects)} access-control candidates for {host}.",
        {"workspaceId": wid, "target": host, "objectCount": len(objects), "ingested": bool(ingestion)},
    )
    return json.dumps(
        {
            **result.as_ingest_payload(),
            "objectCount": len(objects),
            "objects": objects,
            "accessControlStore": stored,
            **({"ingestion": ingestion} if ingestion else {}),
        },
        indent=2,
    )


def record_context(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    context_id = stable_slug(args.get("contextId") or args.get("label") or args.get("role") or "context")
    context = {
        "contextId": context_id,
        "label": args.get("label", context_id),
        "role": args.get("role", "unknown"),
        "userType": args.get("userType", ""),
        "credentialId": args.get("credentialId", ""),
        "authState": args.get("authState", "authenticated" if args.get("credentialId") else "unknown"),
        "notes": args.get("notes", ""),
        "observedEndpointPatterns": args.get("observedEndpointPatterns", []),
        "ownedObjectTypes": args.get("ownedObjectTypes", []),
        "metadata": args.get("metadata", {}),
    }
    stored = merge_access_control_items(wid, host, "contexts", [context], "contextId")
    evidence.log_event(
        "access_control.record_context",
        f"Recorded access-control context {context_id} for {host}.",
        {"workspaceId": wid, "target": host, "contextId": context_id, "role": context["role"], "credentialId": context["credentialId"]},
    )
    return json.dumps({"context": context, "accessControlStore": stored}, indent=2)


def build_test_matrix(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    if args.get("refreshObjects", True):
        entities = workspace._load_target_entities(wid, host)
        merge_access_control_items(wid, host, "objects", extract_object_identifiers(entities, int(args.get("minScore", 25))), "objectId")
    objects = read_access_control_items(wid, host, "objects")
    contexts = read_access_control_items(wid, host, "contexts")
    if args.get("contexts"):
        contexts = [normalize_context(item) for item in args["contexts"] if isinstance(item, dict)]
        merge_access_control_items(wid, host, "contexts", contexts, "contextId")
    matrix = create_matrix(objects, contexts)
    stored = merge_access_control_items(wid, host, "matrix", matrix, "matrixId")
    observations = [
        candidate_observation(
            candidate_type="access_control_test_candidate",
            value=item["endpointPattern"],
            method=item["method"],
            confidence="medium",
            priority=item["riskTier"],
            priority_score={"low": 45, "medium": 70, "high": 85}.get(item["riskTier"], 55),
            reason=item["reason"],
            tags=["access-control", item["testClass"].lower(), item["objectType"]],
            metadata={
                "matrixId": item["matrixId"],
                "testClass": item["testClass"],
                "objectType": item["objectType"],
                "requiredContexts": item["requiredContexts"],
                "requiresConfirmation": item["requiresConfirmation"],
            },
        )
        for item in matrix
    ]
    result = AdapterResult(
        adapter="access_control",
        mode="test_planning",
        workspace_id=wid,
        target=host,
        summary=f"Built {len(matrix)} access-control matrix entries.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=["Matrix entries are planned tests until access_control.execute_matrix_test is run with explicit operator approval."],
        metadata={"contextCount": len(contexts), "objectCount": len(objects)},
    )
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            wid,
            host,
            "adapter_result",
            "test_planning",
            "json",
            json.dumps(result.as_ingest_payload(), indent=2, ensure_ascii=False),
            {"adapter": "access_control", "matrixCount": len(matrix)},
        )
    evidence.log_event(
        "access_control.build_test_matrix",
        f"Built {len(matrix)} access-control matrix entries for {host}.",
        {"workspaceId": wid, "target": host, "matrixCount": len(matrix), "contextCount": len(contexts), "ingested": bool(ingestion)},
    )
    return json.dumps(
        {
            **result.as_ingest_payload(),
            "matrixCount": len(matrix),
            "matrix": matrix,
            "contexts": contexts,
            "missingInformation": missing_information(contexts) + matrix_missing_information(contexts, matrix),
            "accessControlStore": stored,
            **({"ingestion": ingestion} if ingestion else {}),
        },
        indent=2,
    )


def plan_tests(args: dict[str, Any]) -> str:
    entry = args.get("matrixEntry") if isinstance(args.get("matrixEntry"), dict) else None
    if entry is None:
        if args.get("matrixId"):
            entries = read_access_control_items(workspace.normalize_workspace_id(args["workspaceId"]), workspace.normalize_target(args["target"]), "matrix")
            entry = next((item for item in entries if item.get("matrixId") == args["matrixId"]), None)
        if entry is None:
            entry = {
                "matrixId": args.get("matrixId", ""),
                "endpointPattern": args.get("endpointPattern", ""),
                "method": args.get("method", "GET"),
                "objectType": args.get("objectType", "object"),
                "testClass": args.get("testClass", "BOLA"),
                "requiredContexts": args.get("requiredContexts", ["user_a", "user_b"]),
                "riskTier": args.get("riskTier", "medium"),
                "reason": args.get("reason", "Access-control test planning requested."),
            }
    plan = {
        "matrixId": entry.get("matrixId", ""),
        "testClass": entry.get("testClass", "BOLA"),
        "endpointPattern": entry.get("endpointPattern", ""),
        "method": entry.get("method", "GET"),
        "objectType": entry.get("objectType", "object"),
        "requiredContexts": entry.get("requiredContexts", []),
        "riskTier": entry.get("riskTier", "medium"),
        "requiresConfirmation": True,
        "testIdea": entry.get("testIdea", ""),
        "operatorInputsNeeded": [
            "At least two authorized identity contexts with clear labels, roles, and credential IDs where applicable.",
            "Object ownership mapping for which user owns which object instance.",
            "Explicit approval for any future request replay, including endpoint pattern, contexts, and object substitutions.",
        ],
        "safeExecutionModel": [
            "This planner does not send traffic; replay requires access_control.execute_matrix_test with confirm=true.",
            "Approved active validation compares status, redirects, content type, body length, JSON key overlap, body similarity, and sensitive marker deltas.",
            "Do not mutate state-changing endpoints unless the operator approves that exact workflow and rollback plan.",
        ],
        "comparisonHelper": "synapse_mcp.core.http.compare.compare_http_responses",
        "reason": entry.get("reason", ""),
    }
    return json.dumps(plan, indent=2)


def execute_matrix_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running access-control replay requires confirm=true.")
    workspace_id = args["workspaceId"]
    target = args["target"]
    wid = workspace.normalize_workspace_id(workspace_id)
    model_host = workspace.normalize_target(target)
    matrix_entry = resolve_matrix_entry(args, wid, model_host)
    method = str(args.get("method") or matrix_entry.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"} and args.get("allowStateChanging") is not True:
        raise McpError(-32001, "State-changing access-control replay requires allowStateChanging=true and explicit operator approval.")
    request_url = str(args.get("requestUrl") or matrix_entry.get("requestUrl") or "")
    if not request_url:
        raise McpError(-32602, "requestUrl is required for access-control replay.")
    scope_result = require_in_scope(request_url, wid)
    request_host = scope_result["host"]
    contexts = resolve_replay_contexts(args, wid, model_host, matrix_entry)
    if not contexts:
        raise McpError(-32602, "At least one replay context is required.")
    replay_missing_information = matrix_entry_missing_information(contexts, matrix_entry)
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    budget_seconds = float(args.get("totalBudgetSeconds", DEFAULT_REPLAY_BUDGET_SECONDS))
    if budget_seconds <= 0:
        budget_seconds = DEFAULT_REPLAY_BUDGET_SECONDS
    # Redirects stay visible by default so a redirect-to-login can be classified
    # as denied access instead of being followed to a 200 login page.
    policy = HttpClientPolicy.from_args({"followRedirects": False, **args}, timeout_seconds=timeout)
    body = args.get("body")
    json_body = args.get("jsonBody")
    extra_headers = args.get("headers", {})
    replays = []
    full_responses = []
    executed_contexts: list[dict[str, Any]] = []
    skipped_contexts: list[str] = []
    budget_exceeded = False
    allow_anonymous = bool(args.get("allowAnonymousContexts", False))
    # Each context uses its own fresh client (no shared cookie jar across
    # authorization contexts); the budget bounds total wall-clock instead.
    deadline = time.monotonic() + budget_seconds
    for context in contexts:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0.1:
            budget_exceeded = True
            skipped_contexts.append(str(context.get("contextId", "")))
            continue
        context = prepare_replay_context_auth(context, request_url, allow_anonymous=allow_anonymous)
        built = build_replay_request(
            request_url,
            method,
            context.get("credentialId", ""),
            body=body,
            json_body=json_body,
            extra_headers=extra_headers,
            substitutions=context.get("substitutions", args.get("substitutions", {})),
        )
        response_payload = http_client.send(
            HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            policy=HttpClientPolicy(
                backend=policy.backend,
                timeout_seconds=min(policy.timeout_seconds, remaining_seconds),
                max_body_bytes=policy.max_body_bytes,
                follow_redirects=policy.follow_redirects,
                proxy_url=policy.proxy_url,
                verify_tls=policy.verify_tls,
                http2=policy.http2,
            ),
        ).as_dict()
        if time.monotonic() >= deadline:
            budget_exceeded = True
        exchange_evidence = store_http_exchange_evidence(
            wid,
            request_host,
            "access_control_http_exchange",
            request={key: value for key, value in built.items() if not key.startswith("_")},
            response=response_payload,
            metadata={
                "adapter": "access_control",
                "target": request_url,
                "modelHost": model_host,
                "matrixId": matrix_entry.get("matrixId", ""),
                "contextId": context.get("contextId", ""),
                "role": context.get("role", ""),
                "expectedAccess": context.get("expectedAccess"),
                "approval": approval,
            },
        )
        full_responses.append({"context": context, "response": response_payload})
        executed_contexts.append(context)
        replays.append(
            {
                "contextId": context["contextId"],
                "label": context.get("label", context["contextId"]),
                "role": context.get("role", "unknown"),
                "expectedAccess": context.get("expectedAccess"),
                "credentialId": context.get("credentialId", ""),
                "request": {key: value for key, value in built.items() if key != "headers" and not key.startswith("_")},
                "requestHeaders": redact_headers(built["headers"]),
                "response": safe_response_summary(response_payload),
                "exchangeEvidence": exchange_evidence,
            }
        )
    comparisons, possible_broken = build_replay_comparisons(full_responses, matrix_entry)
    assessment = "possible_broken_access_control" if possible_broken else "inconclusive"
    assessment_reason = replay_missing_information[0] if replay_missing_information and not possible_broken else ""
    request_fingerprint = replay_request_fingerprint(matrix_entry, method, request_url, body, json_body, contexts)
    replay_fingerprint = stable_id(request_fingerprint, approval.get("approvalId", ""))
    replay_id = f"acr_{replay_fingerprint}_{uuid4().hex[:8]}"
    replay_record = {
        "replayId": replay_id,
        "requestFingerprint": request_fingerprint,
        "replayFingerprint": replay_fingerprint,
        "matrixId": matrix_entry.get("matrixId", ""),
        "testClass": matrix_entry.get("testClass", "BOLA"),
        "endpointPattern": matrix_entry.get("endpointPattern", ""),
        "method": method,
        "requestUrl": request_url,
        "host": request_host,
        "modelHost": model_host,
        "assessment": assessment,
        "approval": approval,
        "contexts": [{key: value for key, value in context.items() if key != "substitutions"} for context in contexts],
        "replays": replays,
        "comparisons": comparisons,
        "missingInformation": replay_missing_information,
        "assessmentReason": assessment_reason,
        "budgetSeconds": budget_seconds,
        "budgetExceeded": budget_exceeded,
        "skippedContexts": skipped_contexts,
    }
    store = merge_access_control_items(wid, request_host, "replays", [replay_record], "replayId")
    observations = []
    if possible_broken:
        observations.append(
            candidate_observation(
                candidate_type="possible_broken_access_control",
                value=matrix_entry.get("endpointPattern", request_url),
                method=method,
                confidence="medium",
                priority="high",
                priority_score=85,
                reason="Approved cross-context replay returned similar successful content to a context expected to be denied.",
                tags=["access-control", str(matrix_entry.get("testClass", "BOLA")).lower(), matrix_entry.get("objectType", "object")],
                metadata={
                    "replayId": replay_id,
                    "requestFingerprint": request_fingerprint,
                    "matrixId": matrix_entry.get("matrixId", ""),
                    "testClass": matrix_entry.get("testClass", "BOLA"),
                    "requestUrl": request_url,
                },
            )
        )
    result = AdapterResult(
        adapter="access_control",
        mode="active_testing",
        workspace_id=wid,
        target=request_host,
        summary=f"Access-control replay assessment: {assessment}.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=["Replay evidence stores sanitized response summaries, not full response bodies."],
        metadata={
            "replayId": replay_id,
            "requestFingerprint": request_fingerprint,
            "matrixId": matrix_entry.get("matrixId", ""),
            "assessment": assessment,
            "modelHost": model_host,
        },
    )
    ingestion = workspace.ingest_data(
        wid,
        request_host,
        "adapter_result",
        "active_validation",
        "json",
        json.dumps(result.as_ingest_payload(), indent=2, ensure_ascii=False),
        {
            "adapter": "access_control",
            "replayId": replay_id,
            "requestFingerprint": request_fingerprint,
            "matrixId": matrix_entry.get("matrixId", ""),
            "approval": approval,
            "modelHost": model_host,
        },
    )
    action = workspace.record_action(
        wid,
        request_host,
        {
            "type": "active_validation",
            "tool": "access_control.execute_matrix_test",
            "target": request_url,
            "modelTarget": target,
            "modelHost": model_host,
            "method": method,
            "matrixId": matrix_entry.get("matrixId", ""),
            "replayId": replay_id,
            "assessment": assessment,
            "requestFingerprint": request_fingerprint,
            "exchangeEvidenceIds": [item["exchangeEvidence"]["evidenceId"] for item in replays if item.get("exchangeEvidence")],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "access_control.execute_matrix_test",
        f"Ran approved access-control replay for {request_host} with assessment {assessment}.",
        {
            "workspaceId": wid,
            "target": request_url,
            "host": request_host,
            "modelHost": model_host,
            "matrixId": matrix_entry.get("matrixId", ""),
            "replayId": replay_id,
            "requestFingerprint": request_fingerprint,
            "assessment": assessment,
            "approval": approval,
        },
    )
    return json.dumps({"replay": replay_record, "accessControlStore": store, "ingestion": ingestion, "action": action}, indent=2)


def extract_object_identifiers(entities: dict[str, list[dict[str, Any]]], min_score: int) -> list[dict[str, Any]]:
    endpoints_by_url = {item.get("url"): item for item in entities.get("endpoints", []) if isinstance(item, dict)}
    objects: dict[str, dict[str, Any]] = {}
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        for item in objects_from_endpoint(endpoint):
            if item["priorityScore"] >= min_score:
                objects[item["objectId"]] = item
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        endpoint = endpoints_by_url.get(parameter.get("url"), {})
        item = object_from_parameter(parameter, endpoint)
        if item and item["priorityScore"] >= min_score:
            objects[item["objectId"]] = item
    return sorted(objects.values(), key=lambda item: item["priorityScore"], reverse=True)


def objects_from_endpoint(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    url = normalize_surface_url(endpoint.get("url", ""))
    if not url:
        return []
    if is_candidate_noise_url(url):
        return []
    endpoint = {**endpoint, "url": url}
    parsed = urlsplit(url)
    method = str(endpoint.get("method", "GET")).upper()
    segments = [segment for segment in parsed.path.split("/") if segment]
    found = []
    for index, segment in enumerate(segments):
        shape = value_shape(segment)
        if shape not in {"numeric", "uuid", "objectid"}:
            continue
        object_type = object_type_from_segment(segments[index - 1] if index else "")
        endpoint_pattern = endpoint_pattern_for_url(url, index)
        found.append(
            build_object_candidate(
                url=url,
                method=method,
                endpoint_pattern=endpoint_pattern,
                object_type=object_type,
                identifier_name=f"{object_type}_id" if object_type != "object" else "id",
                identifier_value_shape=shape,
                location="path",
                reason=f"Path contains {object_type}-like {shape} identifier.",
                score=75 if object_type != "object" else 60,
                endpoint=endpoint,
            )
        )
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        item = object_from_name_value(url, method, name, value, "query", endpoint)
        if item:
            found.append(item)
    if is_function_endpoint(endpoint):
        found.append(
            build_object_candidate(
                url=url,
                method=method,
                endpoint_pattern=endpoint_pattern_for_url(url),
                object_type=function_object_type(endpoint),
                identifier_name="function",
                identifier_value_shape="none",
                location="endpoint",
                reason="Endpoint path or method suggests privileged functionality that should be tested across roles.",
                score=65,
                endpoint=endpoint,
                test_class="BFLA",
            )
        )
    collection = collection_object_from_endpoint(endpoint, segments)
    if collection:
        found.append(collection)
    return found


def collection_object_from_endpoint(endpoint: dict[str, Any], segments: list[str]) -> dict[str, Any] | None:
    method = str(endpoint.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"} or len(segments) < 2:
        return None
    prefix = segments[0].lower()
    if prefix not in API_COLLECTION_PREFIXES:
        return None
    resource_segment = segments[-1]
    if value_shape(resource_segment) in {"numeric", "uuid", "objectid"}:
        return None
    object_type = object_type_from_segment(resource_segment)
    if object_type == "object":
        return None
    url = str(endpoint.get("url", ""))
    return build_object_candidate(
        url=url,
        method=method,
        endpoint_pattern=endpoint_pattern_for_url(url),
        object_type=object_type,
        identifier_name=f"{object_type}_collection",
        identifier_value_shape="collection",
        location="endpoint",
        reason=f"API collection endpoint exposes {object_type} resources and should be compared across roles.",
        score=75,
        endpoint=endpoint,
        test_class="BFLA",
    )


def object_from_parameter(parameter: dict[str, Any], endpoint: dict[str, Any]) -> dict[str, Any] | None:
    name = str(parameter.get("name", "")).strip()
    url = normalize_surface_url(parameter.get("url", ""))
    if not name or not url:
        return None
    if is_candidate_noise_url(url):
        return None
    return object_from_name_value(
        url,
        str(parameter.get("method", "") or endpoint.get("method", "GET")).upper(),
        name,
        str(parameter.get("value", "") or parameter.get("valuePreview", "")),
        str(parameter.get("location", "query")),
        endpoint,
    )


def object_from_name_value(url: str, method: str, name: str, value: str, location: str, endpoint: dict[str, Any]) -> dict[str, Any] | None:
    normalized_name = normalize_identifier_name(name)
    object_type = ID_NAME_TO_OBJECT.get(normalized_name)
    shape = value_shape(value) if value else "unknown"
    if not object_type and not normalized_name.endswith("_id"):
        return None
    if not object_type:
        object_type = normalized_name.rsplit("_id", 1)[0] or "object"
    score = 70 if object_type != "object" else 55
    if shape in {"numeric", "uuid", "objectid"}:
        score += 10
    if location in {"json", "body", "form"}:
        score += 5
    return build_object_candidate(
        url=url,
        method=method,
        endpoint_pattern=endpoint_pattern_for_url(url),
        object_type=object_type,
        identifier_name=normalized_name,
        identifier_value_shape=shape,
        location=location,
        reason=f"{location} parameter name suggests a {object_type} object identifier.",
        score=min(score, 100),
        endpoint=endpoint,
    )


def build_object_candidate(
    *,
    url: str,
    method: str,
    endpoint_pattern: str,
    object_type: str,
    identifier_name: str,
    identifier_value_shape: str,
    location: str,
    reason: str,
    score: int,
    endpoint: dict[str, Any],
    test_class: str = "BOLA",
) -> dict[str, Any]:
    if test_class == "BOLA" and object_type in {"tenant", "organization"}:
        test_class = "BOPLA"
    state_changing = method in {"POST", "PUT", "PATCH", "DELETE"} or bool(endpoint.get("stateChanging"))
    if state_changing and test_class == "BOLA":
        score = min(score + 10, 100)
    object_id = stable_id(method, endpoint_pattern, object_type, identifier_name, location, test_class)
    return {
        "objectId": object_id,
        "endpointId": stable_id(method, url),
        "url": url,
        "method": method,
        "endpointPattern": endpoint_pattern,
        "objectType": object_type,
        "identifierName": identifier_name,
        "identifierValueShape": identifier_value_shape,
        "location": location,
        "testClass": test_class,
        "stateChanging": state_changing,
        "authRequiredLikely": auth_required_likely(endpoint),
        "priority": priority_for_score(score),
        "priorityScore": score,
        "confidence": "medium" if score >= 70 else "low",
        "reason": reason,
    }


def create_matrix(objects: list[dict[str, Any]], contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    context_ids = [item["contextId"] for item in contexts if item.get("contextId")]
    required_contexts = default_required_contexts(contexts)
    privileged_contexts = [item["contextId"] for item in contexts if _context_is_privileged(item)]
    standard_contexts = [
        item["contextId"]
        for item in contexts
        if item.get("contextId") and _context_is_authenticated(item) and not _context_is_privileged(item)
    ]
    matrix: dict[str, dict[str, Any]] = {}
    for item in objects:
        test_class = item.get("testClass", "BOLA")
        if test_class == "BFLA" and privileged_contexts:
            required = [privileged_contexts[0], (standard_contexts[0] if standard_contexts else next((ctx for ctx in context_ids if ctx not in privileged_contexts), "standard_user"))]
        else:
            required = required_contexts
        risk_tier = risk_for_object(item)
        key = stable_id(item.get("endpointPattern", ""), item.get("method", ""), item.get("objectType", ""), test_class)
        matrix[key] = {
            "matrixId": f"acm_{key}",
            "endpointPattern": item.get("endpointPattern", ""),
            "method": item.get("method", "GET"),
            "objectType": item.get("objectType", "object"),
            "identifierName": item.get("identifierName", ""),
            "identifierValueShape": item.get("identifierValueShape", "unknown"),
            "testClass": test_class,
            "requiredContexts": required,
            "testIdea": test_idea(test_class, item),
            "riskTier": risk_tier,
            "requiresConfirmation": True,
            "stateChanging": bool(item.get("stateChanging")),
            "authRequiredLikely": bool(item.get("authRequiredLikely")),
            "sourceObjectIds": sorted(set(matrix.get(key, {}).get("sourceObjectIds", []) + [item.get("objectId", "")])),
            "reason": matrix_reason(test_class, item, required),
        }
    return sorted(matrix.values(), key=lambda item: {"high": 3, "medium": 2, "low": 1}.get(item["riskTier"], 0), reverse=True)


def default_required_contexts(contexts: list[dict[str, Any]]) -> list[str]:
    authenticated = [item["contextId"] for item in contexts if item.get("contextId") and _context_is_authenticated(item)]
    if len(authenticated) >= 2:
        return authenticated[:2]
    context_ids = [item["contextId"] for item in contexts if item.get("contextId")]
    if len(context_ids) >= 2:
        return context_ids[:2]
    return ["user_a", "user_b"]


def _context_role(context: dict[str, Any]) -> str:
    return str(context.get("role", "") or "").strip().lower()


def _context_is_anonymous(context: dict[str, Any]) -> bool:
    return _context_role(context) in ANONYMOUS_ROLES or str(context.get("authState", "")).strip().lower() == "anonymous" or str(context.get("contextId", "")).strip().lower() in {"anon", "anonymous"}


def _context_is_authenticated(context: dict[str, Any]) -> bool:
    if _context_is_anonymous(context):
        return False
    return bool(context.get("credentialId")) or str(context.get("authState", "")).strip().lower() == "authenticated"


def _context_is_privileged(context: dict[str, Any]) -> bool:
    return _context_role(context) in {"admin", "owner", "manager", "privileged", "administrator"}


def _default_expected_access(context: dict[str, Any], matrix_entry: dict[str, Any]) -> bool | None:
    """Derive the allowed/denied baseline from identity, never from array position.

    Anonymous contexts are expected to be denied a protected resource. For function-level
    (BFLA) tests, privilege decides: privileged roles are expected to be allowed, others
    denied. For object-level (BOLA/BOPLA) tests, access depends on ownership of the specific
    object, which is not asserted at the endpoint-pattern level, so the baseline is left
    unknown (``None``) rather than fabricated from the order contexts happen to be listed in.
    Marking "index 0 = allowed, the rest denied" is the positional anti-pattern access-control
    contract 3.5 prohibits and is what produced false BOLA positives on self-scoped endpoints.
    """
    if _is_explicit_anonymous(context):
        return False
    test_class = str(matrix_entry.get("testClass", "") or "").upper()
    if test_class == "BFLA":
        return _context_is_privileged(context)
    return None


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="bola_cross_object_owner_comparison",
            description="Compare access to same endpoint pattern across two authorized user contexts and object ownership mappings.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="medium",
        ),
        RecommendedTest(
            name="bopla_property_or_tenant_boundary_review",
            description="Review tenant, organization, and submitted object-property boundaries before approved replay.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="medium",
        ),
        RecommendedTest(
            name="bfla_role_function_matrix",
            description="Compare privileged and non-privileged context access to role/function endpoints.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="medium",
        ),
    ]


def access_control_dir(workspace_id: str, target: str):
    path = workspace.target_model_dir(workspace_id, target, "access-control")
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_access_control_items(workspace_id: str, target: str, name: str) -> list[dict[str, Any]]:
    path = access_control_dir(workspace_id, target) / f"{name}.json"
    payload = workspace._read_json(path, [])
    return payload if isinstance(payload, list) else []


def merge_access_control_items(workspace_id: str, target: str, name: str, items: list[dict[str, Any]], key_field: str) -> dict[str, Any]:
    path = access_control_dir(workspace_id, target) / f"{name}.json"
    existing = read_access_control_items(workspace_id, target, name)
    by_key = {str(item.get(key_field, "")): item for item in existing if isinstance(item, dict) and item.get(key_field)}
    created = 0
    for item in items:
        key = str(item.get(key_field, ""))
        if not key:
            continue
        if key in by_key:
            by_key[key].update({field: value for field, value in item.items() if value not in ("", None, [], {})})
        else:
            by_key[key] = item
            created += 1
    merged = sorted(by_key.values(), key=lambda item: str(item.get(key_field, "")))
    workspace._write_json(path, merged)
    return {"path": str(path), "created": created, "total": len(merged)}


def normalize_context(item: dict[str, Any]) -> dict[str, Any]:
    context_id = stable_slug(item.get("contextId") or item.get("label") or item.get("role") or "context")
    return {
        "contextId": context_id,
        "label": item.get("label", context_id),
        "role": item.get("role", "unknown"),
        "userType": item.get("userType", ""),
        "credentialId": item.get("credentialId", ""),
        "authState": item.get("authState", "unknown"),
        "notes": item.get("notes", ""),
        "observedEndpointPatterns": item.get("observedEndpointPatterns", []),
        "ownedObjectTypes": item.get("ownedObjectTypes", []),
        "metadata": item.get("metadata", {}),
    }


def value_shape(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    if UUID_RE.match(text):
        return "uuid"
    if OBJECT_ID_RE.match(text):
        return "objectid"
    if text.isdigit():
        return "numeric"
    if "@" in text and "." in text:
        return "email"
    if re.match(r"^[a-zA-Z0-9_-]{3,80}$", text):
        return "slug"
    return "opaque"


def normalize_identifier_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", name.strip()).strip("_").lower()


def object_type_from_segment(segment: str) -> str:
    return RESOURCE_SEGMENTS.get(segment.lower().strip(), "object")


def endpoint_pattern_for_url(url: str, replace_index: int | None = None) -> str:
    parsed = urlsplit(url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    patterned = []
    for index, segment in enumerate(segments):
        shape = value_shape(segment)
        if replace_index == index or shape in {"numeric", "uuid", "objectid"}:
            previous = object_type_from_segment(segments[index - 1] if index else "")
            patterned.append("{" + (f"{previous}_id" if previous != "object" else "id") + "}")
        else:
            patterned.append(segment)
    return "/" + "/".join(patterned) if patterned else "/"


def stable_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:16]


def replay_request_fingerprint(
    matrix_entry: dict[str, Any],
    method: str,
    request_url: str,
    body: Any,
    json_body: Any,
    contexts: list[dict[str, Any]],
) -> str:
    payload = {
        "matrixId": matrix_entry.get("matrixId", ""),
        "method": method,
        "requestUrl": request_url,
        "body": body if json_body is None else None,
        "jsonBody": json_body,
        "contexts": [
            {
                "contextId": context.get("contextId", ""),
                "expectedAccess": context.get("expectedAccess"),
                "credentialId": context.get("credentialId", ""),
                "authState": context.get("authState", ""),
                "role": context.get("role", ""),
                "substitutions": context.get("substitutions", {}),
            }
            for context in contexts
        ],
    }
    return stable_id("access-control-replay", canonical_json(payload))


def canonical_json(value: Any) -> str:
    return json.dumps(_canonicalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonicalize(nested) for key, nested in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def priority_for_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def auth_required_likely(endpoint: dict[str, Any]) -> bool:
    return bool(endpoint.get("hasAuthorization") or endpoint.get("cookieNames") or endpoint.get("authBoundary")) or any(
        marker in str(endpoint.get("path", "")).lower() for marker in ("account", "user", "admin", "profile", "settings")
    )


def is_function_endpoint(endpoint: dict[str, Any]) -> bool:
    path = str(endpoint.get("path", "") or urlsplit(str(endpoint.get("url", ""))).path).lower()
    method = str(endpoint.get("method", "GET")).upper()
    return method in {"POST", "PUT", "PATCH", "DELETE"} or any(marker in path for marker in FUNCTION_PATH_MARKERS)


def function_object_type(endpoint: dict[str, Any]) -> str:
    path = str(endpoint.get("path", "") or urlsplit(str(endpoint.get("url", ""))).path).lower()
    for segment, object_type in RESOURCE_SEGMENTS.items():
        if segment in path:
            return object_type
    return "function"


def risk_for_object(item: dict[str, Any]) -> str:
    if item.get("stateChanging") or item.get("testClass") == "BFLA":
        return "high"
    if item.get("objectType") in {"tenant", "organization", "account", "invoice", "file"}:
        return "medium"
    return "medium" if item.get("authRequiredLikely") else "low"


def test_idea(test_class: str, item: dict[str, Any]) -> str:
    if test_class == "BFLA":
        return "Compare privileged and non-privileged context access to this function endpoint."
    if test_class == "BOPLA":
        return "Compare tenant/organization/property boundary behavior across authorized contexts."
    return f"Compare access to {item.get('objectType', 'object')}-owned resources across authenticated contexts."


def matrix_reason(test_class: str, item: dict[str, Any], contexts: list[str]) -> str:
    context_text = ", ".join(contexts)
    if test_class == "BFLA":
        return f"Endpoint exposes privileged or state-changing functionality; compare role contexts: {context_text}."
    if test_class == "BOPLA":
        return f"Endpoint exposes tenant, organization, or property-like boundary; compare contexts: {context_text}."
    return f"Endpoint exposes object identifier {item.get('identifierName')} with shape {item.get('identifierValueShape')}; compare contexts: {context_text}."


def build_replay_comparisons(full_responses: list[dict[str, Any]], matrix_entry: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    comparisons: list[dict[str, Any]] = []
    possible_broken = False
    for left_index in range(len(full_responses)):
        for right_index in range(left_index + 1, len(full_responses)):
            left = full_responses[left_index]
            right = full_responses[right_index]
            left_context = left["context"]
            right_context = right["context"]
            left_response = left["response"]
            right_response = right["response"]
            comparison = compare_http_responses(left_response, right_response)
            signals_possible = False
            signal_reason = ""
            downgrade_reason = ""

            expected_signal = expected_denied_signal(left, right, matrix_entry)
            if expected_signal:
                signals_possible = True
                signal_reason = expected_signal["reason"]
                downgrade_reason = replay_signal_downgrade_reason(expected_signal["allowedResponse"], expected_signal["deniedResponse"], expected_signal["comparison"])
                signals_possible = not downgrade_reason

            if not signals_possible:
                peer_reason = peer_access_signal(left, right, comparison, matrix_entry)
                if peer_reason:
                    signals_possible = True
                    signal_reason = peer_reason

            if signals_possible:
                possible_broken = True
            comparison_record = {
                "comparisonType": "peer",
                "baselineContextId": left_context["contextId"],
                "contextId": right_context["contextId"],
                "leftContextId": left_context["contextId"],
                "rightContextId": right_context["contextId"],
                "expectedAccess": right_context.get("expectedAccess"),
                "leftExpectedAccess": left_context.get("expectedAccess"),
                "rightExpectedAccess": right_context.get("expectedAccess"),
                "comparison": comparison,
                "baselineSemantics": response_access_semantics(left_response),
                "responseSemantics": response_access_semantics(right_response),
                "leftSemantics": response_access_semantics(left_response),
                "rightSemantics": response_access_semantics(right_response),
                "signalsPossibleBrokenAccessControl": signals_possible,
            }
            if signal_reason:
                comparison_record["signalReason"] = signal_reason
            if downgrade_reason:
                comparison_record["downgradeReason"] = downgrade_reason
            comparisons.append(comparison_record)
    return comparisons, possible_broken


def expected_denied_signal(left: dict[str, Any], right: dict[str, Any], matrix_entry: dict[str, Any]) -> dict[str, Any] | None:
    pairs = ((left, right), (right, left))
    for allowed, denied in pairs:
        if allowed["context"].get("expectedAccess") is not True or denied["context"].get("expectedAccess") is not False:
            continue
        comparison = compare_http_responses(allowed["response"], denied["response"])
        if not is_success_response(denied["response"]):
            continue
        if not responses_are_similar_successes(comparison):
            continue
        if responses_carry_distinct_identity(comparison):
            # The "denied" context received its own per-context identity data (a self-scoped
            # endpoint such as whoami/my-profile), not the allowed context's object, so this is
            # not access to another principal's resource.
            continue
        return {
            "allowedResponse": allowed["response"],
            "deniedResponse": denied["response"],
            "comparison": comparison,
            "reason": f"Context {denied['context'].get('contextId')} was expected to be denied but received content similar to allowed context {allowed['context'].get('contextId')}.",
        }
    return None


def peer_access_signal(left: dict[str, Any], right: dict[str, Any], comparison: dict[str, Any], matrix_entry: dict[str, Any]) -> str:
    test_class = str(matrix_entry.get("testClass", "BOLA") or "BOLA").upper()
    if test_class not in {"BOLA", "BFLA", "BOPLA"}:
        return ""
    left_context = left["context"]
    right_context = right["context"]
    if not (_context_is_authenticated(left_context) and _context_is_authenticated(right_context)):
        return ""
    if not (is_success_response(left["response"]) and is_success_response(right["response"])):
        return ""
    if not responses_are_similar_successes(comparison, strict=True):
        return ""
    if responses_carry_distinct_identity(comparison):
        # Each context received its own distinct identity data (self-scoped endpoint), not the
        # same shared object — structural similarity here is expected, not broken access.
        return ""
    if test_class == "BFLA" and (_context_is_privileged(left_context) == _context_is_privileged(right_context)):
        return ""
    if test_class == "BOLA" and left_context.get("contextId") == right_context.get("contextId"):
        return ""
    return (
        f"Authenticated peer contexts {left_context.get('contextId')} and {right_context.get('contextId')} "
        f"received highly similar successful data for a {test_class} matrix entry."
    )


def responses_are_similar_successes(comparison: dict[str, Any], *, strict: bool = False) -> bool:
    body_threshold = 0.95 if strict else 0.75
    json_threshold = 0.9 if strict else 0.6
    return bool(
        comparison.get("bodySimilarity", 0) >= body_threshold
        and (comparison.get("jsonKeyOverlap") is None or comparison.get("jsonKeyOverlap") >= json_threshold)
    )


def responses_carry_distinct_identity(comparison: dict[str, Any]) -> bool:
    """True when the two contexts did NOT receive the same shared sensitive object.

    A genuine shared-object BOLA returns byte-identical bodies carrying sensitive data to both
    contexts. A self-scoped endpoint (whoami/my-profile) returns each caller's own data, so the
    bodies differ even when structurally similar. Identical-but-empty or non-sensitive bodies are
    also not a broken-access signal.
    """
    shared_sensitive = bool(comparison.get("bodyIdentical")) and bool(
        comparison.get("sensitiveMarkersA") or comparison.get("sensitiveMarkersB")
    )
    return not shared_sensitive


def missing_information(contexts: list[dict[str, Any]]) -> list[str]:
    missing = []
    if len(contexts) < 2:
        missing.append("At least two contexts are needed for meaningful access-control comparison.")
    if not any(item.get("credentialId") for item in contexts):
        missing.append("No credential IDs are associated with recorded contexts; approved replay will use unauthenticated requests.")
    if not any(item.get("ownedObjectTypes") for item in contexts):
        missing.append("Object ownership mapping is not recorded yet.")
    return missing


def matrix_missing_information(contexts: list[dict[str, Any]], matrix: list[dict[str, Any]]) -> list[str]:
    if any(str(item.get("testClass", "")).upper() == "BFLA" for item in matrix):
        return matrix_entry_missing_information(contexts, {"testClass": "BFLA"})
    return []


def matrix_entry_missing_information(contexts: list[dict[str, Any]], matrix_entry: dict[str, Any]) -> list[str]:
    if str(matrix_entry.get("testClass", "") or "").upper() == "BFLA" and not any(_context_is_privileged(context) for context in contexts):
        return ["BFLA unassessable: no privileged context recorded"]
    return []


def resolve_matrix_entry(args: dict[str, Any], workspace_id: str, target: str) -> dict[str, Any]:
    entry = args.get("matrixEntry") if isinstance(args.get("matrixEntry"), dict) else None
    if entry:
        return dict(entry)
    matrix_id = str(args.get("matrixId", ""))
    if matrix_id:
        entries = read_access_control_items(workspace_id, target, "matrix")
        found = next((item for item in entries if item.get("matrixId") == matrix_id), None)
        if found:
            return found
    return {
        "matrixId": matrix_id,
        "endpointPattern": args.get("endpointPattern", ""),
        "method": args.get("method", "GET"),
        "objectType": args.get("objectType", "object"),
        "testClass": args.get("testClass", "BOLA"),
        "requiredContexts": args.get("requiredContexts", []),
        "riskTier": args.get("riskTier", "medium"),
    }


def resolve_replay_contexts(args: dict[str, Any], workspace_id: str, target: str, matrix_entry: dict[str, Any]) -> list[dict[str, Any]]:
    stored_contexts = {item.get("contextId"): item for item in read_access_control_items(workspace_id, target, "contexts") if isinstance(item, dict)}
    supplied = args.get("contexts")
    if isinstance(supplied, list) and supplied:
        contexts = [merge_context_with_stored(item, stored_contexts) for item in supplied if isinstance(item, dict)]
    else:
        contexts = [
            merge_context_with_stored({"contextId": context_id}, stored_contexts)
            for context_id in matrix_entry.get("requiredContexts", [])
            if context_id
        ]
    if not contexts:
        contexts = [{"contextId": "anonymous", "label": "Anonymous", "role": "anonymous", "expectedAccess": False}]
    allow_anonymous = bool(args.get("allowAnonymousContexts", False))
    normalized = []
    for item in contexts:
        context = normalize_context(item)
        context["expectedAccess"] = item["expectedAccess"] if "expectedAccess" in item else _default_expected_access(context, matrix_entry)
        context["substitutions"] = item.get("substitutions", {})
        if item.get("allowAnonymous") is True:
            context["allowAnonymous"] = True
        has_credential = bool(str(context.get("credentialId", "") or ""))
        if _is_explicit_anonymous(context):
            context["allowAnonymous"] = True
            context["authState"] = "anonymous"
            context.setdefault("anonymousReason", "Context is explicitly marked anonymous.")
        elif has_credential:
            # Credential validity is verified later in prepare_replay_context_auth.
            pass
        elif _context_requires_credentials(context):
            if not allow_anonymous:
                raise McpError(-32602, _missing_credential_error(context))
            context["allowAnonymous"] = True
            context["authState"] = "anonymous"
            context["anonymousReason"] = "No credentialId was provided or stored for this access-control context."
        else:
            context["allowAnonymous"] = True
            context["authState"] = "anonymous"
            context.setdefault("anonymousReason", "Context does not require authentication; replayed without credentials.")
        normalized.append(context)
    return normalized


def _is_explicit_anonymous(context: dict[str, Any]) -> bool:
    role = str(context.get("role", "")).strip().lower()
    auth_state = str(context.get("authState", "")).strip().lower()
    context_id = str(context.get("contextId", "")).strip().lower()
    return bool(
        context.get("allowAnonymous") is True
        or auth_state == "anonymous"
        or role in ANONYMOUS_ROLES
        or context_id == "anonymous"
    )


def _context_requires_credentials(context: dict[str, Any]) -> bool:
    if _is_explicit_anonymous(context):
        return False
    if str(context.get("credentialId", "") or ""):
        return True
    if str(context.get("authState", "")).strip().lower() == "authenticated":
        return True
    role = str(context.get("role", "")).strip().lower()
    return context.get("expectedAccess") is True and role not in ANONYMOUS_ROLES


def _missing_credential_error(context: dict[str, Any]) -> str:
    label = context.get("contextId") or context.get("label") or "context"
    return (
        f"Access-control context '{label}' is expected to be authenticated but has no credentialId. "
        "Provide a valid credentialId, mark the context as anonymous, or set allowAnonymousContexts=true."
    )


def _invalid_credential_error(context: dict[str, Any], credential_id: str) -> str:
    label = context.get("contextId") or context.get("label") or "context"
    return (
        f"Access-control context '{label}' references credentialId '{credential_id}', but that credential "
        "could not be resolved. Provide a valid credentialId, mark the context as anonymous, or set "
        "allowAnonymousContexts=true."
    )


def prepare_replay_context_auth(context: dict[str, Any], request_url: str, allow_anonymous: bool = False) -> dict[str, Any]:
    credential_id = str(context.get("credentialId", "") or "")
    if not credential_id:
        # resolve_replay_contexts already classified credential-less contexts as
        # explicit/permitted anonymous (or failed); keep the anonymous markers.
        context.setdefault("allowAnonymous", True)
        context.setdefault("authState", "anonymous")
        context.setdefault("anonymousReason", "No credentialId was provided or stored for this access-control context.")
        return context
    try:
        from ...core import credentials

        credentials.credential_for_target(credential_id, request_url)
    except McpError as exc:
        if not allow_anonymous:
            raise McpError(-32602, _invalid_credential_error(context, credential_id)) from exc
        context["credentialId"] = ""
        context["allowAnonymous"] = True
        context["authState"] = "anonymous"
        context["anonymousReason"] = f"CredentialId {credential_id} could not be used for this target; replayed without authentication."
        context["credentialError"] = str(exc)
    return context


def merge_context_with_stored(item: dict[str, Any], stored: dict[str, dict[str, Any]]) -> dict[str, Any]:
    context_id = stable_slug(item.get("contextId") or item.get("label") or item.get("role") or "context")
    base = dict(stored.get(context_id, {}))
    base.update(item)
    base["contextId"] = context_id
    return base


def _is_blocked_replay_header(name: Any) -> bool:
    normalized = str(name).strip().lower()
    if normalized in ALLOWED_DIRECT_HEADERS:
        return False
    return any(marker in normalized for marker in BLOCKED_HEADER_MARKERS)


def build_replay_request(
    url: str,
    method: str,
    credential_id: str,
    *,
    body: Any = None,
    json_body: Any = None,
    extra_headers: Any = None,
    substitutions: Any = None,
) -> dict[str, Any]:
    request_url = apply_substitutions(url, substitutions if isinstance(substitutions, dict) else {})
    headers = {"User-Agent": USER_AGENT}
    extra = extra_headers if isinstance(extra_headers, dict) else {}
    for name, value in extra.items():
        if _is_blocked_replay_header(name):
            raise McpError(-32602, "Do not pass secret-bearing headers directly; use credentialId-bound contexts.")
        headers[str(name)] = str(value)
    body_bytes = None
    if json_body is not None:
        body_bytes = json.dumps(apply_json_substitutions(json_body, substitutions if isinstance(substitutions, dict) else {})).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif body is not None:
        body_bytes = str(body).encode("utf-8")
    if credential_id:
        from ...core import credentials

        credential = credentials.credential_for_target(str(credential_id), request_url)
        headers.update(credentials.headers_for_credential_target(credential, request_url))
    return {
        "url": request_url,
        "method": method,
        "headers": headers,
        "body": body_bytes.decode("utf-8", errors="replace") if body_bytes else "",
        "_bodyBytes": body_bytes,
    }


def apply_substitutions(url: str, substitutions: dict[str, Any]) -> str:
    if not substitutions:
        return url
    parsed = urlsplit(url)
    path = parsed.path
    for name, value in substitutions.items():
        token = "{" + str(name) + "}"
        path = path.replace(token, str(value))
    query = []
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((name, str(substitutions.get(name, value))))
    from urllib.parse import urlencode

    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), parsed.fragment))


def apply_json_substitutions(value: Any, substitutions: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {
            key: substitutions[key] if key in substitutions else apply_json_substitutions(nested, substitutions)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [apply_json_substitutions(item, substitutions) for item in value]
    return value


def safe_response_summary(response: dict[str, Any]) -> dict[str, Any]:
    body = str(response.get("body", "") or "")
    headers = {str(name).lower(): str(value) for name, value in response.get("headers", {}).items()} if isinstance(response.get("headers"), dict) else {}
    selected_headers = {}
    for name in ("content-type", "location", "cache-control", "www-authenticate", "set-cookie"):
        if name in headers:
            selected_headers[name] = "<set-cookie-present>" if name == "set-cookie" else headers[name][:200]
    return {
        "status": response.get("status"),
        "headers": selected_headers,
        "bodyLength": len(body),
        "bodySha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else "",
        "jsonKeys": sorted(json_keys(body))[:100],
        "sensitiveMarkers": sorted(sensitive_markers(body, headers)),
        "accessSemantics": response_access_semantics(response),
        "error": response.get("error", ""),
    }


def replay_signal_downgrade_reason(baseline_response: dict[str, Any], response: dict[str, Any], comparison: dict[str, Any]) -> str:
    if has_success_marked_json(baseline_response) or has_success_marked_json(response):
        return ""
    if has_data_bearing_json(baseline_response) or has_data_bearing_json(response):
        return ""
    if not (is_error_shaped_json(baseline_response) and is_error_shaped_json(response)):
        return ""
    json_overlap = comparison.get("jsonKeyOverlap")
    if comparison.get("bodySimilarity", 0) >= 0.95 and (json_overlap is None or json_overlap >= 0.9):
        return "identical_error_shaped_json"
    return ""


def response_access_semantics(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "successStatus": is_success_response(response),
        "json": parse_json_body(response) is not None,
        "errorShapedJson": is_error_shaped_json(response),
        "dataBearingJson": has_data_bearing_json(response),
        "successMarkedJson": has_success_marked_json(response),
    }


def is_error_shaped_json(response: dict[str, Any]) -> bool:
    payload = parse_json_body(response)
    if payload is None:
        return False
    keys = {key.rsplit(".", 1)[-1].lower() for key in flatten_json_keys(payload)}
    text = canonical_json(payload).lower()
    has_error_key = any(key in ERROR_JSON_KEY_MARKERS or key.startswith("err") for key in keys)
    has_error_value = any(marker in text for marker in ERROR_JSON_VALUE_MARKERS)
    return has_error_key or has_error_value


def has_data_bearing_json(response: dict[str, Any]) -> bool:
    payload = parse_json_body(response)
    if payload is None:
        return False
    return _has_data_bearing_json_value(payload)


def has_success_marked_json(response: dict[str, Any]) -> bool:
    payload = parse_json_body(response)
    if payload is None:
        return False
    return _has_success_marker(payload)


def parse_json_body(response: dict[str, Any]) -> Any:
    body = str(response.get("body", "") or "").strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def flatten_json_keys(value: Any) -> set[str]:
    keys: set[str] = set()

    def walk(item: Any, prefix: str = "") -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                keys.add(path)
                walk(nested, path)
        elif isinstance(item, list):
            for nested in item[:20]:
                walk(nested, prefix)

    walk(value)
    return keys


def _has_data_bearing_json_value(value: Any, key: str = "") -> bool:
    normalized_key = key.lower()
    if normalized_key in DATA_BEARING_JSON_KEYS and _meaningful_json_value(value):
        return True
    if normalized_key == "id" or normalized_key.endswith("_id") or normalized_key in {"uuid", "guid"}:
        return _meaningful_json_value(value)
    if isinstance(value, dict):
        return any(_has_data_bearing_json_value(nested, str(nested_key)) for nested_key, nested in value.items())
    if isinstance(value, list):
        if normalized_key in DATA_BEARING_JSON_KEYS or not normalized_key:
            return bool(value) and any(_meaningful_json_value(item) for item in value)
        return any(_has_data_bearing_json_value(item) for item in value if isinstance(item, (dict, list)))
    return False


def _has_success_marker(value: Any, key: str = "") -> bool:
    normalized_key = key.lower()
    if normalized_key in SUCCESS_JSON_KEYS and value is True:
        return True
    if normalized_key == "status" and str(value).strip().lower() in SUCCESS_STATUS_VALUES:
        return True
    if normalized_key == "code" and (value == 0 or str(value).strip().upper() in {"OK", "SUCCESS"}):
        return True
    if isinstance(value, dict):
        return any(_has_success_marker(nested, str(nested_key)) for nested_key, nested in value.items())
    if isinstance(value, list):
        return any(_has_success_marker(item, key) for item in value)
    return False


def _meaningful_json_value(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def json_keys(body: str) -> set[str]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return set()
    keys: set[str] = set()

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                keys.add(path)
                walk(nested, path)
        elif isinstance(value, list):
            for item in value[:20]:
                walk(item, prefix)

    walk(payload)
    return keys


def sensitive_markers(body: str, headers: dict[str, str]) -> set[str]:
    markers = ("email", "username", "user_id", "account_id", "tenant_id", "role", "permission", "token", "secret")
    haystack = (body + "\n" + json.dumps(headers, sort_keys=True)).lower()
    return {marker for marker in markers if marker in haystack}


def is_success_response(response: dict[str, Any]) -> bool:
    status = response.get("status")
    return isinstance(status, int) and 200 <= status < 300
