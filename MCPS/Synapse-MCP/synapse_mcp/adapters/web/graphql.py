# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from ...core import credentials, evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import redact_headers, stable_slug, store_http_exchange_evidence

MAX_ENTITIES = 2000
INTROSPECTION_QUERY = (
    "query SynapseIntrospection{__schema{queryType{name}mutationType{name}"
    "subscriptionType{name}types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}}"
)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("graphql"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 50))
    context = workspace.prepare_target_context(workspace_id, target, purpose="graphql_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {"endpointCount": context.get("knownEndpoints", {}).get("total", 0)},
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
            {"adapter": "graphql", "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "graphql.analyze_workspace",
        f"Analyzed GraphQL candidates for {workspace.normalize_target(target)}.",
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
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url", ""))
        path = str(endpoint.get("path", "") or urlsplit(url).path)
        if not endpoint.get("graphqlEndpoint") and "graphql" not in path.lower() and "graphql" not in url.lower():
            continue
        method = str(endpoint.get("method", "POST") or "POST").upper()
        candidate = {
            "candidateId": f"graphql_{stable_slug(url)}"[:170],
            "type": "introspection_candidate",
            "url": url,
            "method": "POST" if method == "GET" else method,
            "priority": "medium",
            "priorityScore": 65,
            "confidence": "medium",
            "reasons": ["GraphQL-like endpoint observed; approved introspection can confirm whether schema exposure is enabled."],
            "testPlanSummary": "Send one approved introspection query and normalize returned schema fields if enabled.",
        }
        candidates.setdefault(candidate["candidateId"], candidate)
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = []
    for candidate in candidates:
        observations.append(
            candidate_observation(
                candidate_type="graphql_endpoint",
                value=candidate["url"],
                url=candidate["url"],
                method=candidate["method"],
                confidence="medium",
                priority="medium",
                priority_score=55,
                reason="GraphQL-like endpoint observed in workspace data.",
                tags=["graphql", "api"],
                metadata={"candidateId": f"{candidate['candidateId']}_endpoint"},
            )
        )
        observations.append(
            candidate_observation(
                candidate_type="introspection_candidate",
                value=candidate["url"],
                url=candidate["url"],
                method=candidate["method"],
                confidence=candidate["confidence"],
                priority=candidate["priority"],
                priority_score=int(candidate["priorityScore"]),
                reason=candidate["reasons"][0],
                tags=["graphql", "introspection-candidate"],
                metadata={
                    "candidateId": candidate["candidateId"],
                    "reasons": candidate.get("reasons", []),
                    "testPlanSummary": candidate.get("testPlanSummary", ""),
                },
            )
        )
    return AdapterResult(
        adapter="graphql",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} GraphQL introspection candidate endpoints.",
        entities=WorkspaceEntityBundle(observations=observations),
        recommended_tests=recommended_tests(),
        limitations=[
            "Passive analysis only flags likely GraphQL endpoints; schema exposure requires an approved one-request probe.",
        ],
        metadata={"observationCount": len(observations), "contextEndpointCount": context.get("knownEndpoints", {}).get("total", 0)},
    )


def generate_test_plan(args: dict[str, Any]) -> str:
    candidate = _coerce_candidate(args)
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "target": candidate.get("url", ""),
        "method": "POST",
        "sendsTraffic": False,
        "introspectionQuery": INTROSPECTION_QUERY,
        "expectedSignals": [
            "A JSON response contains data.__schema with queryType/types fields.",
            "Errors that explicitly reject __schema indicate introspection is likely disabled.",
        ],
        "guardrails": [
            "This helper builds a plan only; it does not send traffic.",
            "Run the probe only against explicitly authorized in-scope targets after operator approval (confirm=true).",
            "Do not execute discovered queries or mutations as part of introspection validation.",
        ],
        "reasons": candidate.get("reasons", []),
    }
    return json.dumps(plan, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running a GraphQL introspection probe requires confirm=true.")
    candidate = _coerce_candidate(args)
    target_url = str(candidate.get("url", ""))
    if not target_url:
        raise McpError(-32602, "A target url is required.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target_url, workspace_id)
    headers = {"User-Agent": "Synapse-MCP/0.1", "Content-Type": "application/json", "Accept": "application/json"}
    if args.get("credentialId"):
        credential = credentials.credential_for_target(str(args["credentialId"]), target_url)
        headers.update(credentials.headers_for_credential_target(credential, target_url))
    approval = approval_metadata(args)
    timeout = int(args.get("requestTimeout", 10))
    policy = HttpClientPolicy.from_args(args, timeout_seconds=timeout)
    body = json.dumps({"query": INTROSPECTION_QUERY}).encode("utf-8")
    response_payload = http_client.send(HttpRequest(url=target_url, method="POST", headers=headers, body=body), policy=policy).as_dict()
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "graphql_http_exchange",
        request={"url": target_url, "method": "POST", "headers": headers, "body": body},
        response=response_payload,
        metadata={"adapter": "graphql", "target": target_url, "approval": approval},
    )
    parsed_body = _parse_response_body(response_payload.get("body", ""))
    assessment = _assessment(parsed_body, response_payload.get("status"))
    entities = (
        _entities_from_schema(target_url, _schema_from_response(parsed_body))
        if assessment == "introspection_enabled"
        else {"endpoints": [], "parameters": [], "observations": []}
    )
    raw = {
        "candidate": candidate,
        "request": {"url": target_url, "method": "POST"},
        "requestHeaders": redact_headers(headers),
        "response": {
            "status": response_payload.get("status"),
            "contentType": _content_type(response_payload.get("headers", {})),
            "bodyLength": len(str(response_payload.get("body", "") or "")),
        },
        "exchangeEvidence": exchange_evidence,
        "assessment": assessment,
        "entities": entities,
        "approval": approval,
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "graphql_test",
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
            "tool": "graphql.execute_test",
            "target": target_url,
            "method": "POST",
            "assessment": assessment,
            "exchangeEvidenceId": exchange_evidence.get("evidenceId", ""),
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    evidence.log_event(
        "graphql.execute_test",
        f"Ran approved GraphQL introspection probe against {scope_result['host']}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": assessment, "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action}, indent=2)


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="graphql_introspection_probe",
            description="Send one standard introspection POST and check whether data.__schema is returned.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="One JSON POST with an introspection query; do not execute returned operations.",
        )
    ]


def _coerce_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    if "url" not in args:
        raise McpError(-32602, "Provide a candidate object or a url.")
    return {
        "candidateId": args.get("candidateId", ""),
        "url": args["url"],
        "method": "POST",
        "reasons": args.get("reasons", []),
    }


def _parse_response_body(body: Any) -> Any:
    try:
        return json.loads(str(body or ""))
    except json.JSONDecodeError:
        return None


def _assessment(parsed_body: Any, status: Any) -> str:
    if isinstance(parsed_body, dict) and isinstance(parsed_body.get("data"), dict) and isinstance(parsed_body["data"].get("__schema"), dict):
        return "introspection_enabled"
    if isinstance(parsed_body, dict) and parsed_body.get("errors"):
        return "introspection_disabled"
    try:
        if int(status or 0) in {400, 401, 403, 405}:
            return "introspection_disabled"
    except (TypeError, ValueError):
        pass
    return "inconclusive"


def _schema_from_response(parsed_body: Any) -> dict[str, Any]:
    if not isinstance(parsed_body, dict):
        return {}
    data = parsed_body.get("data")
    if not isinstance(data, dict):
        return {}
    schema = data.get("__schema")
    return schema if isinstance(schema, dict) else {}


def _entities_from_schema(url: str, schema: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    entities: dict[str, list[dict[str, Any]]] = {"endpoints": [], "parameters": [], "observations": []}
    if not isinstance(schema, dict):
        return entities
    root_names = {
        "query": _root_name(schema.get("queryType")),
        "mutation": _root_name(schema.get("mutationType")),
        "subscription": _root_name(schema.get("subscriptionType")),
    }
    types_by_name = {
        str(item.get("name", "")): item
        for item in schema.get("types", [])
        if isinstance(item, dict) and item.get("name")
    }
    path_base = urlsplit(url).path or "/"
    for operation_type, type_name in root_names.items():
        if not type_name:
            continue
        gql_type = types_by_name.get(type_name)
        fields = gql_type.get("fields", []) if isinstance(gql_type, dict) and isinstance(gql_type.get("fields"), list) else []
        for field in fields:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            if _entity_count(entities) >= MAX_ENTITIES:
                return entities
            field_name = str(field["name"])
            operation_path = f"{path_base}#{operation_type}.{field_name}"
            endpoint = {
                "type": "endpoint",
                "url": url,
                "method": "POST",
                "path": operation_path,
                "source": "graphql",
                "derived": True,
                "inferred": True,
                "observed": False,
                "graphqlOperation": field_name,
                "graphqlOperationType": operation_type,
                "stateChanging": operation_type == "mutation",
                "confidence": "medium",
            }
            entities["endpoints"].append(endpoint)
            if operation_type == "mutation":
                entities["observations"].append(
                    {
                        "type": "graphql_mutation_surface",
                        "value": field_name,
                        "url": url,
                        "method": "POST",
                        "priority": "medium",
                        "priorityScore": 60,
                        "confidence": "medium",
                        "reason": "GraphQL introspection exposed a mutation field; do not execute it without a separate approved test plan.",
                    }
                )
            args = field.get("args", []) if isinstance(field.get("args"), list) else []
            for arg in args:
                if not isinstance(arg, dict) or not arg.get("name"):
                    continue
                if _entity_count(entities) >= MAX_ENTITIES:
                    return entities
                entities["parameters"].append(
                    {
                        "type": "parameter",
                        "name": str(arg["name"]),
                        "location": "graphql",
                        "method": "POST",
                        "url": url,
                        "path": operation_path,
                        "source": "graphql",
                        "graphqlOperation": field_name,
                        "graphqlOperationType": operation_type,
                        "inputType": _type_name(arg.get("type")),
                    }
                )
    entities["observations"].append(
        {
            "type": "graphql_introspection_enabled",
            "value": url,
            "method": "POST",
            "confidence": "high",
            "priority": "high",
            "priorityScore": 85,
            "reason": "Approved GraphQL introspection probe returned data.__schema.",
        }
    )
    return entities


def _root_name(value: Any) -> str:
    return str(value.get("name", "")) if isinstance(value, dict) else ""


def _type_name(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    if value.get("name"):
        return str(value["name"])
    if isinstance(value.get("ofType"), dict):
        nested = _type_name(value["ofType"])
        return f"{value.get('kind', '')}({nested})" if nested else str(value.get("kind", ""))
    return str(value.get("kind", ""))


def _entity_count(entities: dict[str, list[dict[str, Any]]]) -> int:
    return sum(len(items) for items in entities.values())


def _content_type(headers: Any) -> str:
    if not isinstance(headers, dict):
        return ""
    for name, value in headers.items():
        if str(name).lower() == "content-type":
            return str(value)
    return ""
