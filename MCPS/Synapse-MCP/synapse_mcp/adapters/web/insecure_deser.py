# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote_plus

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from .active_probe import priority_for_score, stable_slug

ADJACENT_SIGNATURE_FIELDS = {"__viewstategenerator", "__eventvalidation"}
CLIENT_CONTROLLED_LOCATIONS = {"query", "body", "form", "json", "xml"}


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("insecure_deser"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 50))
    context = workspace.prepare_target_context(workspace_id, target, purpose="insecure_deser_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "parameterCount": len(entities.get("parameters", [])),
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
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
            {"adapter": "insecure_deser", "maxCandidates": max_candidates},
        )
    evidence.log_event(
        "insecure_deser.analyze_workspace",
        f"Analyzed insecure deserialization candidates for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    siblings = _siblings_by_request(entities.get("parameters", []))
    candidates: dict[str, dict[str, Any]] = {}

    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name", ""))
        location = str(parameter.get("location", "") or "query").lower()
        preview = str(parameter.get("valuePreview", "") or parameter.get("value", ""))
        ecosystem = detect_ecosystem(name, preview)
        if not ecosystem:
            continue
        signed_shape = _signed_shape(parameter, siblings)
        priority_score = 60 if signed_shape or location not in CLIENT_CONTROLLED_LOCATIONS else 82
        candidate = _build_candidate(
            field=name,
            location=location,
            ecosystem=ecosystem,
            url=str(parameter.get("url", "")),
            method=str(parameter.get("method", "GET")).upper(),
            value_preview=preview[:32],
            priority_score=priority_score,
            signed_shape=signed_shape,
            source="parameter",
        )
        candidates.setdefault(candidate["candidateId"], candidate)

    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        cookie_names = endpoint.get("responseCookieNames")
        if not isinstance(cookie_names, list):
            continue
        for cookie_name in cookie_names:
            name = str(cookie_name)
            ecosystem = detect_ecosystem(name, "")
            if not ecosystem:
                continue
            candidate = _build_candidate(
                field=name,
                location="cookie",
                ecosystem=ecosystem,
                url=str(endpoint.get("url", "")),
                method=str(endpoint.get("method", "GET")).upper(),
                value_preview="",
                priority_score=60,
                signed_shape=True,
                source="response_cookie_name",
            )
            candidates.setdefault(candidate["candidateId"], candidate)

    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def detect_ecosystem(name: str, value_preview: str) -> str:
    lowered_name = name.lower()
    value = _decoded_prefix(value_preview)
    lowered_value = value.lower()
    literal_value = value_preview.strip()
    if lowered_name == "__viewstate" or value.startswith("/wEP"):
        return "dotnet_viewstate"
    if value.startswith("rO0AB") or literal_value.startswith("\\xac\\xed\\x00\\x05") or value.startswith("\xac\xed\x00\x05"):
        return "java_serialized"
    if re.match(r'^(?:a:\d+:\{|O:\d+:"|s:\d+:")', value):
        return "php_serialized"
    if value.startswith(("gAS", "gAJ")) or literal_value.startswith(("\\x80\\x04", "\\x80\\x02")) or value.startswith(("\x80\x04", "\x80\x02")):
        return "python_pickle"
    if value.startswith("BAh"):
        return "ruby_marshal"
    if lowered_value.startswith(("/wep", "ro0ab", "gas", "gaj", "bah")):
        # Preserve case-sensitive checks above as primary, but catch lowercased
        # previews that were normalized before reaching the workspace.
        return {
            "/wep": "dotnet_viewstate",
            "ro0ab": "java_serialized",
            "gas": "python_pickle",
            "gaj": "python_pickle",
            "bah": "ruby_marshal",
        }[next(prefix for prefix in ("/wep", "ro0ab", "gas", "gaj", "bah") if lowered_value.startswith(prefix))]
    return ""


def _decoded_prefix(value: str) -> str:
    return unquote_plus(str(value or "").strip())[:120]


def _siblings_by_request(parameters: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    siblings: dict[tuple[str, str], set[str]] = {}
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        key = (str(parameter.get("method", "GET")).upper(), str(parameter.get("url", "")))
        name = str(parameter.get("name", "")).lower()
        if name:
            siblings.setdefault(key, set()).add(name)
    return siblings


def _signed_shape(parameter: dict[str, Any], siblings: dict[tuple[str, str], set[str]]) -> bool:
    if str(parameter.get("name", "")).lower() != "__viewstate":
        return False
    key = (str(parameter.get("method", "GET")).upper(), str(parameter.get("url", "")))
    names = siblings.get(key, set())
    return bool(names & ADJACENT_SIGNATURE_FIELDS)


def _build_candidate(
    *,
    field: str,
    location: str,
    ecosystem: str,
    url: str,
    method: str,
    value_preview: str,
    priority_score: int,
    signed_shape: bool,
    source: str,
) -> dict[str, Any]:
    priority = priority_for_score(priority_score)
    reasons = [f"{ecosystem} marker observed in {location} field '{field}'."]
    if signed_shape:
        reasons.append("Adjacent signing or integrity field observed; treat as lower-priority manual review.")
    return {
        "candidateId": f"insecure_deser_{stable_slug(location)}_{stable_slug(field)}_{stable_slug(ecosystem)}"[:170],
        "type": "insecure_deser_candidate",
        "url": url,
        "method": method or "GET",
        "location": location,
        "field": field,
        "ecosystem": ecosystem,
        "valuePreview": value_preview[:32],
        "priority": priority,
        "priorityScore": priority_score,
        "confidence": "medium" if priority_score >= 80 else "low",
        "reasons": reasons,
        "signedShape": signed_shape,
        "source": source,
        "testPlanSummary": "Manually validate whether this untrusted input reaches an unsafe deserializer; do not deserialize or mutate it in Synapse.",
    }


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type="insecure_deser_candidate",
            value=candidate["field"],
            url=candidate.get("url", ""),
            method=candidate.get("method", ""),
            location=candidate.get("location", ""),
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "Serialized-object marker identified.",
            tags=["insecure-deserialization", candidate["ecosystem"]],
            metadata={
                "candidateId": candidate["candidateId"],
                "field": candidate["field"],
                "ecosystem": candidate["ecosystem"],
                "valuePreview": candidate["valuePreview"],
                "signedShape": candidate.get("signedShape", False),
                "reasons": candidate.get("reasons", []),
                "testPlanSummary": candidate.get("testPlanSummary", ""),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="insecure_deser",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} insecure deserialization candidate inputs.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Signature-based prefix detection only; a recognizable blob is not proof of an unsafe deserializer.",
            "Signed or encrypted blobs may still be vulnerable or benign; validate manually before reporting.",
        ],
        metadata={"observationCount": len(observations), "contextEndpointCount": context.get("knownEndpoints", {}).get("total", 0)},
    )
