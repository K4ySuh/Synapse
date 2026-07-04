# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, surface_candidate
from ...core.errors import McpError
from .active_probe import priority_for_score, redact_value_preview, stable_slug
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url
from . import sqlmap_analysis


# Precision controls (Phase 4): SQLi already gates on a high score; cap how many
# candidates a single host can produce so passive analysis can't flood the workspace.
DEFAULT_MIN_SCORE = 55
MAX_CANDIDATES_PER_HOST = 12

SQLI_PATH_HINTS = ("api", "rest", "search", "login", "products", "product", "users", "user", "orders", "order", "basket", "cart", "items")
SQLI_NAME_HINTS = tuple(sqlmap_analysis.INTERESTING_NAMES) + ("username", "password", "role", "owner", "basket", "coupon")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("sqli"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = str(args["workspaceId"])
    target = str(args["target"])
    max_candidates = int(args.get("maxCandidates", MAX_CANDIDATES_PER_HOST))
    min_score = int(args.get("minScore", DEFAULT_MIN_SCORE))
    context = workspace.prepare_target_context(workspace_id, target, purpose="sqli_candidate_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_workspace_candidates(entities, target=target, min_score=min_score)[:max_candidates]
    result = build_workspace_adapter_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": context.get("parameters", {}).get("total", 0),
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
            {"adapter": "sqli", "maxCandidates": max_candidates, "minScore": min_score},
        )
    evidence.log_event(
        "sqli.analyze_workspace",
        f"Analyzed workspace parameters for SQL injection candidates on {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def analyze_dump(args: dict[str, Any]) -> str:
    payload = {
        "dumpPath": args["dumpPath"],
        "onlyInteresting": args.get("onlyInteresting", True),
        "maxCandidatesPerRequest": args.get("maxCandidatesPerRequest", 5),
        "includeCommands": args.get("includeCommands", True),
        "level": args.get("level", 1),
        "risk": args.get("risk", 1),
    }
    result = json.loads(sqlmap_analysis.analyze_burp_dump(payload))
    ingestion = None
    if args.get("ingest", False):
        workspace_id = args.get("workspaceId")
        target = args.get("target")
        if not workspace_id or not target:
            raise McpError(-32602, "workspaceId and target are required when ingest=true.")
        adapter_result = build_adapter_result(str(workspace_id), str(target), result)
        ingestion = workspace.ingest_data(
            str(workspace_id),
            str(target),
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps({**adapter_result.as_ingest_payload(), "analysis": result}, indent=2, ensure_ascii=False),
            {"adapter": "sqli", "dumpPath": args["dumpPath"]},
        )
    if ingestion:
        result["ingestion"] = ingestion
    return json.dumps(result, indent=2)


def build_command(args: dict[str, Any]) -> str:
    """Build validated sqlmap command(s) without executing them.

    Without workspace context this returns a single generic command (back-compat).
    With workspaceId+target it promotes *every* interesting candidate surface — all
    injectable parameters grouped per route, not just one parameter of one URL — into a
    targeted sqlmap invocation, and marks each promoted sqli candidate as under testing.
    """
    level = int(args["level"])
    risk = int(args["risk"])
    base = sqlmap_analysis.build_sqlmap_command(level, risk, args.get("options"))
    workspace_id = args.get("workspaceId")
    target = args.get("target")
    if not workspace_id or not target:
        return json.dumps({"command": base, "shellCommand": sqlmap_analysis.stringify_command(base)}, indent=2)

    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    min_score = int(args.get("minScore", 55))
    max_targets = int(args.get("maxTargets", 25))
    entities = workspace._load_target_entities(wid, host)
    candidates = find_workspace_candidates(entities, target=host, min_score=min_score)

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        url = str(candidate.get("url", ""))
        method = str(candidate.get("method", "GET")).upper()
        if not url:
            continue
        group = grouped.setdefault(
            (url, method),
            {"url": url, "method": method, "parameters": [], "locations": set(), "candidateIds": [], "priorityScore": 0},
        )
        name = str(candidate.get("parameter", ""))
        if name and name not in group["parameters"]:
            group["parameters"].append(name)
        group["locations"].add(str(candidate.get("location", "query")))
        group["candidateIds"].append(str(candidate.get("candidateId", "")))
        group["priorityScore"] = max(group["priorityScore"], int(candidate.get("priorityScore", 0) or 0))

    ordered = sorted(grouped.values(), key=lambda item: item["priorityScore"], reverse=True)[:max_targets]
    targets: list[dict[str, Any]] = []
    for group in ordered:
        cmd = list(base) + ["-u", group["url"]]
        if group["method"] not in {"GET", "HEAD"}:
            cmd += ["--method", group["method"]]
            body_params = [name for name in group["parameters"] if name]
            if body_params and group["locations"] & {"body", "form", "json"}:
                cmd += ["--data", "&".join(f"{name}=1" for name in body_params)]
        if group["parameters"]:
            cmd += ["-p", ",".join(group["parameters"])]
        targets.append(
            {
                "url": group["url"],
                "method": group["method"],
                "parameters": group["parameters"],
                "candidateIds": [cid for cid in group["candidateIds"] if cid],
                "priorityScore": group["priorityScore"],
                "command": cmd,
                "shellCommand": sqlmap_analysis.stringify_command(cmd),
            }
        )

    promoted = 0
    if args.get("recordPromotion", True) is not False:
        from ...core.adapters.results import surface_candidate_id

        promoted_surfaces = {(group["url"], group["method"]) for group in ordered}
        for candidate in candidates:
            url = str(candidate.get("url", ""))
            method = str(candidate.get("method", "GET")).upper()
            parameter = str(candidate.get("parameter", ""))
            if not parameter or (url, method) not in promoted_surfaces:
                continue
            selector = {"candidateId": surface_candidate_id(method, url, str(candidate.get("location", "query")), parameter)}
            try:
                workspace.record_candidate_validation(wid, host, selector, "testing", vuln_class="sqli")
                promoted += 1
            except McpError:
                continue

    return json.dumps(
        {
            "command": base,
            "shellCommand": sqlmap_analysis.stringify_command(base),
            "targetCount": len(targets),
            "targets": targets,
            "bulkTargetUrls": [group["url"] for group in ordered],
            "promotedCandidates": promoted,
            "minScore": min_score,
        },
        indent=2,
    )


def find_workspace_candidates(entities: dict[str, list[dict[str, Any]]], *, target: str = "", min_score: int = 55) -> list[dict[str, Any]]:
    endpoints = [item for item in entities.get("endpoints", []) if isinstance(item, dict)]
    endpoint_by_url = {str(item.get("url", "")): item for item in endpoints if str(item.get("url", "")).strip()}
    allowed_hosts = allowed_target_hosts(target)
    candidates: dict[str, dict[str, Any]] = {}
    for parameter in entities.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name", "") or "").strip()
        url = normalize_surface_url(parameter.get("url", ""))
        if not name or not url:
            continue
        if is_candidate_noise_url(url):
            continue
        if allowed_hosts and not url_matches_target_host(url, allowed_hosts):
            continue
        endpoint = endpoint_by_url.get(url, {})
        score, reasons = score_workspace_parameter(parameter, endpoint)
        if score < min_score:
            continue
        candidate_id = "sqli_" + stable_slug(f"{url}|{parameter.get('method', '')}|{parameter.get('location', '')}|{name}")
        candidates.setdefault(
            candidate_id,
            {
                "candidateId": candidate_id,
                "type": "sqli_candidate",
                "url": url,
                "method": str(parameter.get("method") or endpoint.get("method") or "GET").upper(),
                "parameter": name,
                "location": str(parameter.get("location") or "query"),
                "path": str(parameter.get("path") or endpoint.get("path") or urlsplit(url).path or "/"),
                "priority": priority_for_score(score),
                "confidence": "medium" if score >= 75 else "low",
                "priorityScore": score,
                "reason": "; ".join(reasons) or "Workspace parameter is a candidate SQL injection input.",
                "valuePreview": redact_value_preview(name, str(parameter.get("valuePreview", "") or "")),
                "tags": ["sqli", "workspace-candidate"],
            },
        )
    return sorted(candidates.values(), key=lambda item: int(item.get("priorityScore", 0) or 0), reverse=True)


def allowed_target_hosts(target: str) -> set[str]:
    hosts = {workspace.normalize_target(target)}
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    if parsed.hostname:
        hosts.add(parsed.hostname.lower())
    return {host for host in hosts if host}


def url_matches_target_host(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    if not parsed.hostname:
        return url.startswith("/")
    return parsed.hostname.lower() in allowed_hosts


def score_workspace_parameter(parameter: dict[str, Any], endpoint: dict[str, Any]) -> tuple[int, list[str]]:
    score = 25
    reasons = ["User-controllable workspace parameter observed."]
    name = str(parameter.get("name", "") or "").lower()
    location = str(parameter.get("location", "") or "query").lower()
    method = str(parameter.get("method") or endpoint.get("method") or "GET").upper()
    path = str(parameter.get("path") or endpoint.get("path") or "").lower()
    value = str(parameter.get("valuePreview", "") or "").strip()
    if location in {"query", "body", "json", "form", "path"}:
        score += 25
        reasons.append(f"Parameter is in {location} input.")
    if any(hint in name for hint in SQLI_NAME_HINTS):
        score += 20
        reasons.append("Parameter name is commonly database-backed.")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 15
        reasons.append("State-changing method may reach server-side data operations.")
    if value and (_looks_numeric(value) or UUID_RE.match(value) or "'" in value or '"' in value):
        score += 10
        reasons.append("Observed value shape is scalar/identifier-like.")
    if any(hint in path for hint in SQLI_PATH_HINTS):
        score += 10
        reasons.append("Endpoint path suggests API or data-access behavior.")
    return min(score, 100), reasons


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def build_workspace_adapter_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        surface_candidate(
            vuln_class="sqli",
            url=str(candidate.get("url", "")),
            method=str(candidate.get("method", "")),
            parameter=str(candidate.get("parameter", "")),
            location=str(candidate.get("location", "")),
            confidence=str(candidate.get("confidence", "low")),
            priority=str(candidate.get("priority", "low")),
            priority_score=int(candidate.get("priorityScore", 0) or 0),
            reason=str(candidate.get("reason", "Workspace parameter is a candidate SQL injection input.")),
            tags=["sqli", "workspace-candidate"],
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="sqli",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(observations)} SQL injection candidate parameters from workspace data.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Workspace SQLi analysis is passive and does not validate exploitability.",
            "Synapse builds sqlmap commands but does not execute sqlmap.",
        ],
        metadata={
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "parameterCount": context.get("parameters", {}).get("total", 0),
        },
    )


def build_adapter_result(workspace_id: str, target: str, analysis: dict[str, Any]) -> AdapterResult:
    observations = []
    for item in analysis.get("results", []):
        if not isinstance(item, dict):
            continue
        method = str(item.get("requestLine", "")).split(" ", 1)[0].upper() or "GET"
        for candidate in item.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            score = int(candidate.get("score", 0) or 0)
            observations.append(
                surface_candidate(
                    vuln_class="sqli",
                    url=str(item.get("requestLine", "")),
                    method=method,
                    parameter=str(candidate.get("name", "")),
                    location=str(candidate.get("location", "")),
                    confidence="medium" if score >= 80 else "low",
                    priority="high" if score >= 85 else ("medium" if score >= 60 else "low"),
                    priority_score=score,
                    reason=str(candidate.get("reason", "SQL injection candidate identified from offline request analysis.")),
                    tags=["sqli", "sqlmap-candidate"],
                )
            )
    return AdapterResult(
        adapter="sqli",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(observations)} SQL injection candidate parameters from offline dump analysis.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "SQLi dump analysis is passive and does not validate exploitability.",
            "Synapse builds sqlmap commands but does not execute sqlmap.",
        ],
        metadata={
            "dumpDir": analysis.get("dumpDir", ""),
            "analyzedRequests": analysis.get("analyzedRequests", 0),
            "aggregateTechnologies": analysis.get("aggregateTechnologies", []),
            "aggregatePossibleDbms": analysis.get("aggregatePossibleDbms", []),
        },
    )
