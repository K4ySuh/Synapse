# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from .active_probe import stable_slug
from .candidate_dedupe import collapse_host_wide
from .surface_hygiene import is_candidate_noise_url, normalize_surface_url

SESSION_COOKIE_MARKERS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "asp.net_sessionid",
    "remember",
)
DEDUPE_SCOPES = {"host", "endpoint"}


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("headers_cookies"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 100))
    dedupe_scope = str(args.get("dedupeScope", "host") or "host").lower()
    if dedupe_scope not in DEDUPE_SCOPES:
        dedupe_scope = "host"
    context = workspace.prepare_target_context(workspace_id, target, purpose="headers_cookies_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities, dedupe_scope=dedupe_scope)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "analyzedResponses": sum(
                1 for endpoint in entities.get("endpoints", []) if isinstance(endpoint, dict) and endpoint.get("responseHeaders")
            ),
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
            {"adapter": "headers_cookies", "maxCandidates": max_candidates, "dedupeScope": dedupe_scope},
        )
    evidence.log_event(
        "headers_cookies.analyze_workspace",
        f"Analyzed security headers and cookie hygiene for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "dedupeScope": dedupe_scope,
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]], *, dedupe_scope: str = "host") -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        url = normalize_surface_url(endpoint.get("url", ""))
        if not url or is_candidate_noise_url(url):
            continue
        normalized_endpoint = {**endpoint, "url": url}
        headers = endpoint.get("responseHeaders")
        cookie_flags = endpoint.get("responseCookieFlags")
        if not isinstance(headers, dict):
            headers = {}
        if not isinstance(cookie_flags, list):
            cookie_flags = []
        if not headers and not cookie_flags:
            continue
        for candidate in header_candidates(normalized_endpoint, headers) + cookie_candidates(normalized_endpoint, cookie_flags):
            candidates.setdefault(candidate["candidateId"], candidate)
    values = sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)
    if dedupe_scope == "endpoint":
        return values
    return collapse_host_wide([_with_host_subject(candidate) for candidate in values], subject_key="subject")


def header_candidates(endpoint: dict[str, Any], headers: dict[str, Any]) -> list[dict[str, Any]]:
    url = str(endpoint.get("url", ""))
    is_https = urlsplit(url).scheme == "https"
    lowered = {str(name).lower(): str(value) for name, value in headers.items()}
    csp = lowered.get("content-security-policy", "")
    results: list[dict[str, Any]] = []

    if not csp and not lowered.get("content-security-policy-report-only"):
        results.append(_candidate(endpoint, "missing_security_header", "content-security-policy", 60,
            "No Content-Security-Policy is set, leaving the page without a primary XSS/injection mitigation."))
    elif csp and (re.search(r"(?:default-src|script-src)[^;]*\*", csp) or "unsafe-inline" in csp.lower()):
        results.append(_candidate(endpoint, "weak_csp", "content-security-policy", 50,
            "Content-Security-Policy allows wildcard or unsafe-inline sources, weakening its protection."))
    if is_https and not lowered.get("strict-transport-security"):
        results.append(_candidate(endpoint, "missing_security_header", "strict-transport-security", 55,
            "HTTPS response has no Strict-Transport-Security header, allowing downgrade/SSL-strip exposure."))
    if not lowered.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        results.append(_candidate(endpoint, "missing_security_header", "x-frame-options", 45,
            "No X-Frame-Options and no CSP frame-ancestors directive; the page may be framed (clickjacking)."))
    if lowered.get("x-content-type-options", "").strip().lower() != "nosniff":
        results.append(_candidate(endpoint, "missing_security_header", "x-content-type-options", 35,
            "X-Content-Type-Options is not 'nosniff'; browsers may MIME-sniff responses."))
    if not lowered.get("referrer-policy"):
        results.append(_candidate(endpoint, "missing_security_header", "referrer-policy", 25,
            "No Referrer-Policy header; full referrer URLs may leak to third parties."))
    return results


def cookie_candidates(endpoint: dict[str, Any], cookie_flags: list[Any]) -> list[dict[str, Any]]:
    url = str(endpoint.get("url", ""))
    is_https = urlsplit(url).scheme == "https"
    results: list[dict[str, Any]] = []
    for cookie in cookie_flags:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name", ""))
        if not name:
            continue
        sensitive = any(marker in name.lower() for marker in SESSION_COOKIE_MARKERS)
        same_site = str(cookie.get("sameSite", "")).lower()
        if not cookie.get("httpOnly"):
            results.append(_cookie_candidate(endpoint, name, "httponly", 70 if sensitive else 40,
                f"Cookie '{name}' is set without HttpOnly, so client-side script can read it.", sensitive))
        if is_https and not cookie.get("secure"):
            results.append(_cookie_candidate(endpoint, name, "secure", 65 if sensitive else 40,
                f"Cookie '{name}' is set over HTTPS without the Secure flag and may be sent over cleartext.", sensitive))
        if not same_site or same_site == "none":
            results.append(_cookie_candidate(endpoint, name, "samesite", 50 if sensitive else 30,
                f"Cookie '{name}' has weak or absent SameSite ({same_site or 'unset'}), broadening CSRF exposure.", sensitive))
    return results


def _candidate(endpoint: dict[str, Any], candidate_type: str, detail: str, score: int, reason: str) -> dict[str, Any]:
    url = str(endpoint.get("url", ""))
    return {
        "candidateId": f"hc_{stable_slug(url)}_{candidate_type}_{stable_slug(detail)}"[:170],
        "type": candidate_type,
        "url": url,
        "method": str(endpoint.get("method", "GET")).upper(),
        "header": detail,
        "priority": _priority(score),
        "priorityScore": score,
        "confidence": "medium",
        "reasons": [reason],
        "evidenceIds": [eid for eid in endpoint.get("evidenceIds", []) if isinstance(eid, str)],
    }


def _cookie_candidate(endpoint: dict[str, Any], name: str, flag: str, score: int, reason: str, sensitive: bool) -> dict[str, Any]:
    url = str(endpoint.get("url", ""))
    return {
        "candidateId": f"hc_{stable_slug(url)}_cookie_{stable_slug(name)}_{flag}"[:170],
        "type": "insecure_cookie_flag",
        "url": url,
        "method": str(endpoint.get("method", "GET")).upper(),
        "cookie": name,
        "flag": flag,
        "sensitiveCookie": sensitive,
        "priority": _priority(score),
        "priorityScore": score,
        "confidence": "medium" if sensitive else "low",
        "reasons": [reason],
        "evidenceIds": [eid for eid in endpoint.get("evidenceIds", []) if isinstance(eid, str)],
    }


def _with_host_subject(candidate: dict[str, Any]) -> dict[str, Any]:
    item = dict(candidate)
    if candidate.get("type") == "insecure_cookie_flag":
        item["subject"] = f"cookie:{candidate.get('cookie', '')}:{candidate.get('flag', '')}".lower()
    else:
        item["subject"] = str(candidate.get("header", "") or candidate.get("type", "")).lower()
    return item


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    observations = [
        candidate_observation(
            candidate_type=candidate["type"],
            value=candidate["url"],
            url=candidate["url"],
            method=candidate["method"],
            confidence=candidate["confidence"],
            priority=candidate["priority"],
            priority_score=int(candidate["priorityScore"]),
            reason=candidate["reasons"][0] if candidate.get("reasons") else "Header/cookie hygiene issue identified.",
            tags=["headers-cookies", candidate["type"].replace("_", "-")],
            metadata={
                "candidateId": candidate["candidateId"],
                "header": candidate.get("header", ""),
                "cookie": candidate.get("cookie", ""),
                "flag": candidate.get("flag", ""),
                "evidenceIds": candidate.get("evidenceIds", []),
                "dedupeScope": candidate.get("dedupeScope", "endpoint"),
                "host": candidate.get("host", ""),
                "subject": candidate.get("subject", ""),
                "affectedUrls": candidate.get("affectedUrls", []),
                "affectedCount": candidate.get("affectedCount", 1 if candidate.get("url") else 0),
            },
        )
        for candidate in candidates
    ]
    return AdapterResult(
        adapter="headers_cookies",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Identified {len(candidates)} security-header and cookie-hygiene observations.",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=[
            "Analyzes only response metadata already recorded in the workspace; run a crawl or dump ingest first.",
            "Cookie analysis uses names and flags only; cookie values are never stored or read.",
        ],
        metadata={"observationCount": len(observations)},
    )


def _priority(score: int) -> str:
    if score >= 65:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 30:
        return "low"
    return "info"
