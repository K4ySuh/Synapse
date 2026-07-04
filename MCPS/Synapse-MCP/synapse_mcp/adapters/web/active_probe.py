# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib import parse

from ...core import credentials, workspace
from ...core.errors import McpError


def coerce_candidate(args: dict[str, Any], *, required_parameter: bool = True) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return candidate
    required = ["url", "method"]
    if required_parameter:
        required.append("parameter")
    if not all(key in args for key in required):
        raise McpError(-32602, "Provide a candidate object or url/method/parameter fields.")
    return {
        "candidateId": args.get("candidateId", ""),
        "url": args["url"],
        "method": args["method"],
        "parameter": args.get("parameter", ""),
        "location": args.get("location", "query"),
        "reasons": args.get("reasons", []),
    }


def record_surface_test_validation(
    workspace_id: str,
    host: str,
    *,
    vuln_class: str,
    url: str,
    method: str,
    parameter: str,
    location: str,
    interesting: bool = False,
    outcome: str | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Record a benign active-test outcome on the consolidated surface test_candidate.

    For in-band tests (LFI/SSTI) pass ``interesting`` — a positive signal confirms the
    class, a benign run with no signal refutes it (per operator: seeing none work should
    immediately remove the candidate). For out-of-band tests (SSRF) pass an explicit
    ``outcome`` since a null in-band response is inconclusive, not a refutation. Tolerant
    when no surface candidate is present in the workspace — the active test still succeeds.
    """
    from ...core.adapters.results import surface_candidate_id

    outcome = outcome or ("confirmed" if interesting else "refuted")
    selector = {"candidateId": surface_candidate_id(str(method or "GET"), str(url), str(location or "query"), str(parameter))}
    try:
        result = workspace.record_candidate_validation(
            workspace_id,
            host,
            selector,
            outcome,
            vuln_class=vuln_class,
            evidence_ids=[eid for eid in (evidence_ids or []) if eid],
        )
    except McpError:
        return {"outcome": outcome, "recorded": False, "reason": "no matching surface candidate in workspace state"}
    return {
        "outcome": outcome,
        "recorded": True,
        "retired": bool(result.get("retired")),
        "findingDraft": result.get("findingDraft"),
    }


def build_http_request(url: str, method: str, parameter: str, location: str, payload: str, credential_id: Any = None) -> dict[str, Any]:
    parsed = parse.urlsplit(url if "://" in url else f"https://{url}")
    method = str(method or "GET").upper()
    location = str(location or "query")
    headers = {"User-Agent": "Synapse-MCP/0.1"}
    body: bytes | None = None
    request_url = parse.urlunsplit(parsed)

    if location == "query" or method == "GET":
        query = parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = [(name, payload if name == parameter else value) for name, value in query]
        if parameter and not any(name == parameter for name, _ in query):
            query.append((parameter, payload))
        request_url = parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parse.urlencode(query), parsed.fragment))
    elif location == "json":
        body = json.dumps({parameter: payload}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif location in {"form", "body"}:
        body = parse.urlencode({parameter: payload}).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        raise McpError(-32602, f"Unsupported active test parameter location: {location}")

    if credential_id:
        credential = credentials.credential_for_target(str(credential_id), request_url)
        headers.update(credentials.headers_for_credential_target(credential, request_url))
    return {"url": request_url, "method": method, "headers": headers, "body": body.decode("utf-8") if body else "", "_bodyBytes": body}


def build_manual_replay(
    args: dict[str, Any],
    *,
    adapter: str,
    payloads: list[str],
    expected_signals: list[str],
    guardrails: list[str],
    required_parameter: bool = True,
) -> dict[str, Any]:
    candidate = coerce_candidate(args, required_parameter=required_parameter)
    target_url = str(candidate.get("url", ""))
    method = str(candidate.get("method", "GET")).upper()
    parameter = str(candidate.get("parameter", ""))
    location = str(candidate.get("location", "query"))
    if not target_url:
        raise McpError(-32602, "A target url is required.")
    if required_parameter and not parameter:
        raise McpError(-32602, "A parameter is required.")
    allowed = [str(payload) for payload in payloads if str(payload)]
    payload = str(args.get("payload") or (allowed[0] if allowed else ""))
    if payload not in allowed:
        raise McpError(-32602, f"{adapter} manual replay only supports built-in benign payloads.")
    built = build_http_request(target_url, method, parameter, location, payload)
    request = {
        "method": built["method"],
        "url": built["url"],
        "headers": redact_headers(built["headers"]),
        "body": built["body"],
    }
    return {
        "adapter": adapter,
        "sendsTraffic": False,
        "candidateId": candidate.get("candidateId", ""),
        "target": target_url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "payload": payload,
        "allowedPayloads": allowed,
        "request": request,
        "expectedSignals": expected_signals,
        "guardrails": [
            "This helper builds a replayable request only; it does not send traffic.",
            "Replay only against explicitly authorized in-scope targets after operator approval.",
            *guardrails,
        ],
        "replayInstructions": [
            "Review the generated request in Burp Repeater or an equivalent manual client.",
            "Send only one benign payload at a time and compare the response with the original request.",
            "Record the request, response, payload, and observed signal as evidence if behavior is relevant.",
        ],
    }


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for name, value in headers.items():
        redacted[name] = "<redacted>" if is_sensitive_header_name(name) else value
    return redacted


def is_sensitive_header_name(name: Any) -> bool:
    normalized = str(name).strip().lower()
    return normalized in {"authorization", "cookie", "set-cookie"} or any(
        marker in normalized
        for marker in (
            "api-key",
            "apikey",
            "auth",
            "credential",
            "csrf",
            "jwt",
            "secret",
            "session",
            "token",
        )
    )


def is_sensitive_value_name(name: Any) -> bool:
    normalized = str(name).strip().lower().replace("_", "-")
    return normalized in {"authorization", "cookie", "set-cookie"} or any(
        marker in normalized
        for marker in (
            "api-key",
            "apikey",
            "auth",
            "bearer",
            "credential",
            "csrf",
            "jwt",
            "passwd",
            "password",
            "secret",
            "session",
            "token",
        )
    )


def redact_value_preview(name: Any, value: Any, *, limit: int = 120) -> str:
    text = str(value)
    return "<redacted>" if is_sensitive_value_name(name) and text else text[:limit]


def response_summary(response: dict[str, Any], *, body_preview_bytes: int = 0) -> dict[str, Any]:
    body = str(response.get("body", "") or "")
    headers = response.get("headers", {})
    header_map = {str(name).lower(): str(value) for name, value in headers.items()} if isinstance(headers, dict) else {}
    selected_headers: dict[str, str] = {}
    for name in ("content-type", "location", "cache-control", "www-authenticate", "set-cookie"):
        if name in header_map:
            selected_headers[name] = "<set-cookie-present>" if name == "set-cookie" else header_map[name][:200]
    summary: dict[str, Any] = {
        "status": response.get("status"),
        "headers": selected_headers,
        "bodyLength": len(body),
        "bodySha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else "",
        "error": response.get("error", ""),
    }
    if body_preview_bytes > 0:
        summary["bodyPreview"] = body[:body_preview_bytes]
    return summary


def store_http_exchange_evidence(
    workspace_id: str,
    target: str,
    source: str,
    *,
    request: dict[str, Any],
    response: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = workspace.store_raw_evidence(
        workspace_id,
        target,
        source,
        "http_exchange",
        "json",
        json.dumps(
            {
                "request": _json_safe(_redact_http_message(request)),
                "response": _json_safe(_redact_http_message(response)),
            },
            indent=2,
            ensure_ascii=False,
        ),
        metadata or {},
    )
    return {
        "evidenceId": record.get("evidenceId", ""),
        "rawPath": record.get("rawPath", ""),
        "source": record.get("source", source),
        "dataType": record.get("dataType", "http_exchange"),
    }


def _redact_http_message(message: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(message)
    headers = redacted.get("headers")
    if isinstance(headers, dict):
        redacted["headers"] = redact_headers({str(name): str(value) for name, value in headers.items()})
    cookies = redacted.get("cookies")
    if isinstance(cookies, list):
        redacted["cookies"] = [_redact_cookie_record(cookie) for cookie in cookies]
    return redacted


def _redact_cookie_record(cookie: Any) -> Any:
    if not isinstance(cookie, dict):
        return "<redacted>"
    redacted = dict(cookie)
    if redacted.get("value"):
        redacted["value"] = "<redacted>"
    return redacted


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items() if not str(key).startswith("_")}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def stable_slug(value: Any) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip().lower()).strip("-")
    return slug or "candidate"


def priority_for_score(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"
