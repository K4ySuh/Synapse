# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from difflib import SequenceMatcher
from typing import Any


SELECTED_HEADERS = ("content-type", "location", "cache-control", "www-authenticate", "set-cookie")
SENSITIVE_MARKERS = ("email", "username", "user_id", "account_id", "tenant_id", "role", "permission", "token", "secret")


def compare_http_responses(response_a: dict[str, Any], response_b: dict[str, Any]) -> dict[str, Any]:
    status_a = response_a.get("status") or response_a.get("statusCode")
    status_b = response_b.get("status") or response_b.get("statusCode")
    body_a = _body_text(response_a)
    body_b = _body_text(response_b)
    headers_a = _headers(response_a)
    headers_b = _headers(response_b)
    content_type_a = headers_a.get("content-type", "")
    content_type_b = headers_b.get("content-type", "")
    location_a = headers_a.get("location", "")
    location_b = headers_b.get("location", "")
    json_keys_a = _json_keys(body_a)
    json_keys_b = _json_keys(body_b)
    length_delta_percent = _length_delta_percent(len(body_a), len(body_b))
    body_similarity = round(SequenceMatcher(None, body_a[:12000], body_b[:12000]).ratio(), 3) if (body_a or body_b) else 1.0
    json_overlap = _set_overlap(json_keys_a, json_keys_b)
    marker_a = _marker_presence(body_a, headers_a)
    marker_b = _marker_presence(body_b, headers_b)
    interesting = []
    if status_a != status_b:
        interesting.append(f"Status changed from {status_a} to {status_b}.")
    if content_type_a != content_type_b:
        interesting.append(f"Content-Type changed from {content_type_a or '<none>'} to {content_type_b or '<none>'}.")
    if location_a != location_b:
        interesting.append("Redirect Location differs between responses.")
    if length_delta_percent >= 20:
        interesting.append(f"Response body length changed by {length_delta_percent}%.")
    for key in sorted(json_keys_b - json_keys_a)[:10]:
        interesting.append(f"Response B contains additional JSON key: {key}")
    for key in sorted(json_keys_a - json_keys_b)[:10]:
        interesting.append(f"Response A contains additional JSON key: {key}")
    for marker in sorted(marker_a ^ marker_b):
        side = "B" if marker in marker_b else "A"
        interesting.append(f"Sensitive marker appears only in response {side}: {marker}")
    confidence = _confidence(status_a != status_b, length_delta_percent, body_similarity, json_overlap, bool(marker_a ^ marker_b))
    return {
        "statusDelta": status_a != status_b,
        "statusA": status_a,
        "statusB": status_b,
        "lengthA": len(body_a),
        "lengthB": len(body_b),
        "lengthDeltaPercent": length_delta_percent,
        "contentTypeDelta": content_type_a != content_type_b,
        "contentTypeA": content_type_a,
        "contentTypeB": content_type_b,
        "redirectLocationDelta": location_a != location_b,
        "selectedHeaderDeltas": _selected_header_deltas(headers_a, headers_b),
        "jsonKeyOverlap": json_overlap,
        "bodySimilarity": body_similarity,
        "bodyIdentical": body_a == body_b,
        "sensitiveMarkersA": sorted(marker_a),
        "sensitiveMarkersB": sorted(marker_b),
        "interestingDifferences": interesting,
        "confidence": confidence,
    }


def _body_text(response: dict[str, Any]) -> str:
    body = response.get("body", "")
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body or "")


def _headers(response: dict[str, Any]) -> dict[str, str]:
    raw = response.get("headers", {})
    if not isinstance(raw, dict):
        return {}
    return {str(name).lower(): str(value) for name, value in raw.items()}


def _json_keys(body: str) -> set[str]:
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


def _set_overlap(a: set[str], b: set[str]) -> float | None:
    if not a and not b:
        return None
    union = a | b
    return round(len(a & b) / len(union), 3) if union else None


def _length_delta_percent(length_a: int, length_b: int) -> float:
    baseline = max(length_a, 1)
    return round(abs(length_b - length_a) / baseline * 100, 2)


def _marker_presence(body: str, headers: dict[str, str]) -> set[str]:
    haystack = (body + "\n" + json.dumps(headers, sort_keys=True)).lower()
    return {marker for marker in SENSITIVE_MARKERS if marker in haystack}


def _selected_header_deltas(headers_a: dict[str, str], headers_b: dict[str, str]) -> list[dict[str, str]]:
    deltas = []
    for name in SELECTED_HEADERS:
        value_a = headers_a.get(name, "")
        value_b = headers_b.get(name, "")
        if value_a != value_b:
            deltas.append({"header": name, "a": _safe_header_value(name, value_a), "b": _safe_header_value(name, value_b)})
    return deltas


def _safe_header_value(name: str, value: str) -> str:
    if name == "set-cookie" and value:
        return "<set-cookie-present>"
    return value[:200]


def _confidence(status_delta: bool, length_delta_percent: float, body_similarity: float, json_overlap: float | None, marker_delta: bool) -> str:
    score = 0
    if status_delta:
        score += 2
    if length_delta_percent >= 30:
        score += 2
    elif length_delta_percent >= 10:
        score += 1
    if body_similarity < 0.5:
        score += 2
    elif body_similarity < 0.8:
        score += 1
    if json_overlap is not None and json_overlap < 0.75:
        score += 1
    if marker_delta:
        score += 2
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"
