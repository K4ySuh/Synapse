# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..errors import McpError
from .. import evidence
from .models import RedactionPolicy


SENSITIVE_MARKERS = {
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "jwt",
    "key",
    "otp",
    "pass",
    "password",
    "secret",
    "session",
    "token",
}
BODY_FIELDS = {"body", "requestbody", "responsebody", "rawbody", "content"}
REQUEST_FIELDS = {"request", "rawrequest", "requestbody"}
RESPONSE_FIELDS = {"response", "rawresponse", "responsebody"}
REDACTED = evidence.REDACTED_VALUE


def policy_from_args(args: dict[str, Any] | None = None) -> RedactionPolicy:
    args = args or {}
    mode = str(args.get("redactionMode", args.get("mode", "high_level")) or "high_level").lower().replace("-", "_")
    if mode not in {"safe", "high_level", "internal", "raw"}:
        raise McpError(-32602, "redactionMode must be one of: high_level, internal, raw. safe is accepted as a deprecated alias.")
    include_raw_http = bool(args.get("includeRawHttp", False))
    include_request_bodies = bool(args.get("includeRequestBodies", False))
    include_response_bodies = bool(args.get("includeResponseBodies", False))
    include_credentials = bool(args.get("includeCredentials", False))
    if mode == "safe":
        include_raw_http = False
        include_request_bodies = False
        include_response_bodies = False
        include_credentials = False
    elif mode == "internal":
        include_credentials = False
    return RedactionPolicy(
        mode=mode,
        include_raw_http=include_raw_http,
        include_request_bodies=include_request_bodies,
        include_response_bodies=include_response_bodies,
        include_credentials=include_credentials,
        include_approval_metadata=bool(args.get("includeApprovalMetadata", True)),
        include_hashes=bool(args.get("includeHashes", True)),
    )


def redact(value: Any, policy: RedactionPolicy, *, field_name: str = "") -> Any:
    marker = _field_marker(field_name)
    if isinstance(value, dict):
        entity_type = str(value.get("type", "") or "")
        if entity_type == "pretext_candidate":
            return redact_pretext_candidate(value, policy)
    if marker in BODY_FIELDS and not _body_allowed(marker, policy):
        return _hashable_redaction(value, policy)
    if marker in REQUEST_FIELDS and not policy.include_raw_http:
        return _hashable_redaction(value, policy)
    if marker in RESPONSE_FIELDS and not policy.include_raw_http:
        return _hashable_redaction(value, policy)
    if _is_sensitive_field(marker) and not policy.include_credentials and not isinstance(value, (int, float)):
        # The sensitive-field-name heuristic guards secret *values* (strings, or containers of
        # them). A numeric scalar — e.g. a per-module candidate count under a label like
        # "Headers Cookies" whose marker merely contains "cookie" — is an aggregate, not a
        # secret, and must not be redacted (bool is an int subclass, so flags are spared too).
        return REDACTED
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in {"approval", "approvalMetadata"} and not policy.include_approval_metadata:
                continue
            out[key_text] = redact(item, policy, field_name=key_text)
        return out
    if isinstance(value, list):
        return [redact(item, policy, field_name=field_name) for item in value]
    if isinstance(value, str) and not policy.include_credentials:
        return _redact_secret_strings(value)
    return value


def redact_pretext_candidate(candidate: dict[str, Any], policy: RedactionPolicy) -> dict[str, Any]:
    """Entity-specific pretext rule.

    Safe/high-level reports may only keep aggregate dimensions. Internal/raw
    operator views retain the actual body and provenance reference IDs.
    """

    if _safe_report_mode(policy):
        return {
            "type": "pretext_candidate",
            "sophisticationTier": candidate.get("sophisticationTier", ""),
            "status": candidate.get("status", "draft"),
        }
    return {
        "type": "pretext_candidate",
        "target": candidate.get("target", ""),
        "subject": candidate.get("subject", ""),
        "senderPersona": candidate.get("senderPersona", ""),
        "bodyTemplate": candidate.get("bodyTemplate", ""),
        "sophisticationTier": candidate.get("sophisticationTier", ""),
        "status": candidate.get("status", "draft"),
        "sourceObservationRefs": [str(item) for item in candidate.get("sourceObservationRefs", []) if str(item)],
        "missingEvidenceIds": [str(item) for item in candidate.get("missingEvidenceIds", []) if str(item)],
        "createdAt": candidate.get("createdAt", ""),
        "approvedAt": candidate.get("approvedAt", ""),
    }


def pretext_report_section(candidates: list[dict[str, Any]], policy: RedactionPolicy) -> dict[str, Any]:
    if _safe_report_mode(policy):
        counts: dict[str, dict[str, int]] = {}
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            tier = str(candidate.get("sophisticationTier", "") or "unknown")
            status = str(candidate.get("status", "") or "draft")
            counts.setdefault(tier, {}).setdefault(status, 0)
            counts[tier][status] += 1
        return {
            "mode": "aggregate",
            "total": sum(sum(statuses.values()) for statuses in counts.values()),
            "counts": counts,
            "summaryLine": _pretext_summary_line(counts),
        }
    return {
        "mode": "operator",
        "total": len([item for item in candidates if isinstance(item, dict)]),
        "items": [redact_pretext_candidate(item, policy) for item in candidates if isinstance(item, dict)],
    }


def detection_gap_report_section(gaps: list[dict[str, Any]], policy: RedactionPolicy) -> dict[str, Any]:
    if _safe_report_mode(policy):
        return {"mode": "excluded", "items": []}
    return {"mode": "operator", "items": [redact(item, policy) for item in gaps if isinstance(item, dict)]}


def _safe_report_mode(policy: RedactionPolicy) -> bool:
    return policy.mode in {"safe", "high_level"}


def _pretext_summary_line(counts: dict[str, dict[str, int]]) -> str:
    if not counts:
        return "No pretext candidates recorded."
    parts: list[str] = []
    for tier in ("high", "medium", "low", "unknown"):
        statuses = counts.get(tier, {})
        for status in ("draft", "approved"):
            count = int(statuses.get(status, 0) or 0)
            if not count:
                continue
            noun = "pretext" if count == 1 else "pretexts"
            verb = "drafted" if status == "draft" else "approved"
            parts.append(f"{count} {tier}-sophistication {noun} {verb}")
    return "; ".join(parts) + "."


def evidence_summary(record: dict[str, Any], policy: RedactionPolicy, raw_content: str | None = None) -> dict[str, Any]:
    summary = {
        "evidenceId": record.get("evidenceId", ""),
        "source": record.get("source", ""),
        "dataType": record.get("dataType", ""),
        "format": record.get("format", ""),
        "createdAt": record.get("createdAt", ""),
        "metadata": redact(record.get("metadata", {}), policy),
    }
    if policy.mode != "safe":
        summary["rawPath"] = record.get("rawPath", "")
    if raw_content is not None and policy.include_raw_http:
        summary["raw"] = redact(raw_content, policy, field_name="rawRequest")
    if policy.include_hashes and raw_content is not None:
        summary["sha256"] = hashlib.sha256(raw_content.encode("utf-8", errors="replace")).hexdigest()
    return summary


def _body_allowed(marker: str, policy: RedactionPolicy) -> bool:
    if marker == "requestbody":
        return policy.include_request_bodies
    if marker == "responsebody":
        return policy.include_response_bodies
    return policy.include_request_bodies or policy.include_response_bodies


def _hashable_redaction(value: Any, policy: RedactionPolicy) -> Any:
    if not policy.include_hashes:
        return REDACTED
    text = str(value)
    return {"redacted": True, "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()}


def _field_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_sensitive_field(marker: str) -> bool:
    return marker in evidence.SENSITIVE_FIELD_NAMES or any(item in marker for item in SENSITIVE_MARKERS)


def _redact_secret_strings(value: str) -> str:
    result = re.sub(r"(?i)(authorization:\s*)(bearer|basic)\s+[^\r\n]+", r"\1\2 [REDACTED]", value)
    result = re.sub(r"(?i)(cookie:\s*)[^\r\n]+", r"\1[REDACTED]", result)
    result = re.sub(r"(?i)(set-cookie:\s*)[^\r\n]+", r"\1[REDACTED]", result)
    return result
