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
