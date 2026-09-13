# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Shared field merge policy for canonical entity ingestion."""

from __future__ import annotations

from typing import Any


_MERGE_UNION_FIELDS = {
    "evidenceIds",
    "missingEvidenceIds",
    "statusCodes",
    "cookieNames",
    "responseCookieNames",
    "responseCookieFlags",
    "contentTypes",
    "requestContentTypes",
    "authorizationSchemes",
    "redirectLocations",
    "queryParameters",
    "bodyParameters",
    "jsonParameters",
    "errorSignals",
    "tags",
    "reasons",
    "affectedUrls",
    "candidateFor",
    "sourceObservationRefs",
}
_MERGE_REPLACE_FIELDS = {"updatedAt", "lastSeenAt"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def merge_entity_fields(merged: dict[str, Any], item: dict[str, Any]) -> None:
    for name, value in item.items():
        if name in _MERGE_UNION_FIELDS:
            current = merged.get(name)
            current_list = current if isinstance(current, list) else ([] if current in ("", None) else [current])
            merged[name] = current_list + [entry for entry in (value if isinstance(value, list) else [value]) if entry not in current_list]
        elif name in _MERGE_REPLACE_FIELDS:
            if value not in ("", None):
                merged[name] = value
        elif name == "severity":
            # Severity only escalates automatically; operator-reviewed records
            # keep whatever the operator decided.
            current_rank = SEVERITY_RANK.get(str(merged.get("severity", "") or ""), -1)
            incoming_rank = SEVERITY_RANK.get(str(value or ""), -1)
            if incoming_rank > current_rank and not merged.get("operatorReviewed"):
                merged[name] = value
        elif name == "isReportable":
            # Reportability is an operator/agent disposition, not adapter data. Every
            # re-ingest carries the default True; it must never override a stored
            # decision (especially a False that suppressed a reviewed false positive).
            # Preserve whatever is already stored; only seed legacy records missing it.
            if "isReportable" not in merged:
                merged[name] = value
        elif name == "candidateDetails" and isinstance(value, dict):
            # One consolidated test_candidate accumulates per-vuln-class detail as each
            # injection adapter contributes its class; keep the first detail per class.
            current = merged.get("candidateDetails")
            current = current if isinstance(current, dict) else {}
            for vuln_class, detail in value.items():
                current.setdefault(vuln_class, detail)
            merged["candidateDetails"] = current
        elif name == "priorityScore" and merged.get("type") == "test_candidate":
            merged[name] = max(int(merged.get(name, 0) or 0), int(value or 0))
        elif name == "priority" and merged.get("type") == "test_candidate":
            current_rank = SEVERITY_RANK.get(str(merged.get("priority", "") or ""), -1)
            incoming_rank = SEVERITY_RANK.get(str(value or ""), -1)
            if incoming_rank > current_rank:
                merged[name] = value
        elif name == "bodyTemplate" and merged.get("type") == "pretext_candidate":
            if value not in ("", None):
                merged[name] = value
        elif name in {"detected", "notes"} and merged.get("type") == "detection_gap":
            merged[name] = value
        elif value not in ("", None, [], {}) and not merged.get(name):
            merged[name] = value
    # A class refuted by the validation lifecycle must not be resurrected by a later
    # re-scan: keep candidateFor free of classes marked refuted in candidateDetails.
    if merged.get("type") == "test_candidate" and isinstance(merged.get("candidateFor"), list):
        details = merged.get("candidateDetails") if isinstance(merged.get("candidateDetails"), dict) else {}
        refuted = {cls for cls, detail in details.items() if isinstance(detail, dict) and detail.get("validationStatus") == "refuted"}
        if refuted:
            merged["candidateFor"] = [cls for cls in merged["candidateFor"] if cls not in refuted]
