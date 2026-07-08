# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from typing import Any

from pydantic import ValidationError

from ...core.adapters.results import PretextCandidateEntity


SOPHISTICATION_TIERS = {"low", "medium", "high"}


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_adapter_result(raw: dict[str, Any]) -> PretextCandidateEntity:
    """Normalize a generated pretext dict without workspace context."""

    if not isinstance(raw, dict):
        raise ValueError("raw pretext candidate must be an object.")
    tier = str(raw.get("sophisticationTier", raw.get("sophistication_tier", "")) or "")
    if tier not in SOPHISTICATION_TIERS:
        raise ValueError("sophisticationTier must be one of: low, medium, high.")
    payload = dict(raw)
    payload.setdefault("status", "draft")
    payload.setdefault("sourceObservationRefs", [])
    try:
        return PretextCandidateEntity(**payload)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def ingest_data(
    entity: PretextCandidateEntity,
    workspace_id: str,
    target: str,
    existing_state: dict[str, list[dict[str, Any]]],
) -> PretextCandidateEntity:
    """Workspace-aware pretext normalization.

    This validates source observation references against the target state and
    stamps workspace-owned fields, but it does not persist or merge anything.
    """

    payload = entity.as_dict()
    refs = [str(ref) for ref in payload.get("sourceObservationRefs", []) if str(ref)]
    payload["sourceObservationRefs"] = refs
    missing = [ref for ref in refs if not _observation_ref_exists(ref, existing_state)]
    payload["missingEvidenceIds"] = missing
    payload.setdefault("createdAt", _now_utc())
    payload["workspaceId"] = workspace_id
    payload["target"] = target
    return PretextCandidateEntity(**payload)


def approve_pretext_candidate(workspace_id: str, target: str, entity_key: str, confirm: bool = False) -> dict[str, Any]:
    """Operator gate for promoting a draft pretext candidate to approved."""

    from ...core import evidence, workspace
    from ...core.errors import McpError

    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    key = str(entity_key or "").strip()
    if not key:
        raise McpError(-32602, "entityKey is required.")
    with workspace.workspace_lock(wid):
        path = workspace.target_entity_path(wid, host, "pretextCandidates")
        items = workspace._read_json(path, [])
        if not isinstance(items, list):
            items = []
        matched = next(
            (
                item
                for item in items
                if isinstance(item, dict)
                and key in {str(item.get("key", "")), workspace._entity_key(item)}
            ),
            None,
        )
        if matched is None:
            raise McpError(-32602, f"Pretext candidate not found: {key}")
        if not confirm:
            return {
                "approved": False,
                "requiresConfirmation": True,
                "message": "Call approve_pretext_candidate again with confirm=true after operator review.",
                "workspaceId": wid,
                "target": host,
                "entityKey": key,
                "pretextCandidate": dict(matched),
            }
        approved_at = workspace.now_utc()
        matched["status"] = "approved"
        matched["approvedAt"] = approved_at
        matched["updatedAt"] = approved_at
        workspace._write_json(path, items)
    evidence.log_event(
        "pretext.approved",
        f"Approved pretext candidate {key} for {host}.",
        {"workspaceId": wid, "target": host, "entityKey": key, "approvedAt": approved_at},
    )
    return {
        "approved": True,
        "requiresConfirmation": False,
        "workspaceId": wid,
        "target": host,
        "entityKey": key,
        "pretextCandidate": dict(matched),
    }


def _observation_ref_exists(ref: str, existing_state: dict[str, list[dict[str, Any]]]) -> bool:
    from ...core import workspace

    observations = existing_state.get("observations", [])
    if not isinstance(observations, list):
        return False
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        candidates = {
            str(observation.get("id", "")),
            str(observation.get("key", "")),
            str(observation.get("candidateId", "")),
            str(observation.get("observationId", "")),
            workspace._entity_key(observation),
        }
        if ref in candidates:
            return True
    return False
