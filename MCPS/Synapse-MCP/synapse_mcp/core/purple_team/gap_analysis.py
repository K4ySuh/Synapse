# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from .. import evidence, workspace
from ..adapters.results import ActionEntity, DetectionGapFindingEntity
from ..errors import McpError
from .technique_reference import TECHNIQUE_DETECTION_MAP


def generate_gap_finding(action: ActionEntity, detected: bool | None, notes: str) -> DetectionGapFindingEntity | None:
    technique_id = str(action.mitre_technique_id or "").strip()
    reference = TECHNIQUE_DETECTION_MAP.get(technique_id)
    if not technique_id or reference is None:
        return None
    action_ref = action.key or action.action_id
    return DetectionGapFindingEntity(
        actionRef=action_ref,
        mitreTechniqueId=technique_id,
        detected=detected,
        criticality=reference.criticality,
        expectedDetectionSources=list(reference.expected_detection_sources),
        notes=notes,
    )


def mark_detection_outcome(
    workspace_id: str,
    target: str,
    action_key: str,
    detected: bool | None,
    notes: str = "",
) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(workspace_id)
    host = workspace.normalize_target(target)
    key = str(action_key or "").strip()
    if not key:
        raise McpError(-32602, "actionKey is required.")
    marked_at = workspace.now_utc()
    with workspace.workspace_lock(wid):
        actions_path = workspace.target_entity_path(wid, host, "actions")
        actions = workspace._read_json(actions_path, [])
        if not isinstance(actions, list):
            actions = []
        action = next((item for item in actions if isinstance(item, dict) and _action_matches(item, key)), None)
        if action is None:
            raise McpError(-32602, f"Action not found: {key}")
        action["detected"] = detected
        action["detectionNotes"] = notes
        action["detectionMarkedAt"] = marked_at
        action["updatedAt"] = marked_at
        workspace._write_json(actions_path, actions)

        gap = generate_gap_finding(ActionEntity(**action), detected, notes)
        stored_gap: dict[str, Any] | None = None
        created = 0
        if gap is not None:
            gap_payload = gap.as_dict()
            # as_dict() drops None via exclude_none, so an explicit "unknown"
            # (detected=None) would otherwise be absent from the merge payload and
            # never override a previously recorded True/False. Carry it explicitly.
            gap_payload["detected"] = detected
            gap_payload["target"] = host
            gap_payload["updatedAt"] = marked_at
            gap_payload.setdefault("createdAt", marked_at)
            gap_payload["key"] = workspace._entity_key(gap_payload)
            stored_gaps, created = workspace._merge_entities(
                workspace.target_entity_path(wid, host, "detectionGaps"),
                [gap_payload],
                "",
            )
            stored_gap = next((item for item in stored_gaps if isinstance(item, dict) and item.get("key") == gap_payload["key"]), gap_payload)
    evidence.log_event(
        "purple_team.detection_outcome",
        f"Recorded detection outcome for action {key} on {host}.",
        {
            "workspaceId": wid,
            "target": host,
            "actionKey": key,
            "detected": detected,
            "gapFindingKey": stored_gap.get("key", "") if stored_gap else "",
        },
    )
    return {
        "workspaceId": wid,
        "target": host,
        "actionKey": key,
        "detected": detected,
        "notes": notes,
        "action": action,
        "detectionGap": stored_gap,
        "created": bool(created),
    }


def _action_matches(action: dict[str, Any], key: str) -> bool:
    return key in {
        str(action.get("key", "")),
        str(action.get("actionId", "")),
        workspace._entity_key(action),
    }
