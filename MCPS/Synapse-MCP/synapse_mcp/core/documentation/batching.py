# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Stable, bounded workspace audit planning and report generation."""

from __future__ import annotations

from copy import deepcopy
from html import escape
from pathlib import Path
from typing import Any

from .. import evidence, perimeter, scope, workspace
from ..errors import McpError
from . import layers
from .layer_renderer import render_workspace_report


DEFAULT_BATCH_SIZE = 20
MAX_BATCH_SIZE = 40


def plan_scope_groups(args: dict[str, Any]) -> dict[str, Any]:
    """Persist stable groups and return a compact, paginated MCP response."""
    manifest = _build_scope_group_manifest(args)
    return _compact_scope_group_manifest(manifest, args)


def _build_scope_group_manifest(args: dict[str, Any]) -> dict[str, Any]:
    """Build or reuse the complete on-disk manifest for internal consumers."""
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    workspace.ensure_workspace(wid)
    size = _batch_size(args.get("targetBatchSize"), "targetBatchSize")
    path = workspace.workspace_report_dir(wid) / "scope-groups.json"
    inventory = _target_inventory(wid)
    existing = workspace._read_json(path, {})
    explicit = args.get("scopeGroups")
    refresh = args.get("refreshGroups") is True

    compatible_existing = (
        isinstance(existing, dict)
        and existing.get("groups")
        and int(existing.get("targetBatchSize", size) or size) == size
        and explicit is None
        and not refresh
    )
    if compatible_existing and _existing_targets(existing) == set(inventory):
        return existing

    relations = _relations(wid, inventory)

    if explicit is not None:
        groups = _explicit_groups(explicit, inventory, size)
    elif (
        compatible_existing
    ):
        groups = _extend_stable_groups(existing.get("groups", []), inventory, size, relations)
    else:
        groups = _automatic_groups(inventory, size, relations)

    assigned = {target for group in groups for target in group["targets"]}
    scope_snapshot = workspace.workspace_scope(wid)
    manifest = {
        "schemaVersion": 1,
        "workspaceId": wid,
        "generatedAt": workspace.now_utc(),
        "targetBatchSize": size,
        "authorizationScopeUnchanged": True,
        "inventory": {
            "enumerableTargetCount": len(inventory),
            "assignedTargetCount": len(assigned),
            "patterns": scope_snapshot.get("patterns", []),
            "cidrs": scope_snapshot.get("cidrs", []),
            "nonEnumerableScope": bool(scope_snapshot.get("patterns") or scope_snapshot.get("cidrs")),
            "outOfScopeWorkspaceTargets": _out_of_scope_workspace_targets(wid, scope_snapshot),
        },
        "groups": groups,
        "retiredTargets": sorted(_existing_targets(existing) - set(inventory)),
        "crossGroupRelations": _cross_group_relations(groups, relations),
        "relatedAssetsOutsideAuditGroups": _external_relations(wid, inventory),
        "gaps": _scope_gaps(scope_snapshot, inventory),
        "manifestPath": str(path),
    }
    workspace._write_json(path, manifest)
    return manifest


def _compact_scope_group_manifest(manifest: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    groups = manifest.get("groups", []) if isinstance(manifest.get("groups"), list) else []
    cursor = _bounded_int(args.get("groupCursor"), "groupCursor", default=0, minimum=0, maximum=len(groups))
    limit = _bounded_int(args.get("groupLimit"), "groupLimit", default=5, minimum=1, maximum=40)
    selected = groups[cursor : cursor + limit]
    include_targets = args.get("includeTargets") is True
    compact_groups = []
    for group in selected:
        targets = group.get("targets", []) if isinstance(group, dict) and isinstance(group.get("targets"), list) else []
        compact = {
            "groupId": group.get("groupId", ""),
            "name": group.get("name", ""),
            "targetCount": len(targets),
            "targetPreview": targets[:5],
        }
        if include_targets:
            compact["targets"] = targets
        compact_groups.append(compact)
    next_cursor = cursor + len(selected)
    cross_relations = manifest.get("crossGroupRelations", []) if isinstance(manifest.get("crossGroupRelations"), list) else []
    external_relations = (
        manifest.get("relatedAssetsOutsideAuditGroups", [])
        if isinstance(manifest.get("relatedAssetsOutsideAuditGroups"), list)
        else []
    )
    inventory = manifest.get("inventory", {}) if isinstance(manifest.get("inventory"), dict) else {}
    return {
        "schemaVersion": manifest.get("schemaVersion", 1),
        "workspaceId": manifest.get("workspaceId", ""),
        "generatedAt": manifest.get("generatedAt", ""),
        "targetBatchSize": manifest.get("targetBatchSize", DEFAULT_BATCH_SIZE),
        "authorizationScopeUnchanged": True,
        "inventory": {
            "enumerableTargetCount": inventory.get("enumerableTargetCount", 0),
            "assignedTargetCount": inventory.get("assignedTargetCount", 0),
            "patternCount": len(inventory.get("patterns", [])) if isinstance(inventory.get("patterns"), list) else 0,
            "cidrCount": len(inventory.get("cidrs", [])) if isinstance(inventory.get("cidrs"), list) else 0,
            "nonEnumerableScope": inventory.get("nonEnumerableScope", False),
            "outOfScopeWorkspaceTargetCount": len(inventory.get("outOfScopeWorkspaceTargets", []))
            if isinstance(inventory.get("outOfScopeWorkspaceTargets"), list)
            else 0,
        },
        "groupCount": len(groups),
        "groups": compact_groups,
        "groupPage": {
            "cursor": cursor,
            "limit": limit,
            "returned": len(compact_groups),
            "nextCursor": next_cursor if next_cursor < len(groups) else None,
        },
        "relationCounts": {
            "crossGroup": len(cross_relations),
            "outsideAuditGroups": len(external_relations),
        },
        "retiredTargetCount": len(manifest.get("retiredTargets", [])) if isinstance(manifest.get("retiredTargets"), list) else 0,
        "gaps": manifest.get("gaps", []),
        "manifestPath": manifest.get("manifestPath", ""),
    }


def prepare_validation_batch(args: dict[str, Any]) -> dict[str, Any]:
    """Return one deterministic, resumable candidate-review queue page; sends no traffic."""
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    size = _batch_size(args.get("batchSize"), "batchSize")
    plan = _build_scope_group_manifest(args)
    group_id = str(args.get("groupId") or (plan["groups"][0]["groupId"] if plan["groups"] else ""))
    group = next((item for item in plan["groups"] if item["groupId"] == group_id), None)
    if group is None:
        raise McpError(-32602, f"Unknown scope group: {group_id}")
    queue_path = workspace.workspace_report_dir(wid) / "validation-queues" / f"{group_id}.json"
    snapshot = workspace._read_json(queue_path, {})
    if isinstance(snapshot, dict) and isinstance(snapshot.get("candidates"), list) and args.get("refreshQueue") is not True:
        queue = [item for item in snapshot["candidates"] if isinstance(item, dict)]
        snapshot_generated_at = str(snapshot.get("generatedAt") or workspace.now_utc())
    else:
        queue = _validation_queue(wid, group["targets"])
        snapshot_generated_at = workspace.now_utc()
        workspace._write_json(
            queue_path,
            {
                "schemaVersion": 1,
                "workspaceId": wid,
                "groupId": group_id,
                "generatedAt": snapshot_generated_at,
                "targets": group["targets"],
                "candidateCount": len(queue),
                "candidates": queue,
            },
        )
    cursor = _cursor(args.get("cursor"), len(queue))
    page = queue[cursor : cursor + size]
    next_cursor = cursor + len(page)
    payload = {
        "schemaVersion": 1,
        "workspaceId": wid,
        "groupId": group_id,
        "generatedAt": snapshot_generated_at,
        "snapshotStable": True,
        "sendsTraffic": False,
        "requiresApprovalBeforeExecution": True,
        "batchSize": size,
        "cursor": cursor,
        "nextCursor": next_cursor if next_cursor < len(queue) else None,
        "totalCandidates": len(queue),
        "returnedCount": len(page),
        "remainingCount": max(0, len(queue) - next_cursor),
        "candidates": page,
        "queuePath": str(queue_path),
    }
    return payload


def render_workspace_report_batches(args: dict[str, Any]) -> dict[str, Any]:
    """Render bounded report parts for a bounded number of stable scope groups."""
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    record_size = _batch_size(args.get("recordBatchSize"), "recordBatchSize")
    plan = _build_scope_group_manifest(args)
    group_cursor = _cursor(args.get("groupCursor"), len(plan["groups"]))
    max_groups = _bounded_int(args.get("maxGroups"), "maxGroups", default=1, minimum=1, maximum=10)
    max_parts = _bounded_int(args.get("maxParts"), "maxParts", default=1, minimum=1, maximum=40)
    requested_part_cursor = _bounded_int(args.get("partCursor"), "partCursor", default=0, minimum=0, maximum=1_000_000)
    selected = plan["groups"][group_cursor : group_cursor + max_groups]
    run_id = workspace.slug(str(args.get("runId") or f"audit-{workspace.now_utc().replace(':', '').replace('-', '')}"))
    run_root = workspace.workspace_report_dir(wid) / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    manifest_path = run_root / "manifest.json"
    prior_manifest = workspace._read_json(manifest_path, {})
    if not isinstance(prior_manifest, dict):
        prior_manifest = {}
    requested_layers = layers._selected_layers(args)
    if prior_manifest and (
        int(prior_manifest.get("targetBatchSize", plan["targetBatchSize"])) != plan["targetBatchSize"]
        or int(prior_manifest.get("recordBatchSize", record_size)) != record_size
        or prior_manifest.get("layers", requested_layers) != requested_layers
    ):
        raise McpError(-32602, "The existing runId uses different target, record, or layer batching settings; choose a new runId.")
    prior_groups = {
        str(item.get("groupId")): item
        for item in prior_manifest.get("groups", [])
        if isinstance(item, dict) and item.get("groupId")
    }
    newly_rendered_groups: list[dict[str, Any]] = []
    part_budget = max_parts
    resume_group_cursor: int | None = None
    resume_part_cursor: int | None = None

    for selected_index, group in enumerate(selected):
        if part_budget <= 0:
            break
        context = layers.build_workspace_report_context({**args, "targets": group["targets"]})["workspaceReport"]
        part_cursor = requested_part_cursor if selected_index == 0 else 0
        parts, total_records, part_count, next_part_cursor = _paginate_context(
            context,
            record_size,
            part_cursor=part_cursor,
            max_parts=part_budget,
        )
        group_root = run_root / group["groupId"]
        group_root.mkdir(parents=True, exist_ok=True)
        part_records = []
        for part in parts:
            part_number = int(part["summary"]["batch"]["part"])
            part_name = f"part-{part_number:03d}"
            html_path = group_root / f"{part_name}.html"
            json_path = group_root / f"{part_name}.json"
            html_path.write_text(render_workspace_report(part, "html"), encoding="utf-8")
            workspace._write_json(json_path, {"contextType": "workspace_report", "workspaceReport": part})
            part_records.append(
                {
                    "part": part_number,
                    "recordCount": part["summary"]["batch"]["includedRecordCount"],
                    "reportPath": str(html_path),
                    "contextPath": str(json_path),
                }
            )
        prior_group = prior_groups.get(group["groupId"], {})
        prior_parts = {
            int(item.get("part", 0)): item
            for item in prior_group.get("parts", [])
            if isinstance(prior_group, dict) and isinstance(item, dict) and int(item.get("part", 0) or 0) > 0
        }
        for item in part_records:
            prior_parts[item["part"]] = item
        combined_parts = [prior_parts[key] for key in sorted(prior_parts)]
        newly_rendered_groups.append(
            {
                "groupId": group["groupId"],
                "name": group["name"],
                "targets": group["targets"],
                "targetCount": len(group["targets"]),
                "totalRecordCount": total_records,
                "partCount": part_count,
                "renderedPartCount": len(combined_parts),
                "deferredPartCount": max(0, part_count - len(combined_parts)),
                "nextPartCursor": next_part_cursor,
                "parts": combined_parts,
            }
        )
        part_budget -= len(parts)
        if next_part_cursor is not None:
            resume_group_cursor = group_cursor + selected_index
            resume_part_cursor = next_part_cursor
            break

    for item in newly_rendered_groups:
        prior_groups[item["groupId"]] = item
    group_order = {group["groupId"]: index for index, group in enumerate(plan["groups"])}
    rendered_groups = sorted(prior_groups.values(), key=lambda item: group_order.get(str(item.get("groupId")), len(group_order)))
    completed_this_call = len(newly_rendered_groups)
    if resume_group_cursor is not None:
        next_group_cursor = resume_group_cursor
    else:
        next_group_cursor = min(len(plan["groups"]), group_cursor + completed_this_call)
    completed_groups = sum(1 for item in rendered_groups if int(item.get("renderedPartCount", 0)) >= int(item.get("partCount", 0)))
    run_manifest = {
        "schemaVersion": 1,
        "workspaceId": wid,
        "runId": run_id,
        "generatedAt": str(prior_manifest.get("generatedAt") or workspace.now_utc()),
        "updatedAt": workspace.now_utc(),
        "scopeGroupManifestPath": plan["manifestPath"],
        "targetBatchSize": plan["targetBatchSize"],
        "recordBatchSize": record_size,
        "maxParts": max_parts,
        "layers": requested_layers,
        "groupCursor": group_cursor,
        "nextGroupCursor": next_group_cursor if next_group_cursor < len(plan["groups"]) else None,
        "partCursor": requested_part_cursor,
        "nextPartCursor": resume_part_cursor,
        "groupCount": len(plan["groups"]),
        "renderedGroupCount": len(rendered_groups),
        "completedGroupCount": completed_groups,
        "deferredGroupCount": max(0, len(plan["groups"]) - completed_groups),
        "groups": rendered_groups,
        "coverageGaps": plan["gaps"],
    }
    index_path = run_root / "index.html"
    run_manifest["manifestPath"] = str(manifest_path)
    run_manifest["indexPath"] = str(index_path)
    workspace._write_json(manifest_path, run_manifest)
    index_path.write_text(_render_index(run_manifest), encoding="utf-8")
    evidence.log_event(
        "documentation.render_workspace_report_batches",
        f"Rendered {len(newly_rendered_groups)} bounded report group(s) for workspace {wid}.",
        {"workspaceId": wid, "runId": run_id, "manifestPath": str(manifest_path), "indexPath": str(index_path)},
    )
    return run_manifest


def _batch_size(value: Any, field: str) -> int:
    return _bounded_int(value, field, default=DEFAULT_BATCH_SIZE, minimum=1, maximum=MAX_BATCH_SIZE)


def _cursor(value: Any, total: int) -> int:
    return _bounded_int(value, "cursor", default=0, minimum=0, maximum=total)


def _bounded_int(value: Any, field: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise McpError(-32602, f"{field} must be an integer between {minimum} and {maximum}.") from exc
    if number < minimum or number > maximum:
        raise McpError(-32602, f"{field} must be between {minimum} and {maximum}.")
    return number


def _target_inventory(workspace_id: str) -> list[str]:
    scope_snapshot = workspace.workspace_scope(workspace_id)
    hosts = set(scope_snapshot.get("hosts", []))
    root = workspace.workspace_path(workspace_id) / "targets"
    for path in sorted(root.glob("*/target.json")) if root.exists() else []:
        target = workspace._read_json(path, {}).get("target")
        if target and scope.check_target_in_scope(str(target), scope_snapshot)["inScope"]:
            hosts.add(workspace.normalize_target(str(target)))
    return sorted(hosts)


def _out_of_scope_workspace_targets(workspace_id: str, scope_snapshot: dict[str, Any]) -> list[str]:
    root = workspace.workspace_path(workspace_id) / "targets"
    targets = []
    for path in sorted(root.glob("*/target.json")) if root.exists() else []:
        target = workspace._read_json(path, {}).get("target")
        if target and not scope.check_target_in_scope(str(target), scope_snapshot)["inScope"]:
            targets.append(workspace.normalize_target(str(target)))
    return targets


def _relations(workspace_id: str, inventory: list[str]) -> list[dict[str, str]]:
    allowed = set(inventory)
    relations: dict[tuple[str, str, str], dict[str, str]] = {}
    for target in inventory:
        for item in workspace.load_reportable_target_entities(workspace_id, target).get("observations", []):
            if not isinstance(item, dict) or item.get("type") != "asset_relation":
                continue
            source = workspace.normalize_target(str(item.get("sourceAsset") or target))
            related = workspace.normalize_target(str(item.get("targetAsset") or item.get("value") or ""))
            if source not in allowed or related not in allowed or source == related:
                continue
            relation_type = str(item.get("relationType") or "related_to")
            key = (source, related, relation_type)
            relations[key] = {"sourceAsset": source, "targetAsset": related, "relationType": relation_type}
    return [relations[key] for key in sorted(relations)]


def _external_relations(workspace_id: str, inventory: list[str]) -> list[dict[str, str]]:
    allowed = set(inventory)
    relations: dict[tuple[str, str, str], dict[str, str]] = {}
    for target in inventory:
        for item in workspace.load_reportable_target_entities(workspace_id, target).get("observations", []):
            if not isinstance(item, dict) or item.get("type") != "asset_relation":
                continue
            source = workspace.normalize_target(str(item.get("sourceAsset") or target))
            related = workspace.normalize_target(str(item.get("targetAsset") or item.get("value") or ""))
            if not related or (source in allowed and related in allowed):
                continue
            relation_type = str(item.get("relationType") or "related_to")
            relations[(source, related, relation_type)] = {
                "sourceAsset": source,
                "targetAsset": related,
                "relationType": relation_type,
                "scopeStatus": str(item.get("scopeStatus") or "out_of_scope_or_unresolved"),
                "trafficSent": False,
            }
    return [relations[key] for key in sorted(relations)]


def _automatic_groups(inventory: list[str], size: int, relations: list[dict[str, str]]) -> list[dict[str, Any]]:
    parent = {target: target for target in inventory}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    for relation in relations:
        left, right = relation["sourceAsset"], relation["targetAsset"]
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root
    components: dict[str, list[str]] = {}
    for target in inventory:
        components.setdefault(find(target), []).append(target)
    chunks: list[list[str]] = []
    pending: list[str] = []
    for component in sorted((sorted(value) for value in components.values()), key=lambda value: value[0]):
        if len(component) > size:
            if pending:
                chunks.append(pending)
                pending = []
            chunks.extend(component[index : index + size] for index in range(0, len(component), size))
        elif len(pending) + len(component) <= size:
            pending.extend(component)
        else:
            chunks.append(pending)
            pending = list(component)
    if pending:
        chunks.append(pending)
    return [_group(index, targets) for index, targets in enumerate(chunks, 1)]


def _extend_stable_groups(existing: list[Any], inventory: list[str], size: int, relations: list[dict[str, str]]) -> list[dict[str, Any]]:
    allowed = set(inventory)
    groups = []
    assigned: set[str] = set()
    used_ids: set[str] = set()
    for item in existing:
        if not isinstance(item, dict):
            continue
        targets = [str(target) for target in item.get("targets", []) if str(target) in allowed and str(target) not in assigned]
        if targets:
            group_id = str(item.get("groupId") or f"scope-{len(groups) + 1:03d}")
            groups.append(_group_record(group_id, targets, str(item.get("name") or "")))
            used_ids.add(group_id)
            assigned.update(targets)
    related: dict[str, set[str]] = {}
    for relation in relations:
        related.setdefault(relation["sourceAsset"], set()).add(relation["targetAsset"])
        related.setdefault(relation["targetAsset"], set()).add(relation["sourceAsset"])
    for target in inventory:
        if target in assigned:
            continue
        destination = next(
            (group for group in groups if len(group["targets"]) < size and related.get(target, set()).intersection(group["targets"])),
            None,
        )
        if destination is None:
            destination = next((group for group in groups if len(group["targets"]) < size), None)
        if destination is None:
            next_index = 1
            while f"scope-{next_index:03d}" in used_ids:
                next_index += 1
            destination = _group(next_index, [])
            groups.append(destination)
            used_ids.add(destination["groupId"])
        destination["targets"].append(target)
        destination["targetCount"] = len(destination["targets"])
        assigned.add(target)
    return groups


def _explicit_groups(value: Any, inventory: list[str], size: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise McpError(-32602, "scopeGroups must be an array.")
    allowed = set(inventory)
    assigned: set[str] = set()
    groups = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("targets"), list):
            raise McpError(-32602, "Each scopeGroups item must contain a targets array.")
        targets = [workspace.normalize_target(str(target)) for target in item["targets"]]
        if len(targets) > size:
            raise McpError(-32602, f"An explicit scope group exceeds targetBatchSize={size}.")
        invalid = [target for target in targets if target not in allowed or target in assigned]
        if invalid:
            raise McpError(-32602, f"Explicit scope group has unknown or duplicate targets: {', '.join(invalid)}")
        groups.append(_group(len(groups) + 1, targets, str(item.get("name") or "")))
        assigned.update(targets)
    remaining = [target for target in inventory if target not in assigned]
    for index in range(0, len(remaining), size):
        groups.append(_group(len(groups) + 1, remaining[index : index + size], "Unassigned scope"))
    return groups


def _group(index: int, targets: list[str], name: str = "") -> dict[str, Any]:
    group_id = f"scope-{index:03d}"
    return _group_record(group_id, targets, name)


def _group_record(group_id: str, targets: list[str], name: str = "") -> dict[str, Any]:
    default_name = f"Scope group {int(group_id.rsplit('-', 1)[-1])}" if group_id.rsplit("-", 1)[-1].isdigit() else group_id
    return {"groupId": group_id, "name": name or default_name, "targets": list(targets), "targetCount": len(targets)}


def _existing_targets(manifest: Any) -> set[str]:
    if not isinstance(manifest, dict):
        return set()
    return {str(target) for group in manifest.get("groups", []) if isinstance(group, dict) for target in group.get("targets", [])}


def _cross_group_relations(groups: list[dict[str, Any]], relations: list[dict[str, str]]) -> list[dict[str, str]]:
    target_group = {target: group["groupId"] for group in groups for target in group["targets"]}
    return [
        {**relation, "sourceGroupId": target_group[relation["sourceAsset"]], "targetGroupId": target_group[relation["targetAsset"]]}
        for relation in relations
        if target_group.get(relation["sourceAsset"]) != target_group.get(relation["targetAsset"])
    ]


def _scope_gaps(scope_snapshot: dict[str, Any], inventory: list[str]) -> list[str]:
    gaps = []
    if scope_snapshot.get("patterns"):
        gaps.append("Wildcard scope patterns are authorization rules, not enumerable assets; discovered matching targets are grouped when workspace state exists.")
    if scope_snapshot.get("cidrs"):
        gaps.append("CIDR scope entries are authorization rules, not automatically expanded; discovered addresses are grouped when workspace state exists.")
    if not inventory:
        gaps.append("No exact or workspace-known targets are currently available for grouping.")
    return gaps


def _validation_queue(workspace_id: str, targets: list[str]) -> list[dict[str, Any]]:
    per_target: dict[str, list[dict[str, Any]]] = {}
    for target in targets:
        entities = workspace.load_reportable_target_entities(workspace_id, target)
        candidates = perimeter.candidate_inventory(entities, target).get("items", [])
        seen = {_candidate_key(item) for item in candidates if isinstance(item, dict)}
        for observation in entities.get("observations", []):
            if not isinstance(observation, dict) or observation.get("retired") or observation.get("analysisEligible") is False:
                continue
            kind = str(observation.get("type", ""))
            if not (kind.endswith("_candidate") or kind in {"cve_candidate", "test_candidate"}):
                continue
            if _candidate_key(observation) not in seen:
                candidates.append(observation)
                seen.add(_candidate_key(observation))
        per_target[target] = sorted(
            ({"target": target, **item} for item in candidates if isinstance(item, dict)),
            key=lambda item: (-int(item.get("priorityScore", 0) or 0), str(item.get("type", "")), _candidate_key(item)),
        )
    queue: list[dict[str, Any]] = []
    while any(per_target.values()):
        for target in targets:
            if per_target[target]:
                item = per_target[target].pop(0)
                queue.append(
                    {
                        "queueIndex": len(queue),
                        "target": target,
                        "candidateKey": _candidate_key(item),
                        "type": item.get("type", ""),
                        "priority": item.get("priority", item.get("severity", "")),
                        "priorityScore": item.get("priorityScore", 0),
                        "value": item.get("value", item.get("url", "")),
                        "reason": item.get("reason", ""),
                        "evidenceIds": item.get("evidenceIds", []),
                    }
                )
    return queue


def _candidate_key(item: dict[str, Any]) -> str:
    stored = item.get("key") or item.get("candidateId") or item.get("observationId")
    if stored:
        return str(stored)
    return "|".join(str(item.get(field, "")) for field in ("type", "method", "url", "value", "parameter"))


def _paginate_context(
    context: dict[str, Any],
    size: int,
    *,
    part_cursor: int = 0,
    max_parts: int = 1,
) -> tuple[list[dict[str, Any]], int, int, int | None]:
    total = _context_record_count(context)
    part_count = max(1, (total + size - 1) // size)
    if part_cursor < 0 or part_cursor >= part_count:
        raise McpError(-32602, f"partCursor must be between 0 and {part_count - 1} for this scope group.")
    parts = []
    stop = min(part_count, part_cursor + max_parts)
    for part_index in range(part_cursor, stop):
        start, end = part_index * size, min(total, (part_index + 1) * size)
        part = deepcopy(context)
        position = [0]
        for layer in part.get("layers", []):
            _slice_sections(layer.get("sections", []), start, end, position)
            layer["evidence"] = []
            layer["gaps"] = []
            layer["recommendedNextSteps"] = []
            for target in layer.get("targets", []):
                _slice_sections(target.get("sections", []), start, end, position)
                target["observations"] = []
                target["candidates"] = []
                target["gaps"] = []
                target["recommendedNextSteps"] = []
        part["gaps"] = _slice_values(part.get("gaps", []), start, end, position)
        part["recommendedNextSteps"] = _slice_values(part.get("recommendedNextSteps", []), start, end, position)
        included = max(0, end - start)
        part.setdefault("summary", {})["batch"] = {
            "part": part_index + 1,
            "partCount": part_count,
            "recordBatchSize": size,
            "includedRecordCount": included,
            "totalRecordCount": total,
            "deferredRecordCount": max(0, total - end),
        }
        part.setdefault("gaps", []).append(
            f"This is report part {part_index + 1} of {part_count}; it contains {included} of {total} rendered records. Sibling parts preserve the remaining coverage."
        )
        parts.append(part)
    return parts, total, part_count, stop if stop < part_count else None


def _context_record_count(context: dict[str, Any]) -> int:
    count = 0
    for layer in context.get("layers", []):
        count += sum(_section_count(section) for section in layer.get("sections", []))
        for target in layer.get("targets", []):
            count += sum(_section_count(section) for section in target.get("sections", []))
    count += len(context.get("gaps", [])) if isinstance(context.get("gaps"), list) else 0
    count += len(context.get("recommendedNextSteps", [])) if isinstance(context.get("recommendedNextSteps"), list) else 0
    return count


def _section_count(section: Any) -> int:
    if not isinstance(section, dict):
        return 0
    if section.get("kind") == "tree":
        return _tree_count(section.get("tree", {}))
    if isinstance(section.get("rows"), list) and section["rows"]:
        return len(section["rows"])
    if isinstance(section.get("items"), list) and section["items"]:
        return len(section["items"])
    return 0


def _tree_count(tree: Any) -> int:
    if not isinstance(tree, dict):
        return 0
    count = sum(len(tree.get(key, [])) for key in ("endpoints", "requests") if isinstance(tree.get(key), list))
    count += sum(_tree_count(child) for child in tree.get("children", []) if isinstance(child, dict))
    if isinstance(tree.get("tree"), dict):
        count += _tree_count(tree["tree"])
    return count


def _slice_sections(sections: Any, start: int, end: int, position: list[int]) -> None:
    for section in sections if isinstance(sections, list) else []:
        if not isinstance(section, dict):
            continue
        count = _section_count(section)
        local_start = max(0, start - position[0])
        local_end = max(0, min(count, end - position[0]))
        if section.get("kind") == "tree":
            section["tree"] = _slice_tree(section.get("tree", {}), local_start, local_end)
        elif isinstance(section.get("rows"), list) and section["rows"]:
            section["rows"] = section["rows"][local_start:local_end]
            if section.get("kind") == "candidate_groups":
                metadata = section.get("metadata", {}) if isinstance(section.get("metadata"), dict) else {}
                group_by = str(metadata.get("groupBy") or _candidate_group_field(section))
                section["metadata"] = {
                    **metadata,
                    "groupBy": group_by,
                    "groups": layers._candidate_groups(section.get("headers", []), section["rows"], group_by),
                }
        elif isinstance(section.get("items"), list) and section["items"]:
            section["items"] = section["items"][local_start:local_end]
        position[0] += count


def _candidate_group_field(section: dict[str, Any]) -> str:
    headers = [str(item) for item in section.get("headers", [])]
    metadata = section.get("metadata", {}) if isinstance(section.get("metadata"), dict) else {}
    groups = metadata.get("groups", []) if isinstance(metadata.get("groups"), list) else []
    group_headers = [str(item) for item in groups[0].get("headers", [])] if groups and isinstance(groups[0], dict) else []
    return next((header for header in headers if header not in group_headers), headers[0] if headers else "Category")


def _slice_values(values: Any, start: int, end: int, position: list[int]) -> list[Any]:
    items = values if isinstance(values, list) else []
    local_start = max(0, start - position[0])
    local_end = max(0, min(len(items), end - position[0]))
    position[0] += len(items)
    return items[local_start:local_end]


def _slice_tree(tree: Any, start: int, end: int) -> dict[str, Any]:
    position = [0]

    def visit(node: Any) -> dict[str, Any]:
        if not isinstance(node, dict):
            return {}
        result = {key: deepcopy(value) for key, value in node.items() if key not in {"endpoints", "requests", "children", "tree", "endpointCount"}}
        for key in ("endpoints", "requests"):
            values = node.get(key, []) if isinstance(node.get(key), list) else []
            kept = []
            for value in values:
                if start <= position[0] < end:
                    kept.append(deepcopy(value))
                position[0] += 1
            if key in node:
                result[key] = kept
        children = [visit(child) for child in node.get("children", []) if isinstance(child, dict)]
        if "children" in node:
            result["children"] = [child for child in children if _tree_count(child) or child.get("children")]
        if isinstance(node.get("tree"), dict):
            result["tree"] = visit(node["tree"])
        result["endpointCount"] = _tree_count(result)
        return result

    return visit(tree)


def _render_index(manifest: dict[str, Any]) -> str:
    rows = []
    for group in manifest["groups"]:
        links = " ".join(
            f'<a href="{escape(group["groupId"] + "/" + Path(part["reportPath"]).name)}">Part {part["part"]}</a>' for part in group["parts"]
        )
        rows.append(
            f"<tr><td>{escape(group['name'])}</td><td>{group['targetCount']}</td><td>{group['totalRecordCount']}</td>"
            f"<td>{group.get('renderedPartCount', len(group['parts']))}/{group['partCount']}</td><td>{links}</td></tr>"
        )
    return """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Synapse audit report index</title><style>body{font:16px system-ui;margin:2rem;max-width:1100px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.6rem;text-align:left}a{margin-right:.7rem}</style></head><body>""" + (
        f"<h1>{escape(manifest['workspaceId'])} audit report run</h1><p>Run <code>{escape(manifest['runId'])}</code>. "
        f"Rendered {manifest['renderedGroupCount']} of {manifest['groupCount']} scope groups; {manifest['deferredGroupCount']} remain deferred.</p>"
        "<table><thead><tr><th>Scope group</th><th>Targets</th><th>Records</th><th>Parts</th><th>Reports</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>"
    )
