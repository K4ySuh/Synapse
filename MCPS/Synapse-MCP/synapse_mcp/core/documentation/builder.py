# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import scope, workspace
from ..errors import McpError
from .models import CoverageSummary, EvidencePackContext, FindingDraftContext, ReportContext
from .redaction import evidence_summary, policy_from_args, redact


SEVERITIES = ("critical", "high", "medium", "low", "info")
MODULE_OBSERVATION_PREFIXES = {
    "headers_cookies": ("missing_security_header", "weak_csp", "insecure_cookie_flag"),
    "csrf": ("csrf_", "csrf_candidate", "possible_csrf"),
    "cors": ("possible_cors_misconfiguration", "cors_"),
    "ssrf": ("ssrf_",),
    "lfi": ("lfi_", "file_handling_behavior_observed"),
    "ssti": ("ssti_", "possible_ssti"),
    "ssi": ("ssi_", "possible_ssi", "html_sink_observed"),
    "open_redirect": ("open_redirect_",),
    "command_injection": ("command_injection_", "possible_command_injection"),
    "graphql": ("graphql_",),
    "xxe": ("xxe_",),
    "insecure_deser": ("insecure_deser_", "possible_insecure_deserialization"),
    "tls_posture": ("tls_", "weak_tls", "certificate_"),
    "jwt": ("jwt_",),
    "xss": ("xss_",),
    "sqli": ("sqli_",),
    "access_control": ("access_control_", "possible_broken_access_control"),
    "js": ("js_",),
    "fingerprint": ("technology_component",),
    "perimeter": ("auth_boundary", "protected_resource", "api_surface", "non_web_service"),
    "nuclei": ("nuclei_",),
}
# Action types and adapters that send traffic / actively test the target. Used to
# avoid overstating active testing in coverage; anything without a positive active
# signal is treated as passive.
ACTIVE_ACTION_TYPES = {"active_scan", "active_validation", "replay", "exploit_validation", "http_request"}
ACTIVE_ADAPTERS = {"access_control", "active_probe", "ffuf", "nmap", "nuclei"}
KNOWN_PASSIVE_MODULES = set(MODULE_OBSERVATION_PREFIXES) - {"access_control", "perimeter", "fingerprint", "js", "nuclei"}


def build_report_context(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    workspace_meta = _workspace_meta(wid)
    target_filter = args.get("target", "")
    targets = _target_names(wid, target_filter)
    include_findings = bool(args.get("includeFindings", True))
    include_evidence = bool(args.get("includeEvidence", True))
    include_coverage = bool(args.get("includeCoverage", True))

    target_contexts = [_target_report_summary(wid, target, policy) for target in targets]
    findings = []
    evidence_items = []
    for target in targets:
        entities = workspace.load_reportable_target_entities(wid, target)
        if include_findings:
            findings.extend(_finding_items(wid, target, entities["findings"], policy))
        if include_evidence:
            evidence_items.extend(_target_evidence_items(wid, target, policy, include_raw=False))
    coverage = summarize_coverage({"workspaceId": wid, "target": target_filter, "redactionMode": policy.mode}) if include_coverage else {}
    context = ReportContext(
        workspace_id=wid,
        project={
            "name": workspace_meta.get("workspaceId", wid),
            "client": workspace_meta.get("organization", ""),
            "assessmentType": args.get("assessmentType", "Security Assessment"),
            "startDate": args.get("startDate", ""),
            "endDate": args.get("endDate", ""),
            "notes": workspace_meta.get("notes", ""),
        },
        scope={
            "targets": targets,
            "excluded": args.get("excluded", []),
            "notes": _scope_notes(),
        },
        executive_summary=_executive_summary(findings),
        coverage=coverage.get("coverage", coverage),
        targets=target_contexts,
        findings=findings,
        evidence=evidence_items,
        appendices=[],
        redaction=policy,
    )
    return {"contextType": "report", "report": context.as_dict()}


def build_finding_context(args: dict[str, Any]) -> dict[str, Any]:
    return {"contextType": "finding", "findingContext": _finding_context(args).as_dict()}


def build_finding_draft(args: dict[str, Any]) -> dict[str, Any]:
    context = _finding_context(args)
    finding = context.finding
    draft = {
        "title": finding.get("title", "Untitled finding"),
        "severity": finding.get("severity", "info"),
        "confidence": finding.get("confidence", "low"),
        "affectedAssets": finding.get("affectedAssets", [context.target]),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", ""),
        "evidence": context.evidence,
        "reproductionSteps": finding.get("reproductionSteps", []),
        "remediation": finding.get("remediation", ""),
        "limitations": context.limitations,
        "operatorReview": {
            "status": finding.get("status", ""),
            "operatorReviewed": finding.get("operatorReviewed", False),
        },
    }
    return {"contextType": "finding_draft", "draft": draft}


def build_evidence_pack(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    policy = policy_from_args(args)
    finding = None
    evidence_ids: list[str] = []
    if args.get("findingId"):
        finding = _find_finding(wid, target, args["findingId"])
        evidence_ids = [str(item) for item in finding.get("evidenceIds", []) if str(item).strip()]
    evidence_items = _target_evidence_items(
        wid,
        target,
        policy,
        include_raw=policy.include_raw_http,
        evidence_ids=evidence_ids or None,
    )
    actions = workspace._load_target_entities(wid, target)["actions"]
    context = EvidencePackContext(
        workspace_id=wid,
        target=target,
        finding=redact(finding, policy) if finding else None,
        evidence=evidence_items,
        actions=redact(actions, policy),
        scope_status=workspace.scope_status_for_target(target),
        policy=policy,
    )
    return {"contextType": "evidence_pack", "evidencePack": context.as_dict()}


def summarize_coverage(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    target_filter = args.get("target", "")
    targets = _target_names(wid, target_filter)
    # Prefer the workspace-local scope (which active adapters honor) so coverage
    # matches execution policy; fall back to the global scope when it is unset.
    ws_scope = workspace.workspace_scope(wid)
    effective_scope = ws_scope if any(ws_scope.get(name) for name in ("hosts", "patterns", "cidrs")) else scope.load_scope()
    targets_in_scope = sorted({workspace.normalize_target(item) for item in effective_scope.get("hosts", []) if workspace.normalize_target(item)})
    findings_by_severity = {severity: 0 for severity in SEVERITIES}
    targets_with_traffic: set[str] = set()
    targets_scanned: set[str] = set()
    adapters_used: set[str] = set()
    active_modules: set[str] = set()
    passive_modules: set[str] = set()
    actions_performed: list[dict[str, Any]] = []
    follow_up: list[str] = []
    untested: list[str] = []

    for target in targets:
        entities = workspace.load_reportable_target_entities(wid, target)
        target_passive_modules: set[str] = set()
        if entities["endpoints"] or entities["parameters"]:
            targets_with_traffic.add(target)
        for finding in entities["findings"]:
            severity = str(finding.get("severity", "info")).lower()
            findings_by_severity[severity if severity in findings_by_severity else "info"] += 1
            if finding.get("status") == "candidate" or finding.get("operatorReviewed") is False:
                follow_up.append(f"Review candidate finding {finding.get('title', finding.get('id', 'untitled'))} on {target}.")
        for action in entities["actions"]:
            tool = _action_tool(action)
            active = is_active_action(action)
            if tool:
                adapters_used.add(tool.split(".", 1)[0])
                if active:
                    active_modules.add(tool.split(".", 1)[0])
            if active:
                targets_scanned.add(target)
            actions_performed.append(
                {
                    "target": target,
                    "tool": tool or action.get("type", "action"),
                    "createdAt": action.get("createdAt", ""),
                    "approvalId": _approval_value(action, "approvalId"),
                    "riskTier": _approval_value(action, "riskTier"),
                }
            )
        for observation in entities["observations"]:
            observation_type = str(observation.get("type", ""))
            module = _module_for_observation(observation_type)
            if module:
                passive_modules.add(module)
                target_passive_modules.add(module)
            if observation_type == "test_candidate":
                # A consolidated surface candidate credits passive coverage for every
                # vuln class it is a candidate for.
                for vuln_class in observation.get("candidateFor", []):
                    module_name = str(vuln_class)
                    if module_name:
                        passive_modules.add(module_name)
                        target_passive_modules.add(module_name)
            if observation_type.endswith("_candidate"):
                follow_up.append(f"Review {observation_type} on {target}: {observation.get('value', '')}.")
        if not entities["endpoints"]:
            untested.append(f"No endpoints or imported traffic are recorded for {target}.")
        if not any(is_active_action(item) for item in entities["actions"]):
            untested.append(f"No active tool actions are recorded for {target}.")
        if any(str(item.get("type", "")).startswith("access_control_") for item in entities["observations"]) and not any(
            _action_tool(item) == "access_control.execute_matrix_test" for item in entities["actions"]
        ):
            untested.append(f"No approved access-control replay is recorded for {target}.")
        if entities["endpoints"] or entities["parameters"]:
            for module in sorted(KNOWN_PASSIVE_MODULES):
                if module not in target_passive_modules and not _target_has_module_action(entities, module):
                    untested.append(f"No {_module_display_name(module)} passive candidate analysis is recorded for {target}.")

    coverage = CoverageSummary(
        workspace_id=wid,
        targets_in_scope=targets_in_scope,
        targets_with_workspace_state=targets,
        targets_with_traffic=sorted(targets_with_traffic),
        targets_scanned=sorted(targets_scanned),
        adapters_used=sorted(adapters_used | passive_modules),
        passive_only_modules=sorted(passive_modules - active_modules),
        active_modules=sorted(active_modules),
        actions_performed=actions_performed,
        findings_by_severity=findings_by_severity,
        untested_areas=sorted(set(untested)),
        actions_requiring_follow_up=sorted(set(follow_up))[:50],
    )
    return {"contextType": "coverage", "coverage": coverage.as_dict()}


def _finding_context(args: dict[str, Any]) -> FindingDraftContext:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    policy = policy_from_args(args)
    finding = _find_finding(wid, target, args["findingId"])
    evidence_items = []
    if bool(args.get("includeEvidence", True)):
        evidence_items = _target_evidence_items(
            wid,
            target,
            policy,
            include_raw=policy.include_raw_http,
            evidence_ids=[str(item) for item in finding.get("evidenceIds", [])],
        )
    limitations = []
    if finding.get("missingEvidenceIds"):
        limitations.append(f"Missing linked evidence ids: {', '.join(str(item) for item in finding['missingEvidenceIds'])}.")
    if finding.get("operatorReviewed") is False:
        limitations.append("Finding has not been operator-reviewed.")
    return FindingDraftContext(
        workspace_id=wid,
        target=target,
        finding=redact(finding, policy),
        evidence=evidence_items,
        limitations=limitations,
        redaction=policy,
    )


def _workspace_meta(workspace_id: str) -> dict[str, Any]:
    path = workspace.workspace_path(workspace_id) / "workspace.json"
    meta = workspace._read_json(path, {})
    if not meta:
        raise McpError(-32602, f"Workspace not found: {workspace_id}")
    return meta


def _target_names(workspace_id: str, target: str = "") -> list[str]:
    _workspace_meta(workspace_id)
    if target:
        return [workspace.normalize_target(target)]
    root = workspace.workspace_path(workspace_id) / "targets"
    targets = []
    for target_dir in sorted(root.glob("*")) if root.exists() else []:
        meta = workspace._read_json(target_dir / "target.json", {})
        if meta.get("target"):
            targets.append(str(meta["target"]))
    return targets


def _target_report_summary(workspace_id: str, target: str, policy: Any) -> dict[str, Any]:
    entities = workspace.load_reportable_target_entities(workspace_id, target)
    pending_observations = [
        item
        for item in entities["observations"]
        if isinstance(item, dict)
        and (
            str(item.get("type", "")).endswith("_candidate")
            or "candidate" in str(item.get("type", ""))
            or item.get("operatorReviewed") is False
        )
    ]
    return {
        "target": target,
        "scopeStatus": workspace.scope_status_for_target(target),
        "serviceCount": len(entities["services"]),
        "endpointCount": len(entities["endpoints"]),
        "parameterCount": len(entities["parameters"]),
        "findingCount": len(entities["findings"]),
        "observationCount": len(entities["observations"]),
        "services": redact(entities["services"], policy),
        "technologies": _technology_items(entities["services"], entities["observations"]),
        "pendingObservations": redact(pending_observations[:20], policy),
        "recentActions": redact(entities["actions"][-10:], policy),
    }


def _finding_items(workspace_id: str, target: str, findings: list[dict[str, Any]], policy: Any) -> list[dict[str, Any]]:
    return [redact({**item, "target": target, "workspaceId": workspace_id}, policy) for item in findings if isinstance(item, dict)]


def _find_finding(workspace_id: str, target: str, finding_id: str) -> dict[str, Any]:
    findings = workspace._load_target_entities(workspace_id, target)["findings"]
    for finding in findings:
        if isinstance(finding, dict) and finding_id in {finding.get("id"), finding.get("key")}:
            return finding
    raise McpError(-32602, f"Finding not found: {finding_id}")


def _target_evidence_items(
    workspace_id: str,
    target: str,
    policy: Any,
    *,
    include_raw: bool = False,
    evidence_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    evidence_dir = workspace.target_path(workspace_id, target) / "evidence"
    if not evidence_dir.exists():
        return []
    wanted = set(evidence_ids or [])
    items = []
    for meta_path in sorted(evidence_dir.glob("ev_*.json")):
        record = workspace._read_json(meta_path, {})
        if not isinstance(record, dict):
            continue
        if wanted and record.get("evidenceId") not in wanted:
            continue
        raw_content = None
        if include_raw or policy.include_hashes:
            raw_path = _safe_raw_evidence_path(record, evidence_dir)
            if raw_path is not None:
                raw_content = raw_path.read_text(encoding="utf-8", errors="replace")
        items.append(evidence_summary(record, policy, raw_content if include_raw or policy.include_hashes else None))
    return items


def _safe_raw_evidence_path(record: dict[str, Any], evidence_dir: Path) -> Path | None:
    raw_value = str(record.get("rawPath", "")).strip()
    if not raw_value:
        return None
    raw_path = Path(raw_value).expanduser()
    if not raw_path.is_absolute():
        raw_path = evidence_dir / raw_path
    evidence_root = evidence_dir.resolve()
    resolved = raw_path.resolve()
    try:
        resolved.relative_to(evidence_root)
    except ValueError:
        return None
    if not resolved.is_file():
        return None
    return resolved


def _executive_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        counts[severity if severity in counts else "info"] += 1
    key_findings = [
        {"title": item.get("title", "Untitled finding"), "severity": item.get("severity", "info"), "target": item.get("target", "")}
        for item in findings
        if str(item.get("severity", "")).lower() in {"critical", "high"}
    ][:10]
    return {
        "riskOverview": "Draft summary generated from operator-reviewed and candidate findings.",
        "findingsBySeverity": counts,
        "keyFindings": key_findings,
        "positiveSecurityNotes": [],
    }


def _technology_items(services: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for service in services:
        if not isinstance(service, dict):
            continue
        # A service with no detected product is a bare nmap port-table guess (e.g. "ppp" on
        # port 3000), not a technology. The open port is still reflected in the scope overview.
        if not str(service.get("product", "")).strip():
            continue
        name = " ".join(
            str(service.get(key, "")).strip()
            for key in ("product", "version", "name")
            if str(service.get(key, "")).strip()
        ).strip()
        if not name:
            continue
        location = ":".join(str(service.get(key, "")).strip() for key in ("host", "port") if str(service.get(key, "")).strip())
        key = name
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "name": name,
                "source": "service",
                "location": location,
                "evidenceIds": service.get("evidenceIds", []),
            }
        )
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        observation_type = str(observation.get("type", ""))
        if "technology" not in observation_type and observation_type not in {"nuclei_result", "fingerprint"}:
            continue
        name = str(observation.get("name") or observation.get("value") or observation.get("templateId") or "").strip()
        if not name:
            continue
        # Drop bare service-name guesses (e.g. a stale "ppp" technology_component) that have no
        # version and only low confidence — the same nmap port-table noise filtered elsewhere.
        if (
            observation_type == "technology_component"
            and str(observation.get("source") or "") == "service"
            and not str(observation.get("version") or "").strip()
            and str(observation.get("confidence") or "").lower() in {"low", ""}
        ):
            continue
        key = f"{name}|{observation_type}"
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "name": name,
                "source": observation_type or "observation",
                "location": str(observation.get("url") or observation.get("matchedAt") or observation.get("value") or ""),
                "evidenceIds": observation.get("evidenceIds", []),
            }
        )
    return items[:20]


def _scope_notes() -> list[str]:
    current_scope = scope.load_scope()
    notes = current_scope.get("notes", "")
    if isinstance(notes, str) and notes.strip():
        return [notes.strip()]
    return []


def is_active_action(action: dict[str, Any]) -> bool:
    """Conservatively decide whether a recorded action actively tested the target.

    Passive work (documentation/report generation, workspace import, passive
    normalization, operator notes, static analysis without traffic) has no active
    signal and is treated as passive. When metadata is imperfect, err toward
    passive so coverage never overstates active testing.
    """
    if not isinstance(action, dict):
        return False
    approval = action.get("approval")
    if isinstance(approval, dict) and (approval.get("approvalId") or approval.get("riskTier")):
        return True
    if action.get("approvalId") or action.get("riskTier"):
        return True
    if action.get("sendsTraffic") is True:
        return True
    metadata = action.get("metadata")
    if isinstance(metadata, dict) and metadata.get("sendsTraffic") is True:
        return True
    if str(action.get("type", "")).strip().lower() in ACTIVE_ACTION_TYPES:
        return True
    tool = _action_tool(action)
    adapter = tool.split(".", 1)[0].lower() if tool else ""
    return adapter in ACTIVE_ADAPTERS


def _action_tool(action: dict[str, Any]) -> str:
    for key in ("tool", "adapter", "profile", "type"):
        value = action.get(key)
        if isinstance(value, str) and value.strip() and value != "action":
            return value.strip()
    return ""


def _approval_value(action: dict[str, Any], key: str) -> str:
    approval = action.get("approval")
    if isinstance(approval, dict) and approval.get(key):
        return str(approval[key])
    if action.get(key):
        return str(action[key])
    return ""


def _module_for_observation(observation_type: str) -> str:
    for module, prefixes in MODULE_OBSERVATION_PREFIXES.items():
        if any(observation_type.startswith(prefix) or observation_type == prefix for prefix in prefixes):
            return module
    return ""


def _module_display_name(module: str) -> str:
    return {"sqli": "SQL injection", "xss": "XSS"}.get(module, module)


def _target_has_module_action(entities: dict[str, list[dict[str, Any]]], module: str) -> bool:
    for action in entities["actions"]:
        if not isinstance(action, dict):
            continue
        tool = _action_tool(action).lower()
        if tool == module or tool.startswith(f"{module}."):
            return True
    return False
