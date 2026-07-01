# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from ..errors import McpError
from .models import RenderResult
from .templates import template_for


def render(template_id: str, context: dict[str, Any]) -> RenderResult:
    template = template_for(template_id)
    if template.context_type == "report":
        report = _context_payload(context, "report")
        content = _render_assessment_summary_report(report) if template_id == "assessment_summary_report" else _render_report(report)
    elif template.context_type == "finding":
        content = _render_finding(_context_payload(context, "findingContext", "draft"))
    elif template.context_type == "evidence_pack":
        content = _render_evidence_pack(_context_payload(context, "evidencePack"))
    elif template.context_type == "coverage":
        content = _render_coverage(_context_payload(context, "coverage"))
    else:
        raise McpError(-32602, f"Unsupported template context type: {template.context_type}")
    return RenderResult(
        template_id=template.template_id,
        context_type=template.context_type,
        format="markdown",
        content=content,
        bytes=len(content.encode("utf-8")),
    )


def _context_payload(context: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = context.get(key)
        if isinstance(value, dict):
            return value
    if all(key in context for key in ("workspaceId",)):
        return context
    raise McpError(-32602, f"Context does not match expected keys: {', '.join(keys)}")


def _render_report(report: dict[str, Any]) -> str:
    project = report.get("project", {})
    coverage = report.get("coverage", {})
    executive = report.get("executiveSummary", {})
    lines = [
        f"# {project.get('name') or report.get('workspaceId', 'Security Assessment')} Report",
        "",
        f"- Client: {_text(project.get('client'))}",
        f"- Assessment type: {_text(project.get('assessmentType'))}",
        f"- Dates: {_date_range(project.get('startDate'), project.get('endDate'))}",
        f"- Presentation mode: `{report.get('redaction', {}).get('mode', 'high_level')}`",
        "",
        "## Executive Summary",
        "",
        _text(executive.get("riskOverview")) or "Draft summary pending operator review.",
        "",
        "### Findings By Severity",
        "",
        _severity_table(executive.get("findingsBySeverity", {})),
        "",
        "## Scope",
        "",
        _bullet_list(report.get("scope", {}).get("targets", []), empty="No targets recorded."),
        "",
        "## Coverage",
        "",
        _render_coverage_body(coverage),
        "",
        "## Findings",
        "",
    ]
    findings = report.get("findings", [])
    if findings:
        for finding in findings:
            lines.extend(_finding_section(finding, heading_level=3))
    else:
        lines.append("No findings are recorded in this report context.")
    evidence_items = report.get("evidence", [])
    lines.extend(["", "## Evidence Index", ""])
    if evidence_items:
        lines.extend(_evidence_table(evidence_items))
    else:
        lines.append("No evidence metadata is included.")
    return "\n".join(lines).rstrip() + "\n"


def _render_assessment_summary_report(report: dict[str, Any]) -> str:
    project = report.get("project", {})
    coverage = report.get("coverage", {})
    scope = report.get("scope", {})
    targets = [item for item in report.get("targets", []) if isinstance(item, dict)]
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    confirmed_findings = [item for item in findings if item.get("operatorReviewed") is not False and str(item.get("status", "")).lower() != "candidate"]
    pending_items = _pending_items(report)
    lines = [
        "# Assessment Summary Report",
        "",
        f"- Workspace: `{report.get('workspaceId', '')}`",
        f"- Client / Organization: {_text(project.get('client')) or 'not specified'}",
        f"- Assessment type: {_text(project.get('assessmentType')) or 'Security Assessment'}",
        f"- Dates: {_date_range(project.get('startDate'), project.get('endDate'))}",
        f"- Scope: `{len(scope.get('targets', []))}` target(s)",
        f"- Presentation mode: `{report.get('redaction', {}).get('mode', 'high_level')}`",
        "",
        "## 1. General Summary",
        "",
        _assessment_summary_text(report, confirmed_findings, pending_items),
        "",
        "### Scope Overview",
        "",
        *_scope_overview_table(targets, coverage),
        "",
        "### Findings Summary",
        "",
        _severity_table(coverage.get("findingsBySeverity", report.get("executiveSummary", {}).get("findingsBySeverity", {}))),
        "",
        "## 2. Technologies Detected",
        "",
        *_technologies_table(targets),
        "",
        "## 3. Actions Performed",
        "",
        *_assessment_actions_table(targets, coverage),
        "",
        "## 4. Findings",
        "",
    ]
    if confirmed_findings:
        for finding in confirmed_findings:
            lines.extend(_finding_section(finding, heading_level=3))
            lines.append("")
    else:
        lines.append("No confirmed operator-reviewed findings are recorded in this report context.")
    lines.extend(["", "## 5. Pending Observations And Suggested Next Steps", ""])
    lines.extend(_pending_observations_table(pending_items))
    lines.extend(["", "## 6. Assessment Limitations", ""])
    lines.append(_bullet_list(coverage.get("untestedAreas", []), empty="No assessment limitations are recorded in this report context."))
    lines.extend(["", "## Appendix: Evidence Index", ""])
    evidence_items = report.get("evidence", [])
    lines.extend(_assessment_evidence_table(evidence_items) if evidence_items else ["No evidence metadata is included."])
    return "\n".join(lines).rstrip() + "\n"


def _render_finding(context: dict[str, Any]) -> str:
    finding = context.get("finding", context)
    if "title" in context and "finding" not in context:
        finding = context
    lines = _finding_section(finding, heading_level=1)
    evidence = context.get("evidence", [])
    if evidence:
        lines.extend(["", "## Evidence", ""])
        lines.extend(_evidence_table(evidence))
    limitations = context.get("limitations", [])
    if limitations:
        lines.extend(["", "## Limitations", "", _bullet_list(limitations)])
    return "\n".join(lines).rstrip() + "\n"


def _render_evidence_pack(pack: dict[str, Any]) -> str:
    lines = [
        f"# Evidence Pack: {pack.get('target', 'target')}",
        "",
        f"- Workspace: `{pack.get('workspaceId', '')}`",
        f"- Presentation mode: `{pack.get('policy', {}).get('mode', 'high_level')}`",
        "",
    ]
    finding = pack.get("finding")
    if isinstance(finding, dict):
        lines.extend(["## Finding", ""])
        lines.extend(_finding_section(finding, heading_level=3))
        lines.append("")
    lines.extend(["## Evidence", ""])
    evidence_items = pack.get("evidence", [])
    lines.extend(_evidence_table(evidence_items) if evidence_items else ["No evidence metadata is included."])
    actions = pack.get("actions", [])
    lines.extend(["", "## Actions", ""])
    if actions:
        lines.extend(_actions_table(actions))
    else:
        lines.append("No actions are included.")
    return "\n".join(lines).rstrip() + "\n"


def _render_coverage(coverage: dict[str, Any]) -> str:
    return "# Coverage Summary\n\n" + _render_coverage_body(coverage).rstrip() + "\n"


def _render_coverage_body(coverage: dict[str, Any]) -> str:
    lines = [
        "### Targets With Workspace State",
        "",
        _bullet_list(coverage.get("targetsWithWorkspaceState", []), empty="No workspace targets recorded."),
        "",
        "### Adapter Usage",
        "",
        f"- Active modules: {_inline_list(coverage.get('activeModules', []))}",
        f"- Passive-only modules: {_inline_list(coverage.get('passiveOnlyModules', []))}",
        f"- All adapters observed: {_inline_list(coverage.get('adaptersUsed', []))}",
        "",
        "### Findings By Severity",
        "",
        _severity_table(coverage.get("findingsBySeverity", {})),
        "",
        "### Untested Areas",
        "",
        _bullet_list(coverage.get("untestedAreas", []), empty="No untested areas inferred."),
        "",
        "### Follow-Up",
        "",
        _bullet_list(coverage.get("actionsRequiringFollowUp", []), empty="No follow-up actions inferred."),
    ]
    return "\n".join(lines)


def _finding_section(finding: dict[str, Any], heading_level: int = 2) -> list[str]:
    heading = "#" * heading_level
    lines = [
        f"{heading} {_text(finding.get('title')) or 'Untitled Finding'}",
        "",
        f"- Severity: `{_text(finding.get('severity', 'info'))}`",
        f"- Confidence: `{_text(finding.get('confidence', 'low'))}`",
        f"- Status: `{_text(finding.get('status', 'candidate'))}`",
        f"- Affected assets: {_inline_list(finding.get('affectedAssets', []))}",
        "",
        "### Description",
        "",
        _text(finding.get("description")) or "Description pending operator review.",
        "",
        "### Impact",
        "",
        _text(finding.get("impact")) or "Impact pending operator review.",
        "",
        "### Reproduction Steps",
        "",
        _numbered_list(finding.get("reproductionSteps", []), empty="Reproduction steps pending operator review."),
        "",
        "### Remediation",
        "",
        _text(finding.get("remediation")) or "Remediation guidance pending operator review.",
    ]
    return lines


def _evidence_table(items: list[dict[str, Any]]) -> list[str]:
    lines = ["| Evidence ID | Source | Type | Created | SHA-256 |", "| --- | --- | --- | --- | --- |"]
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("evidenceId")),
                    _cell(item.get("source")),
                    _cell(item.get("dataType")),
                    _cell(item.get("createdAt")),
                    _cell(item.get("sha256", "")),
                ]
            )
            + " |"
        )
    return lines


def _actions_table(items: list[dict[str, Any]]) -> list[str]:
    lines = ["| Tool | Created | Approval | Risk |", "| --- | --- | --- | --- |"]
    for item in items:
        approval = item.get("approval") if isinstance(item.get("approval"), dict) else {}
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("tool") or item.get("type")),
                    _cell(item.get("createdAt")),
                    _cell(approval.get("approvalId") or item.get("approvalId")),
                    _cell(approval.get("riskTier") or item.get("riskTier")),
                ]
            )
            + " |"
        )
    return lines


def _scope_overview_table(targets: list[dict[str, Any]], coverage: dict[str, Any]) -> list[str]:
    targets_with_traffic = set(coverage.get("targetsWithTraffic", []))
    targets_scanned = set(coverage.get("targetsScanned", []))
    lines = ["| Host | Workspace State | Traffic Observed | Active Actions | Findings |", "| --- | --- | --- | ---: | ---: |"]
    for target in targets:
        host = _text(target.get("target"))
        actions = target.get("recentActions", [])
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(host),
                    "yes",
                    "yes" if host in targets_with_traffic else "no",
                    str(len(actions) if isinstance(actions, list) else (1 if host in targets_scanned else 0)),
                    str(int(target.get("findingCount", 0) or 0)),
                ]
            )
            + " |"
        )
    return lines if targets else ["No targets recorded."]


def _technologies_table(targets: list[dict[str, Any]]) -> list[str]:
    lines = ["| Host | Technologies / Services | Source |", "| --- | --- | --- |"]
    for target in targets:
        technologies = [item for item in target.get("technologies", []) if isinstance(item, dict)]
        if technologies:
            for item in technologies:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _cell(target.get("target")),
                            _cell(item.get("name")),
                            _cell(item.get("source")),
                        ]
                    )
                    + " |"
                )
        elif int(target.get("serviceCount", 0) or 0) > 0:
            lines.append(f"| {_cell(target.get('target'))} | {int(target.get('serviceCount', 0) or 0)} service record(s) | workspace services |")
    return lines if len(lines) > 2 else ["No technology or service records are included in this report context."]


def _assessment_actions_table(targets: list[dict[str, Any]], coverage: dict[str, Any]) -> list[str]:
    rows: list[dict[str, Any]] = []
    for target in targets:
        host = _text(target.get("target"))
        for action in target.get("recentActions", []):
            if isinstance(action, dict):
                rows.append({**action, "target": host})
    if not rows:
        rows = [item for item in coverage.get("actionsPerformed", []) if isinstance(item, dict)]
    lines = ["| Time | Host | Action / Tool | Profile | Result | Approval / Risk |", "| --- | --- | --- | --- | --- | --- |"]
    for item in rows:
        approval = item.get("approval") if isinstance(item.get("approval"), dict) else {}
        risk = approval.get("riskTier") or item.get("riskTier") or ""
        result = _action_result(item)
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("createdAt")),
                    _cell(item.get("target")),
                    _cell(item.get("tool") or item.get("type")),
                    _cell(item.get("profile")),
                    _cell(result),
                    _cell(risk),
                ]
            )
            + " |"
        )
    return lines if rows else ["No active actions are recorded in this report context."]


def _pending_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        host = _text(target.get("target"))
        for observation in target.get("pendingObservations", []):
            if isinstance(observation, dict):
                items.append(
                    {
                        "host": host,
                        "type": observation.get("type", "observation"),
                        "summary": observation.get("value") or observation.get("reason") or observation.get("title") or observation.get("candidateId", ""),
                        "nextStep": observation.get("testPlanSummary") or observation.get("reason") or "Review and confirm or discard this observation.",
                        "status": "needs-review",
                    }
                )
    for finding in report.get("findings", []):
        if isinstance(finding, dict) and (finding.get("operatorReviewed") is False or str(finding.get("status", "")).lower() == "candidate"):
            items.append(
                {
                    "host": finding.get("target", ""),
                    "type": "candidate_finding",
                    "summary": finding.get("title", "Untitled candidate finding"),
                    "nextStep": "Operator review is required before reporting as confirmed.",
                    "status": "pending",
                }
            )
    return items[:80]


def _pending_observations_table(items: list[dict[str, Any]]) -> list[str]:
    lines = ["| Host | Type | Observation / Candidate | Suggested Next Step | Status |", "| --- | --- | --- | --- | --- |"]
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("host")),
                    _cell(item.get("type")),
                    _cell(item.get("summary")),
                    _cell(item.get("nextStep")),
                    _cell(item.get("status")),
                ]
            )
            + " |"
        )
    return lines if items else ["No pending observations or suggested next steps are recorded in this report context."]


def _assessment_evidence_table(items: list[dict[str, Any]]) -> list[str]:
    lines = ["| Evidence ID | Host | Source | Type | Created |", "| --- | --- | --- | --- | --- |"]
    for item in items:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("evidenceId")),
                    _cell(metadata.get("host") or metadata.get("target") or item.get("target")),
                    _cell(item.get("source")),
                    _cell(item.get("dataType")),
                    _cell(item.get("createdAt")),
                ]
            )
            + " |"
        )
    return lines


def _assessment_summary_text(report: dict[str, Any], confirmed_findings: list[dict[str, Any]], pending_items: list[dict[str, Any]]) -> str:
    target_count = len(report.get("scope", {}).get("targets", []))
    finding_count = len(confirmed_findings)
    pending_count = len(pending_items)
    return (
        f"This report summarizes stored Synapse workspace context for {target_count} target(s). "
        f"It includes {finding_count} confirmed finding(s) and {pending_count} pending observation(s) or candidate item(s) that require review."
    )


def _action_result(item: dict[str, Any]) -> str:
    if item.get("timedOut") is True:
        return f"timed out after {item.get('timeoutSeconds', '')}s".strip()
    if "returnCode" in item:
        return f"return code {item.get('returnCode')}"
    if item.get("evidenceId"):
        return "evidence recorded"
    return _text(item.get("status")) or "recorded"


def _severity_table(counts: dict[str, Any]) -> str:
    severities = ("critical", "high", "medium", "low", "info")
    lines = ["| Severity | Count |", "| --- | --- |"]
    for severity in severities:
        lines.append(f"| {severity.title()} | {int(counts.get(severity, 0) or 0)} |")
    return "\n".join(lines)


def _bullet_list(items: list[Any], empty: str = "None.") -> str:
    values = [str(item) for item in items if str(item).strip()]
    if not values:
        return empty
    return "\n".join(f"- {item}" for item in values)


def _numbered_list(items: list[Any], empty: str = "None.") -> str:
    values = [str(item) for item in items if str(item).strip()]
    if not values:
        return empty
    return "\n".join(f"{index}. {item}" for index, item in enumerate(values, start=1))


def _inline_list(items: list[Any]) -> str:
    values = [_text(item) for item in items if _text(item)]
    return ", ".join(values) if values else "none"


def _date_range(start: Any, end: Any) -> str:
    if start and end:
        return f"{start} to {end}"
    return str(start or end or "not specified")


def _cell(value: Any) -> str:
    return _text(value).replace("|", "\\|")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        if not value:
            return ""
        dict_items = [item for item in value if isinstance(item, dict)]
        if len(dict_items) == len(value):
            for key in ("name", "target", "title", "id"):
                labels = [_text(item.get(key)) for item in dict_items]
                if all(labels):
                    return _join_limited(labels)
            return f"{len(value)} records"
        if all(_is_scalar(item) for item in value):
            return _join_limited([_text(item) for item in value if _text(item)])
        return f"{len(value)} records"
    if isinstance(value, dict):
        if not value:
            return ""
        if all(_is_scalar(item) for item in value.values()):
            return _join_limited([f"{_label(key)}: {_text(item)}" for key, item in value.items() if _text(item)])
        return f"{len(value)} fields"
    return str(value).strip()


def _join_limited(values: list[str], limit: int = 8) -> str:
    clipped = values[:limit]
    suffix = f", +{len(values) - limit} more" if len(values) > limit else ""
    return ", ".join(clipped) + suffix


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _label(value: Any) -> str:
    text = str(value or "")
    result = []
    for char in text:
        if char.isupper() and result:
            result.append(" ")
        result.append(char)
    return "".join(result).replace("_", " ").strip().title()
