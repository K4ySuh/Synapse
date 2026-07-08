# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import urlsplit

from .assets import banner_html, html_shell


TREE_SCRIPT = (
    "function synapseToggleTree(id,open){document.querySelectorAll('#'+id+' details').forEach(function(item){item.open=open;});}"
    "function synapseFilterTree(id,value){var q=(value||'').toLowerCase();document.querySelectorAll('#'+id+' .record').forEach(function(item){var m=!q||item.textContent.toLowerCase().indexOf(q)>-1;item.style.display=m?'':'none';if(m&&q){var p=item.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}}});}"
    "function synapseSetActiveToc(){var h=location.hash.slice(1);document.querySelectorAll('.report-toc a').forEach(function(a){a.classList.toggle('active',h&&a.getAttribute('href')==='#'+h);});}"
    "addEventListener('hashchange',synapseSetActiveToc);addEventListener('DOMContentLoaded',synapseSetActiveToc);"
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(value: Any) -> int:
    return _SEVERITY_RANK.get(str(value or "").strip().lower(), 5)


def _workspace_layer_sections(layer: dict[str, Any]) -> list[dict[str, Any]]:
    """All layer-level sections for a layer, in their canonical emission order.

    Consolidated workspace reports never truncate or skip sections: every section
    the layer produces is rendered, and empty sections become an explicit
    empty-state line instead of being dropped.
    """
    sections = layer.get("sections", [])
    return [section for section in sections if isinstance(section, dict)] if isinstance(sections, list) else []


def render_layer_report(context: dict[str, Any], format_name: str = "html") -> str:
    if format_name == "markdown":
        return _render_layer_markdown(context)
    return _render_layer_html(context)


def render_workspace_report(context: dict[str, Any], format_name: str = "html") -> str:
    if format_name == "markdown":
        return _render_workspace_markdown(context)
    return _render_workspace_html(context)


def _render_layer_html(context: dict[str, Any]) -> str:
    sections = [_render_section_html(section) for section in context.get("sections", []) if isinstance(section, dict) and _section_has_content(section)]
    toc_items = [("summary", "Summary")]
    toc_items.extend((_section_anchor(section), str(section.get("title", "Section"))) for section in context.get("sections", []) if isinstance(section, dict) and _section_has_content(section))
    target_sections = []
    rendered_gaps: set[str] = set()
    rendered_summary_lines: set[tuple[str, str]] = set()
    summary_html = _summary_list(
        {
            **(context.get("summary", {}) if isinstance(context.get("summary"), dict) else {}),
        },
        seen=rendered_summary_lines,
    )
    for target in context.get("targets", []) if isinstance(context.get("targets"), list) else []:
        if not isinstance(target, dict):
            continue
        target_id = _slug("target", target.get("target", "target"))
        toc_items.append((target_id, str(target.get("target", "Target"))))
        rendered_sections = "".join(_render_section_html(section, heading_level=3) for section in target.get("sections", []) if isinstance(section, dict) and _section_has_content(section))
        target_sections.append(
            f"<section class=\"layer\" id=\"{_html(target_id)}\">"
            f"{_layer_head(target.get('target', 'Target'), 'target')}"
            f"{_summary_list(target.get('summary', {}), seen=rendered_summary_lines)}"
            f"{_render_unique_string_list('Coverage Gaps', target.get('gaps', []), rendered_gaps)}"
            + rendered_sections
            + "</section>"
        )
    body = "\n".join(
        [
            banner_html(
                context.get("title") or "Layer Report",
                "Normalized passive workspace report generated from Synapse state.",
                {
                    "report": '<span id="reportName">Operator Report</span>',
                    "workspace": context.get("workspaceId", ""),
                    "layer": context.get("layer", ""),
                    "generated": context.get("generatedAt", ""),
                },
            ),
            '<div class="wrap"><div class="layout">',
            _render_toc(toc_items),
            '<main class="synapse-report-main">',
            '<section class="layer" id="summary">',
            _layer_head("Summary", "00", "Internal Summary"),
            summary_html,
            "</section>",
            *sections,
            *target_sections,
            _render_unique_string_list("Coverage Gaps", context.get("gaps", []), rendered_gaps, section=True),
            _render_string_list("Recommended Next Steps", context.get("recommendedNextSteps", []), section=True),
            "</main></div></div>",
        ]
    )
    return html_shell(
        str(context.get("title") or "Layer Report"),
        body,
        TREE_SCRIPT,
        {"workspace": context.get("workspaceId", ""), "generated": context.get("generatedAt", "")},
    )


def _render_workspace_html(context: dict[str, Any]) -> str:
    layer_sections = []
    single_target = _workspace_target_count(context) == 1
    base_body_class = "high-level" if _presentation_label(_report_mode(context)) == "high_level" else "operator"
    rendered_gaps: set[str] = set()
    toc_items: list[tuple[str, str]] = []
    for layer_index, layer in enumerate(context.get("layers", []) if isinstance(context.get("layers"), list) else [], start=1):
        if not isinstance(layer, dict):
            continue
        layer_id = _slug("layer", layer.get("layer") or layer.get("title") or "layer")
        toc_items.append((layer_id, str(layer.get("title") or layer.get("layer") or "Layer")))
        target_sections = []
        target_detail_sections = []
        rendered_summary_lines: set[tuple[str, str]] = set()
        layer_summary_html = _summary_list(_layer_summary_for_display(layer), seen=rendered_summary_lines)
        layer_targets = layer.get("targets", []) if isinstance(layer.get("targets"), list) else []
        for target in layer_targets:
            if not isinstance(target, dict):
                continue
            target_id = _slug(layer_id, target.get("target", "target"))
            rendered_sections = "".join(
                _render_section_html(section, heading_level=4, extra_class="operator-only")
                for section in target.get("sections", [])
                if isinstance(section, dict)
            )
            target_gaps = _render_unique_string_list('Coverage Gaps', target.get('gaps', []), rendered_gaps)
            if single_target:
                if rendered_sections or target_gaps:
                    target_detail_sections.append(rendered_sections + target_gaps)
                continue
            toc_items.append((target_id, str(target.get("target", "Target"))))
            target_sections.append(
                f"<section class=\"block target-block operator-only\" id=\"{_html(target_id)}\">"
                f"<h3>{_html(target.get('target', 'Target'))}</h3>"
                f"{_summary_list(target.get('summary', {}), seen=rendered_summary_lines)}"
                f"{target_gaps}"
                + rendered_sections
                + "</section>"
            )
        rendered_layer_sections = "".join(
            _render_section_html(section, heading_level=3, extra_class="operator-only") for section in _workspace_layer_sections(layer)
        )
        operator_detail = _render_operator_detail(
            layer,
            rendered_layer_sections + "".join(target_sections) + "".join(target_detail_sections),
        )
        layer_sections.append(
            f"<section class=\"layer\" id=\"{_html(layer_id)}\">"
            f"{_layer_head(layer.get('title') or layer.get('layer') or 'Layer', f'{layer_index:02d}', _layer_subtitle(layer))}"
            f"{layer_summary_html}"
            f"{_render_layer_highlights(layer)}"
            f"{_render_layer_brief(layer, single_target=single_target)}"
            + operator_detail
            + _render_unique_string_list("Coverage Gaps", layer.get("gaps", []), rendered_gaps)
            + "</section>"
        )
    body = "\n".join(
        [
            banner_html(
                context.get("title") or "Workspace Report",
                "Consolidated all-layer workspace report generated from Synapse state.",
                {
                    "report": '<span id="reportName">Operator Report</span>',
                    "workspace": context.get("workspaceId", ""),
                    "target": _workspace_primary_target(context),
                    "generated": context.get("generatedAt", ""),
                },
            ),
            _render_workspace_risk_posture(context),
            _render_workspace_finding_cards(context, single_target=single_target),
            _render_executive_summary(context),
            '<div class="wrap operator-only"><div class="layout">',
            _render_toc(toc_items),
            '<main class="synapse-report-main">',
            *layer_sections,
            _render_unique_string_list("Workspace Coverage Gaps", context.get("gaps", []), rendered_gaps, section=True),
            _render_string_list("Workspace Recommended Next Steps", context.get("recommendedNextSteps", []), section=True),
            "</main></div></div>",
        ]
    )
    return html_shell(
        str(context.get("title") or "Workspace Report"),
        body,
        TREE_SCRIPT,
        {"workspace": context.get("workspaceId", ""), "generated": context.get("generatedAt", "")},
        body_class=f"{base_body_class} single-target" if single_target else base_body_class,
    )


def _workspace_target_count(context: dict[str, Any]) -> int:
    summary = context.get("summary", {}) if isinstance(context.get("summary"), dict) else {}
    try:
        summary_count = int(summary.get("targetCount", 0) or 0)
    except (TypeError, ValueError):
        summary_count = 0
    if summary_count:
        return summary_count
    targets: set[str] = set()
    for layer in context.get("layers", []) if isinstance(context.get("layers"), list) else []:
        if not isinstance(layer, dict):
            continue
        for target in layer.get("targets", []) if isinstance(layer.get("targets"), list) else []:
            if not isinstance(target, dict):
                continue
            name = str(target.get("target") or "").strip()
            if name:
                targets.add(name.lower())
    return len(targets)


def _workspace_primary_target(context: dict[str, Any]) -> str:
    for layer in context.get("layers", []) if isinstance(context.get("layers"), list) else []:
        if not isinstance(layer, dict):
            continue
        for target in layer.get("targets", []) if isinstance(layer.get("targets"), list) else []:
            if isinstance(target, dict):
                name = str(target.get("target") or "").strip()
                if name:
                    return name
    return ""


def _render_operator_detail(layer: dict[str, Any], detail_html: str) -> str:
    if not str(detail_html or "").strip():
        return ""
    title = str(layer.get("title") or layer.get("layer") or "Layer")
    return (
        '<details class="operator-detail operator-only">'
        f'<summary>Operator Detail <span>{_html(title)}</span></summary>'
        f'<div class="operator-detail-body">{detail_html}</div>'
        "</details>"
    )


def _render_layer_brief(layer: dict[str, Any], *, single_target: bool) -> str:
    name = str(layer.get("layer") or "").lower()
    if name != "web_vulnerabilities":
        return ""
    rows = _web_vulnerability_brief_rows(layer, single_target=single_target)
    if not rows:
        return ""
    headers = ["Family", "Top Surface", "Parameter", "Priority", "Count"] if single_target else ["Host", "Family", "Top Surface", "Parameter", "Priority", "Count"]
    return (
        '<section class="block layer-brief">'
        '<h3>High-Value Candidate Surface</h3>'
        f"{_html_table(headers, rows)}"
        "</section>"
    )


def _web_vulnerability_brief_rows(layer: dict[str, Any], *, single_target: bool) -> list[list[Any]]:
    for section in _workspace_layer_sections(layer):
        if str(section.get("sectionId", "")) != "web_vulnerability_candidates":
            continue
        rows: list[list[Any]] = []
        for group in _candidate_groups(section):
            group_rows = group.get("rows", []) if isinstance(group.get("rows"), list) else []
            if not group_rows:
                continue
            headers = [str(item) for item in group.get("headers", [])]
            first = group_rows[0] if isinstance(group_rows[0], list) else []
            data = {header: first[index] if index < len(first) else "" for index, header in enumerate(headers)}
            brief_row = [
                _candidate_category_label(group.get("category", "Candidates")),
                data.get("Top Surface", ""),
                data.get("Parameter", ""),
                data.get("Priority", ""),
                group.get("count", len(group_rows)),
            ]
            if not single_target:
                brief_row.insert(0, data.get("Host", ""))
            rows.append(brief_row)
        return rows
    return []


# Per-layer summary keys that are redundant as headline stat tiles. The full set is
# still preserved in the workspace JSON/context; this only de-noises the at-a-glance
# tile row so each layer reads like the curated hand-built template (e.g. the JS layer
# shows assets / inferred endpoints / signals, not three overlapping endpoint totals).
_LAYER_TILE_DENY: dict[str, set[str]] = {
    "js": {"endpointCount", "observedEndpointCount", "parameterCount"},
    "web_vulnerabilities": {"moduleCounts"},
}


def _layer_summary_for_display(layer: dict[str, Any]) -> dict[str, Any]:
    summary = layer.get("summary", {}) if isinstance(layer.get("summary"), dict) else {}
    deny = _LAYER_TILE_DENY.get(str(layer.get("layer") or "").lower())
    if not deny:
        return summary
    return {key: value for key, value in summary.items() if key not in deny}


def _render_layer_markdown(context: dict[str, Any]) -> str:
    rendered_gaps: set[str] = set()
    rendered_summary_lines: set[tuple[str, str]] = set()
    lines = [
        f"# {context.get('title') or 'Layer Report'}",
        "",
        f"- Workspace: `{context.get('workspaceId', '')}`",
        f"- Layer: `{context.get('layer', '')}`",
        f"- Generated: `{context.get('generatedAt', '')}`",
        "",
    ]
    lines.extend(_markdown_summary(context.get("summary", {}), seen=rendered_summary_lines))
    for section in context.get("sections", []) if isinstance(context.get("sections"), list) else []:
        if isinstance(section, dict):
            lines.extend(_render_section_markdown(section, heading_level=2))
    for target in context.get("targets", []) if isinstance(context.get("targets"), list) else []:
        if not isinstance(target, dict):
            continue
        lines.extend(["", f"## {target.get('target', 'Target')}", ""])
        lines.extend(_markdown_summary(target.get("summary", {}), seen=rendered_summary_lines))
        lines.extend(_markdown_unique_string_list("Coverage Gaps", target.get("gaps", []), rendered_gaps, heading_level=3))
        for section in target.get("sections", []) if isinstance(target.get("sections"), list) else []:
            if isinstance(section, dict):
                lines.extend(_render_section_markdown(section, heading_level=3))
    lines.extend(_markdown_unique_string_list("Coverage Gaps", context.get("gaps", []), rendered_gaps, heading_level=2))
    lines.extend(_markdown_string_list("Recommended Next Steps", context.get("recommendedNextSteps", []), heading_level=2))
    return "\n".join(lines).rstrip() + "\n"


def _render_workspace_markdown(context: dict[str, Any]) -> str:
    rendered_gaps: set[str] = set()
    mode = _report_mode(context)
    lines = [
        f"# {context.get('title') or 'Workspace Report'}",
        "",
        f"- Report: `{_report_type_label(mode)}`",
        f"- Workspace: `{context.get('workspaceId', '')}`",
        f"- Presentation mode: `{_presentation_label(mode)}`",
        f"- Generated: `{context.get('generatedAt', '')}`",
        "",
    ]
    lines.extend(_markdown_summary(context.get("summary", {})))
    for layer in context.get("layers", []) if isinstance(context.get("layers"), list) else []:
        if not isinstance(layer, dict):
            continue
        lines.extend(["", f"## {layer.get('title') or layer.get('layer') or 'Layer'}", ""])
        rendered_summary_lines: set[tuple[str, str]] = set()
        lines.extend(_markdown_summary(layer.get("summary", {}), seen=rendered_summary_lines))
        for section in _workspace_layer_sections(layer):
            lines.extend(_render_section_markdown(section, heading_level=3))
        for target in layer.get("targets", []) if isinstance(layer.get("targets"), list) else []:
            if not isinstance(target, dict):
                continue
            lines.extend(["", f"### {target.get('target', 'Target')}", ""])
            lines.extend(_markdown_summary(target.get("summary", {}), seen=rendered_summary_lines))
            lines.extend(_markdown_unique_string_list("Coverage Gaps", target.get("gaps", []), rendered_gaps, heading_level=4))
            for section in target.get("sections", []) if isinstance(target.get("sections"), list) else []:
                if isinstance(section, dict):
                    lines.extend(_render_section_markdown(section, heading_level=4))
        lines.extend(_markdown_unique_string_list("Coverage Gaps", layer.get("gaps", []), rendered_gaps, heading_level=3))
    lines.extend(_markdown_unique_string_list("Workspace Coverage Gaps", context.get("gaps", []), rendered_gaps, heading_level=2))
    lines.extend(_markdown_string_list("Workspace Recommended Next Steps", context.get("recommendedNextSteps", []), heading_level=2))
    return "\n".join(lines).rstrip() + "\n"


def _report_mode(context: dict[str, Any]) -> str:
    redaction = context.get("redaction")
    mode = str((redaction or {}).get("mode") or "").strip().lower() if isinstance(redaction, dict) else ""
    return mode or "internal"


def _report_type_label(mode: str) -> str:
    return {"safe": "High-Level", "high_level": "High-Level", "internal": "Operator", "raw": "Operator (raw)"}.get(str(mode or "").lower(), "Workspace")


def _presentation_label(mode: str) -> str:
    return {"safe": "high_level", "high_level": "high_level", "internal": "operator", "raw": "operator_raw"}.get(str(mode or "").lower(), "operator")


def _layer_head(title: Any, index: Any, subtitle: Any = "") -> str:
    sub = f'<span class="sub">{_html(subtitle)}</span>' if str(subtitle or "").strip() else ""
    return f'<div class="layer-head"><span class="idx">{_html(index)}</span><h2>{_html(title)}</h2>{sub}</div>'


def _layer_subtitle(layer: dict[str, Any]) -> str:
    name = str(layer.get("layer") or "").lower()
    return {
        "access_control": "BOLA / BFLA / BOPLA",
        "js": "static analysis",
        "auth": "boundaries",
        "perimeter": "surface",
        "engagement": "pretext & detection",
    }.get(name, "")


def _render_workspace_risk_posture(context: dict[str, Any]) -> str:
    findings = _workspace_finding_records(context)
    candidate_drivers = _workspace_candidate_drivers(context)
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        counts[severity if severity in counts else "info"] += 1
    total_candidates = sum(int(item.get("count", 0) or 0) for item in candidate_drivers)
    driver_count = len({str(item.get("label", "")) for item in candidate_drivers if item.get("label")})
    summary_bits = []
    if findings:
        summary_bits.append(f"{len(findings)} confirmed finding{'s' if len(findings) != 1 else ''}")
    if total_candidates:
        summary_bits.append(f"{total_candidates} candidate observation{'s' if total_candidates != 1 else ''} across {driver_count} report groups")
    summary = " - ".join(summary_bits) if summary_bits else "No confirmed findings or passive candidate observations are recorded."
    tiles = "".join(
        "<div class=\"risk-tile severity-{severity}{zero}\"><span class=\"risk-num\">{count}</span><span class=\"risk-label\">{label}</span></div>".format(
            severity=_html(severity),
            zero=" is-zero" if counts[severity] == 0 else "",
            count=_html(counts[severity]),
            label=_html(severity.title()),
        )
        for severity in ("critical", "high", "medium", "low", "info")
    )
    risk_drivers = _workspace_finding_drivers(findings) + candidate_drivers
    drivers = "".join(
        "<span class=\"risk-driver severity-{severity}\"><b>{count}</b> {label}<em>{layer}</em></span>".format(
            severity=_html(str(item.get("severity") or "info")),
            count=_html(item.get("count", 0)),
            label=_html(item.get("label", "")),
            layer=_html(f" · {item.get('layer')}" if str(item.get("layer") or "").strip() else ""),
        )
        for item in risk_drivers[:6]
    )
    driver_html = f'<div class="risk-drivers">{drivers}</div>' if drivers else ""
    return (
        '<section class="report-strip risk-panel">'
        '<div class="risk-top"><div><span class="section-label">Risk Posture</span>'
        f'<p>{_html(summary)}</p></div></div>'
        f'<div class="risk-tiles">{tiles}</div>'
        f"{driver_html}"
        "</section>"
    )


def _render_workspace_finding_cards(context: dict[str, Any], *, single_target: bool = False) -> str:
    findings = _workspace_finding_records(context)
    if not findings:
        return ""
    cards = []
    for finding in findings[:6]:
        title = str(finding.get("title") or "Untitled finding")
        severity = str(finding.get("severity") or "info")
        status = str(finding.get("status") or "confirmed")
        assets = str(finding.get("affectedAssets") or finding.get("host") or "").strip()
        evidence = str(finding.get("evidence") or "").strip()
        detail = _single_target_asset_label(assets, finding.get("host", "")) if single_target else assets
        detail = detail or "Affected asset not recorded."
        ref = f'<div class="finding-ref operator-only">{_html(evidence)}</div>' if evidence else ""
        cards.append(
            '<article class="finding-card">'
            '<div class="finding-card-top">'
            f'{_badge_html(severity, "Severity")}{_badge_html(status, "Status")}'
            f'<span class="mono muted host-label">{_html(finding.get("host", ""))}</span>'
            '</div>'
            f'<h4>{_html(title)}</h4>'
            f'<p>{_html(detail)}</p>'
            f"{ref}"
            "</article>"
        )
    return (
        '<section class="report-strip finding-strip operator-only">'
        '<h3 class="section-label">Confirmed Findings - operator-reviewed</h3>'
        f'<div class="finding-grid">{"".join(cards)}</div>'
        "</section>"
    )


def _single_target_asset_label(value: str, target: Any) -> str:
    target_host = _hostname_for_target(target)
    parts = [part.strip() for part in str(value or "").split(",") if part.strip()]
    return ", ".join(_single_target_url_label(part, target_host) for part in parts)


def _single_target_url_label(value: str, target_host: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    if target_host and parsed.hostname and parsed.hostname.lower() != target_host:
        return value
    label = parsed.path or "/"
    if parsed.query:
        label += f"?{parsed.query}"
    if parsed.fragment:
        label += f"#{parsed.fragment}"
    return label


def _hostname_for_target(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw.split(":", 1)[0]).lower()


def _render_layer_highlights(layer: dict[str, Any]) -> str:
    items: list[str] = []
    name = str(layer.get("layer") or "").lower()
    summary = layer.get("summary", {}) if isinstance(layer.get("summary"), dict) else {}
    if name == "web_vulnerabilities":
        candidate_count = int(summary.get("candidateCount", 0) or 0)
        module_counts = summary.get("moduleCounts", {}) if isinstance(summary.get("moduleCounts"), dict) else {}
        if candidate_count:
            modules = sorted(_candidate_category_label(module) for module in module_counts)[:6]
            items.append(f"{candidate_count} passive candidate observations are grouped into high-value surfaces across {len(module_counts)} analyzer families.")
            if modules:
                items.append(f"Families with reportable surface: {', '.join(modules)}.")
        else:
            items.append("No passive web vulnerability candidate observations are recorded.")
    elif name == "access_control":
        replay_count = int(summary.get("replayCount", 0) or 0)
        review_count = int(summary.get("accessControlReviewItems", 0) or 0)
        matrix_count = int(summary.get("matrixCount", 0) or 0)
        items.append(f"{matrix_count} planned access-control matrix entries, {replay_count} replay results, and {review_count} access-control review items are recorded.")
    elif name == "js":
        inferred = int(summary.get("jsInferredEndpointCount", 0) or 0)
        assets = int(summary.get("assetCount", 0) or 0)
        signals = int(summary.get("jsSignalCount", 0) or 0)
        items.append(f"{assets} JavaScript assets, {inferred} inferred endpoints, and {signals} client-side signals are recorded.")
    elif name == "auth":
        portals = int(summary.get("loginPortalCount", 0) or 0)
        protected = int(summary.get("protectedResourceCount", 0) or 0)
        credentials = int(summary.get("credentialMetadataCount", 0) or 0)
        items.append(f"{portals} login portals, {protected} protected-resource observations, and {credentials} credential/profile metadata records are in scope for this report.")
    elif name == "perimeter":
        endpoints = int(summary.get("endpointCount", 0) or 0)
        technologies = int(summary.get("technologyCount", 0) or 0)
        candidates = int(summary.get("candidateCount", 0) or 0)
        items.append(f"{endpoints} endpoints, {technologies} technology components, and {candidates} perimeter review candidates are summarized.")
    gaps = layer.get("gaps", []) if isinstance(layer.get("gaps"), list) else []
    if gaps:
        items.append(f"{len(gaps)} coverage gap{'s' if len(gaps) != 1 else ''} remain for this layer.")
    if not items:
        return ""
    return '<ul class="layer-highlights high-level-only">' + "".join(f"<li>{_html(item)}</li>" for item in items) + "</ul>"


def _workspace_finding_records(context: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for layer in context.get("layers", []) if isinstance(context.get("layers"), list) else []:
        if not isinstance(layer, dict):
            continue
        for section in layer.get("sections", []) if isinstance(layer.get("sections"), list) else []:
            if not isinstance(section, dict) or str(section.get("sectionId", "")) != "reviewed_findings":
                continue
            headers = [str(item) for item in section.get("headers", [])]
            for row in section.get("rows", []) if isinstance(section.get("rows"), list) else []:
                if not isinstance(row, list):
                    continue
                data = {headers[index]: row[index] if index < len(row) else "" for index in range(len(headers))}
                status = str(data.get("Status", "") or "").lower()
                if status and "confirmed" not in status:
                    continue
                records.append(
                    {
                        "host": data.get("Host", ""),
                        "severity": data.get("Severity", "info"),
                        "title": data.get("Title", ""),
                        "status": data.get("Status", ""),
                        "affectedAssets": data.get("Affected Assets", ""),
                        "evidence": data.get("Evidence", ""),
                    }
                )
    return sorted(records, key=lambda item: (_severity_rank(item.get("severity", "")), str(item.get("title", "")).lower()))


def _workspace_candidate_drivers(context: dict[str, Any]) -> list[dict[str, Any]]:
    drivers: list[dict[str, Any]] = []
    for layer in context.get("layers", []) if isinstance(context.get("layers"), list) else []:
        if not isinstance(layer, dict):
            continue
        layer_name = str(layer.get("layer") or layer.get("title") or "layer")
        if layer_name == "perimeter":
            continue
        for section in layer.get("sections", []) if isinstance(layer.get("sections"), list) else []:
            if not isinstance(section, dict) or str(section.get("kind", "")) != "candidate_groups":
                continue
            metadata = section.get("metadata", {}) if isinstance(section.get("metadata"), dict) else {}
            groups = metadata.get("groups", []) if isinstance(metadata.get("groups"), list) else []
            for group in groups:
                if not isinstance(group, dict):
                    continue
                rows = group.get("rows", []) if isinstance(group.get("rows"), list) else []
                headers = [str(item) for item in group.get("headers", [])]
                severity = _group_worst_severity(headers, rows)
                drivers.append(
                    {
                        "label": _candidate_category_label(group.get("category", "Candidates")),
                        "count": int(group.get("count", 0) or len(rows)),
                        "severity": severity,
                        # These rows are passive candidate observations, not confirmed
                        # vulnerabilities; label them as such so the risk posture does not
                        # read as e.g. "27 confirmed web vulnerabilities".
                        "layer": "candidates",
                    }
                )
    return sorted(drivers, key=lambda item: (_severity_rank(item.get("severity", "")), -int(item.get("count", 0) or 0), str(item.get("label", "")).lower()))


def _workspace_finding_drivers(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not findings:
        return []
    severity = sorted((str(item.get("severity") or "info") for item in findings), key=_severity_rank)[0]
    return [{"label": "confirmed findings", "count": len(findings), "severity": severity, "layer": ""}]


# Executive-summary themes: candidate analyzer families collapse into a handful of
# plain-language concern areas so the high-level view reads as a stakeholder briefing,
# not an acronym list. Pure presentation over existing workspace data.
_EXEC_THEME_ORDER = ("access", "injection", "forgery", "config", "other")
_EXEC_THEME_NAMES = {
    "access": "Access control & authorization",
    "injection": "Injection & server-side input handling",
    "forgery": "Cross-site request & cross-origin handling",
    "config": "Security headers & transport hardening",
    "other": "Other candidate exposures",
}
_EXEC_THEME_RECS = {
    "access": "Enforce per-object and per-function authorization on the server for every sensitive request.",
    "injection": "Validate and encode user-supplied input on the flagged server-side surfaces.",
    "forgery": "Require anti-forgery tokens on state-changing requests and restrict cross-origin access.",
    "config": "Apply a baseline security-header and transport-hardening policy across the application.",
    "other": "Validate the remaining candidate exposures before release.",
}


def _exec_theme_key(label: str, layer: str) -> str:
    text = f"{label} {layer}".lower()
    if "access control" in str(layer or "").lower():
        return "access"
    if any(token in text for token in ("ssrf", "lfi", "rfi", "xss", "sqli", "ssti", "xxe", "command", "injection", "deserial", "template")):
        return "injection"
    if any(token in text for token in ("csrf", "redirect", "cors", "origin")):
        return "forgery"
    if any(token in text for token in ("csp", "header", "hsts", "tls", "cookie", "clickjack", "cache-control")):
        return "config"
    return "other"


def _executive_themes(drivers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for driver in drivers:
        key = _exec_theme_key(str(driver.get("label", "")), str(driver.get("layer", "")))
        bucket = buckets.setdefault(key, {"key": key, "name": _EXEC_THEME_NAMES[key], "count": 0, "severity": "info"})
        bucket["count"] += int(driver.get("count", 0) or 0)
        if _severity_rank(driver.get("severity", "info")) < _severity_rank(bucket["severity"]):
            bucket["severity"] = str(driver.get("severity") or "info")
    return [buckets[key] for key in _EXEC_THEME_ORDER if key in buckets]


# Strip operator-facing locators (a `via GET /path` request line) and leading vuln
# acronyms from a finding title so the executive view reads in plain business terms.
_EXEC_METHOD_SUFFIX = re.compile(r"\s+via\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b.*$", re.IGNORECASE)
_EXEC_ACRONYM_PREFIX = re.compile(r"^(?:BOLA|BFLA|BOPLA|IDOR|SSRF|LFI|RFI|XSS|SQLI|SSTI|XXE|CSRF|CORS)\b\s*[:/\-–—]?\s*", re.IGNORECASE)


def _executive_finding_title(title: Any) -> str:
    original = str(title or "").strip()
    text = _EXEC_METHOD_SUFFIX.sub("", original)
    text = _EXEC_ACRONYM_PREFIX.sub("", text).strip(" :/-–—")
    if not text:
        text = original
    return text[0].upper() + text[1:] if text else text


def _render_executive_summary(context: dict[str, Any]) -> str:
    findings = _workspace_finding_records(context)
    themes = _executive_themes(_workspace_candidate_drivers(context))
    severe = sum(1 for item in findings if str(item.get("severity") or "").lower() in {"critical", "high"})
    confirmed = len(findings)
    candidate_total = sum(int(item.get("count", 0) or 0) for item in themes)
    area_count = len(themes)

    if severe:
        posture = "This assessment confirmed high-severity weaknesses that warrant prompt remediation."
    elif confirmed:
        posture = "This assessment confirmed weaknesses of limited severity."
    elif candidate_total:
        posture = "No weaknesses were confirmed, but candidate exposures remain to be validated."
    else:
        posture = "No confirmed findings or candidate exposures were recorded in this assessment."

    count_bits: list[str] = []
    if confirmed:
        count_bits.append(f"{confirmed} confirmed finding{'s' if confirmed != 1 else ''}")
    if candidate_total:
        count_bits.append(
            f"{candidate_total} candidate exposure{'s' if candidate_total != 1 else ''} across {area_count} area{'s' if area_count != 1 else ''}"
        )
    count_line = " &middot; ".join(_html(bit) for bit in count_bits) if count_bits else "No issues recorded"

    if findings:
        finding_items = "".join(
            '<li>{badge}<div class="exec-finding-body"><b>{title}</b><span class="exec-asset">{asset}</span></div></li>'.format(
                badge=_badge_html(str(item.get("severity", "info")).title(), "Severity"),
                title=_html(_executive_finding_title(item.get("title")) or "Untitled finding"),
                asset=_html(
                    _single_target_asset_label(str(item.get("affectedAssets") or ""), item.get("host", ""))
                    or "Affected area not recorded."
                ),
            )
            for item in findings
        )
        findings_html = f'<ol class="exec-findings">{finding_items}</ol>'
    else:
        findings_html = '<p class="exec-empty">No findings were confirmed in this assessment.</p>'

    if themes:
        theme_items = "".join(
            '<li><span class="exec-dot severity-{sev}"></span><b>{name}</b><span class="exec-theme-meta">{count} to validate</span></li>'.format(
                sev=_html(str(theme.get("severity") or "info")),
                name=_html(theme.get("name", "")),
                count=_html(theme.get("count", 0)),
            )
            for theme in themes
        )
        themes_html = f'<ul class="exec-themes">{theme_items}</ul>'
    else:
        themes_html = '<p class="exec-empty">No candidate exposures were recorded.</p>'

    recs: list[str] = []
    if confirmed:
        lead = f"Prioritize remediation of the {confirmed} confirmed finding{'s' if confirmed != 1 else ''}"
        recs.append(lead + (f", treating the {severe} high-severity item{'s' if severe != 1 else ''} as immediate." if severe else "."))
    recs.extend(_EXEC_THEME_RECS[theme["key"]] for theme in themes)
    if confirmed or candidate_total:
        recs.append("Re-test after remediation to confirm the issues are closed.")
    if recs:
        rec_items = "".join(
            f'<li><span class="num">{index}</span><span>{_html(text)}</span></li>' for index, text in enumerate(recs, start=1)
        )
        recs_html = f'<ol class="exec-actions">{rec_items}</ol>'
    else:
        recs_html = '<p class="exec-empty">No recommended actions at this time.</p>'

    return (
        '<section class="exec-summary high-level-only">'
        '<span class="exec-eyebrow">Executive Summary</span>'
        f'<h2 class="exec-headline">{_html(posture)}</h2>'
        f'<p class="exec-sub">{count_line}. Technical detail, evidence, and reproduction steps are in the operator report.</p>'
        f'<div class="exec-block"><h3 class="exec-label">Key Findings</h3>{findings_html}</div>'
        f'<div class="exec-block"><h3 class="exec-label">Areas Requiring Attention</h3>{themes_html}</div>'
        f'<div class="exec-block"><h3 class="exec-label">Recommended Actions</h3>{recs_html}</div>'
        "</section>"
    )


def _group_worst_severity(headers: list[str], rows: list[Any]) -> str:
    for header in ("Severity", "Priority", "Risk", "Assessment", "Status"):
        if header not in headers:
            continue
        index = headers.index(header)
        severities = [str(row[index]) for row in rows if isinstance(row, list) and index < len(row)]
        if severities:
            return sorted(severities, key=_severity_rank)[0]
    return "info"


def _empty_state_text(title: Any) -> str:
    label = str(title or "records").strip() or "records"
    return f"No {label.lower()} recorded."


def _render_section_html(section: dict[str, Any], heading_level: int = 2, extra_class: str = "") -> str:
    title = _html(section.get("title", "Section"))
    heading = f"h{heading_level}"
    section_id = _section_anchor(section)
    summary = f"<p>{_html(section.get('summary', ''))}</p>" if section.get("summary") else ""
    kind = str(section.get("kind", "table"))
    if not _section_has_content(section):
        content = f'<p class="empty-state">{_html(_empty_state_text(section.get("title")))}</p>'
    elif kind == "tree":
        content = _render_tree(section.get("tree", {}), section.get("sectionId", "tree"))
    elif kind == "candidate_groups":
        content = _render_candidate_groups(section)
    elif kind == "signal_groups":
        content = _render_signal_groups(section)
    elif section.get("rows") and section.get("headers"):
        content = _html_table(section.get("headers", []), section.get("rows", []))
    elif section.get("items"):
        content = _html_table(_headers_for_items(section.get("items", [])), _rows_for_items(section.get("items", [])))
    else:
        content = f'<p class="empty-state">{_html(_empty_state_text(section.get("title")))}</p>'
    class_name = "block" + (f" {extra_class}" if extra_class else "")
    return f"<section class=\"{_html(class_name)}\" id=\"{_html(section_id)}\"><{heading}>{title}</{heading}>{summary}{content}</section>"


def _render_section_markdown(section: dict[str, Any], heading_level: int = 2) -> list[str]:
    heading = "#" * heading_level
    title = section.get("title", "Section")
    lines = ["", f"{heading} {title}", ""]
    if section.get("summary"):
        lines.extend([str(section["summary"]), ""])
    if not _section_has_content(section):
        lines.append(f"_{_empty_state_text(title)}_")
    elif str(section.get("kind", "")) == "candidate_groups":
        lines.extend(_render_candidate_groups_markdown(section, title))
    elif str(section.get("kind", "")) == "signal_groups":
        lines.extend(_render_signal_groups_markdown(section, title))
    elif section.get("headers") and section.get("rows"):
        headers = [str(item) for item in section.get("headers", [])]
        lines.append("| " + " | ".join(_md(item) for item in headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in section.get("rows", []):
            if isinstance(row, list):
                lines.append("| " + " | ".join(_md(item) for item in row) + " |")
    elif str(section.get("kind", "")) == "tree":
        lines.append("Tree data is available in the JSON context and HTML report.")
    else:
        lines.append(f"_{_empty_state_text(title)}_")
    return lines


def _render_tree(tree: dict[str, Any], tree_id: str) -> str:
    if not isinstance(tree, dict) or not tree:
        return "<p>No tree records.</p>"
    safe_id = "".join(ch if ch.isalnum() else "_" for ch in tree_id)
    controls = (
        f"<div class=\"controls\"><input type=\"search\" placeholder=\"Filter this tree\" oninput=\"synapseFilterTree('{safe_id}', this.value)\">"
        f"<button type=\"button\" onclick=\"synapseToggleTree('{safe_id}', true)\">Expand all</button>"
        f"<button type=\"button\" onclick=\"synapseToggleTree('{safe_id}', false)\">Collapse all</button></div>"
    )
    return controls + f"<div class=\"tree\" id=\"{_html(safe_id)}\">{_render_tree_node(tree, root=True)}</div>"


def _render_tree_node(node: dict[str, Any], root: bool = False) -> str:
    children = node.get("children", []) if isinstance(node.get("children"), list) else []
    endpoints = node.get("endpoints", []) if isinstance(node.get("endpoints"), list) else []
    requests = node.get("requests", []) if isinstance(node.get("requests"), list) else []
    inner = "".join(_render_tree_node(child) for child in children if isinstance(child, dict))
    inner += "".join(_render_record(item, "endpoint") for item in endpoints if isinstance(item, dict))
    inner += "".join(_render_record(item, "request") for item in requests if isinstance(item, dict))
    if root:
        return inner or "<p>No records.</p>"
    return (
        "<details>"
        f"<summary>{_html(node.get('name', ''))} <span class=\"muted\">{_html(node.get('endpointCount', 0))}</span></summary>"
        f"{inner}"
        "</details>"
    )


def _render_record(item: dict[str, Any], class_name: str) -> str:
    params = ", ".join(str(value) for value in item.get("queryParameters", []) if str(value).strip()) if isinstance(item.get("queryParameters"), list) else ""
    if not params and isinstance(item.get("parameters"), list):
        params = ", ".join(str(param.get("name", "")) for param in item["parameters"] if isinstance(param, dict) and param.get("name"))
    badges = "".join(f"<span class=\"badge\">{_html(flag)}</span>" for flag in item.get("flags", []) if str(flag).strip()) if isinstance(item.get("flags"), list) else ""
    origin = item.get("origin") or item.get("status", "")
    origin_class = " js" if str(origin) == "js_inferred" else (" observed" if str(origin) == "observed" else "")
    source = item.get("sourceAsset") or item.get("source") or item.get("title", "")
    return (
        f"<div class=\"record {class_name}{origin_class}\">"
        f"<span>{_html(item.get('method', ''))}</span>"
        f"<span>{_html(origin)}</span>"
        f"<code title=\"{_html(item.get('url', ''))}\">{_html(item.get('label') or item.get('path') or item.get('url', ''))}</code>"
        f"<span>{_html(params)}</span>"
        f"<span class=\"muted\">{badges}<br>{_html(source)}</span>"
        "</div>"
    )


def _summary_list(summary: dict[str, Any], *, seen: set[tuple[str, str]] | None = None) -> str:
    if not isinstance(summary, dict) or not summary:
        return "<p>No summary values.</p>"
    cards = []
    items = []
    for key, value in summary.items():
        label = _label(key)
        rendered = _summary_value(value)
        identity = (label, rendered)
        if seen is not None and identity in seen:
            continue
        if seen is not None:
            seen.add(identity)
        if _is_numeric_summary(value):
            cards.append(f"<div class=\"stat-card\"><span class=\"stat-value\">{_html(rendered)}</span><span class=\"stat-label\">{_html(label)}</span></div>")
        else:
            items.append(f"<li><strong>{_html(label)}:</strong> {_html(rendered)}</li>")
    if not cards and not items:
        return ""
    card_html = f"<div class=\"stat-grid\">{''.join(cards)}</div>" if cards else ""
    list_html = f"<ul class=\"summary-list\">{''.join(items)}</ul>" if items else ""
    return f"<div class=\"summary-block\">{card_html}{list_html}</div>"


def _render_string_list(title: str, items: Any, *, section: bool = False) -> str:
    values = _string_items(items)
    if not values:
        content = '<p class="empty-state">No records.</p>'
    elif "recommended next steps" in title.lower():
        content = '<ol class="next-step-list">' + "".join(
            f'<li><span class="step-num">{index}</span><span>{_html(item)}</span></li>'
            for index, item in enumerate(values, start=1)
        ) + "</ol>"
    else:
        content = "<ul>" + "".join(f"<li>{_html(item)}</li>" for item in values) + "</ul>"
    if section:
        return f"<section class=\"layer\">{_layer_head(title, '++')}{content}</section>"
    return f"<h3>{_html(title)}</h3>{content}"


def _render_unique_string_list(title: str, items: Any, rendered: set[str], *, section: bool = False) -> str:
    values = _new_string_items(items, rendered)
    if not values:
        return "" if section else ""
    content = "<ul>" + "".join(f"<li>{_html(item)}</li>" for item in values) + "</ul>"
    if section:
        return f"<section class=\"layer\">{_layer_head(title, '++')}{content}</section>"
    return f"<h3>{_html(title)}</h3>{content}"


def _markdown_summary(summary: dict[str, Any], *, seen: set[tuple[str, str]] | None = None) -> list[str]:
    if not isinstance(summary, dict):
        return []
    lines = []
    for key, value in summary.items():
        label = _label(key)
        rendered = _summary_value(value)
        identity = (label, rendered)
        if seen is not None and identity in seen:
            continue
        if seen is not None:
            seen.add(identity)
        lines.append(f"- {label}: `{rendered}`")
    return lines + [""] if lines else []


def _markdown_string_list(title: str, items: Any, heading_level: int) -> list[str]:
    lines = ["", f"{'#' * heading_level} {title}", ""]
    values = _string_items(items)
    if values:
        lines.extend(f"- {item}" for item in values)
    else:
        lines.append("No records.")
    return lines


def _markdown_unique_string_list(title: str, items: Any, rendered: set[str], heading_level: int) -> list[str]:
    values = _new_string_items(items, rendered)
    if not values:
        return []
    return ["", f"{'#' * heading_level} {title}", "", *[f"- {item}" for item in values]]


def _html_table(headers: list[Any], rows: list[list[Any]]) -> str:
    if not rows:
        return '<p class="empty-state">No records.</p>'
    head = "<tr>" + "".join(f'<th class="{_header_class(item)}">{_html(item)}</th>' for item in headers) + "</tr>"
    body = "".join("<tr>" + "".join(f'<td class="{_header_class(headers[index] if index < len(headers) else "")}">{_html_cell(cell, headers[index] if index < len(headers) else "")}</td>' for index, cell in enumerate(row)) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{body}</tbody></table></div>'


def _candidate_groups(section: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = section.get("metadata") if isinstance(section.get("metadata"), dict) else {}
    groups = metadata.get("groups", [])
    return [group for group in groups if isinstance(group, dict) and group.get("rows")] if isinstance(groups, list) else []


def _candidate_group_label(group: dict[str, Any]) -> tuple[str, str]:
    count = group.get("count", len(group.get("rows", [])))
    noun = "candidate" if count == 1 else "candidates"
    return _candidate_category_label(group.get("category", "Candidates")), f"({count} {noun})"


def _candidate_category_label(value: Any) -> str:
    raw = str(value or "").strip()
    labels = {
        "headers_cookies": "Security Headers / Cookies",
        "csrf": "CSRF",
        "cors": "CORS",
        "ssrf": "SSRF",
        "lfi": "LFI / RFI",
        "ssti": "SSTI",
        "ssi": "SSI",
        "open_redirect": "Open Redirect",
        "command_injection": "Command Injection",
        "graphql": "GraphQL",
        "xxe": "XXE",
        "insecure_deser": "Insecure Deserialization",
        "tls_posture": "TLS Posture",
        "jwt": "JWT",
        "xss": "XSS",
        "sqli": "SQL Injection",
    }
    lowered = raw.lower()
    if lowered in labels:
        return labels[lowered]
    if "_" not in raw and raw != lowered:
        return raw
    return raw.replace("_", " ").strip().title() or "Candidates"


def _render_candidate_groups(section: dict[str, Any]) -> str:
    parts = []
    for group in _candidate_groups(section):
        category, count_label = _candidate_group_label(group)
        heading = f'<h4 class="candidate-group-title">{_html(category)} <span class="muted">{_html(count_label)}</span></h4>'
        parts.append(f'<div class="candidate-group">{heading}{_html_table(group.get("headers", []), group.get("rows", []))}</div>')
    return "".join(parts) or '<p class="empty-state">No candidate observations recorded.</p>'


def _render_candidate_groups_markdown(section: dict[str, Any], title: Any) -> list[str]:
    lines: list[str] = []
    for group in _candidate_groups(section):
        category, count_label = _candidate_group_label(group)
        headers = [str(item) for item in group.get("headers", [])]
        lines.extend(["", f"**{category} {count_label}**", ""])
        lines.append("| " + " | ".join(_md(item) for item in headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in group.get("rows", []):
            if isinstance(row, list):
                lines.append("| " + " | ".join(_md(item) for item in row) + " |")
    return lines or [f"_{_empty_state_text(title)}_"]


def _signal_groups(section: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = section.get("metadata") if isinstance(section.get("metadata"), dict) else {}
    groups = metadata.get("groups", [])
    return [group for group in groups if isinstance(group, dict) and group.get("rows")] if isinstance(groups, list) else []


def _signal_group_label(group: dict[str, Any]) -> tuple[str, str]:
    count = group.get("count", len(group.get("rows", [])))
    noun = "signal" if count == 1 else "signals"
    label = _signal_type_label(group.get("category", "JavaScript signals"))
    return label, f"({count} {noun})"


def _signal_type_label(value: Any) -> str:
    raw = str(value or "").strip().lower()
    labels = {
        "js_endpoint_reference": "Endpoint Reference",
        "js_inferred_endpoint": "Inferred Endpoint",
        "js_rpc_command_group": "RPC Command Group",
        "js_spa_route": "SPA Route",
        "js_value_table_code": "Value Table Code",
    }
    if raw in labels:
        return labels[raw]
    if raw.startswith("js_"):
        raw = raw[3:]
    return raw.replace("_", " ").strip().title() or "JavaScript Signals"


def _render_signal_groups(section: dict[str, Any]) -> str:
    safe_id = "".join(ch if ch.isalnum() else "_" for ch in str(section.get("sectionId", "signals")))
    controls = (
        f"<div class=\"controls\"><input type=\"search\" placeholder=\"Filter JavaScript signals\" oninput=\"synapseFilterTree('{safe_id}', this.value)\">"
        f"<button type=\"button\" onclick=\"synapseToggleTree('{safe_id}', true)\">Expand all</button>"
        f"<button type=\"button\" onclick=\"synapseToggleTree('{safe_id}', false)\">Collapse all</button></div>"
    )
    groups = []
    for group in _signal_groups(section):
        category, count_label = _signal_group_label(group)
        rows = "".join(_render_signal_record(group.get("headers", []), row) for row in group.get("rows", []) if isinstance(row, list))
        body = rows or '<p class="empty-state">No JavaScript signals recorded.</p>'
        groups.append(
            "<details class=\"signal-group\">"
            f"<summary>{_html(category)} <span class=\"muted\">{_html(count_label)}</span></summary>"
            f"{body}"
            "</details>"
        )
    return controls + f"<div class=\"tree signal-tree\" id=\"{_html(safe_id)}\">{''.join(groups)}</div>" if groups else '<p class="empty-state">No JavaScript signals recorded.</p>'


def _render_signal_record(headers: list[Any], row: list[Any]) -> str:
    data = {str(header): row[index] if index < len(row) else "" for index, header in enumerate(headers)}
    host = data.get("Host", "")
    value = data.get("Value", "")
    source = data.get("Source Asset", "")
    reason = data.get("Reason", "")
    return (
        '<div class="record signal-record">'
        f"<span>{_html(host)}</span>"
        f"<code title=\"{_html(value)}\">{_html(value)}</code>"
        f"<span class=\"muted\">{_html(reason)}</span>"
        f"<span class=\"muted operator-only\">{_html(source)}</span>"
        "</div>"
    )


def _render_signal_groups_markdown(section: dict[str, Any], title: Any) -> list[str]:
    lines: list[str] = []
    for group in _signal_groups(section):
        category, count_label = _signal_group_label(group)
        headers = [str(item) for item in group.get("headers", [])]
        value_index = headers.index("Value") if "Value" in headers else 0
        source_index = headers.index("Source Asset") if "Source Asset" in headers else None
        reason_index = headers.index("Reason") if "Reason" in headers else None
        lines.extend(["", f"**{category} {count_label}**", ""])
        for row in group.get("rows", []):
            if not isinstance(row, list):
                continue
            value = row[value_index] if value_index < len(row) else ""
            source = row[source_index] if source_index is not None and source_index < len(row) else ""
            reason = row[reason_index] if reason_index is not None and reason_index < len(row) else ""
            suffix = f" - {reason}" if str(reason).strip() else ""
            source_suffix = f" (source: {source})" if str(source).strip() else ""
            lines.append(f"- `{_md(value)}`{suffix}{source_suffix}")
    return lines or [f"_{_empty_state_text(title)}_"]


def _header_class(header: Any) -> str:
    classes = []
    normalized = str(header or "").strip().lower()
    if _is_operator_only_header(header):
        classes.append("operator-only")
    if normalized in {"host", "hosts"}:
        classes.append("host-column")
    return " ".join(classes)


def _is_operator_only_header(header: Any) -> bool:
    normalized = str(header or "").strip().lower()
    return normalized in {
        "credential id",
        "approval id",
        "local path",
        "replay id",
        "matrix id",
        "context id",
        "sha-256",
        "source asset",
        "source",
        "username/profile",
        "id",
        "exploit reference",
        "subject",
        "sender persona",
        "body template",
        "action reference",
    }


def _column_widths(headers: list[Any], rows: list[list[Any]]) -> list[float]:
    if not headers:
        return []
    weights = []
    for index, header in enumerate(headers):
        values = [str(header or "")]
        for row in rows:
            if isinstance(row, list) and index < len(row):
                values.append(str(row[index] or ""))
        longest = max((len(value) for value in values), default=1)
        weights.append(max(8, min(34, longest)))
    total = sum(weights) or 1
    return [(weight / total) * 100 for weight in weights]


def _section_has_content(section: dict[str, Any]) -> bool:
    if str(section.get("kind", "")) == "tree":
        return _tree_record_count(section.get("tree", {})) > 0
    if section.get("rows"):
        return True
    if section.get("items"):
        return True
    return False


def _tree_record_count(tree: Any) -> int:
    if not isinstance(tree, dict):
        return 0
    count = 0
    for key in ("endpoints", "requests"):
        value = tree.get(key)
        if isinstance(value, list):
            count += len([item for item in value if isinstance(item, dict)])
    children = tree.get("children", [])
    if isinstance(children, list):
        count += sum(_tree_record_count(child) for child in children)
    nested = tree.get("tree")
    if isinstance(nested, dict):
        count += _tree_record_count(nested)
    return count


def _headers_for_items(items: list[dict[str, Any]]) -> list[str]:
    keys = []
    for item in items:
        for key in item:
            if key not in keys:
                keys.append(key)
        if len(keys) >= 8:
            break
    return keys


def _rows_for_items(items: list[dict[str, Any]]) -> list[list[Any]]:
    headers = _headers_for_items(items)
    return [[item.get(header, "") for header in headers] for item in items]


def _label(value: Any) -> str:
    text = str(value or "")
    result = []
    for char in text:
        if char.isupper() and result:
            result.append(" ")
        result.append(char)
    return "".join(result).replace("_", " ").strip().title()


def _summary_value(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return "0"
        dict_items = [item for item in value if isinstance(item, dict)]
        if len(dict_items) == len(value):
            for key in ("name", "target", "title"):
                labels = [str(item.get(key, "")).strip() for item in dict_items]
                if all(labels):
                    return _join_limited(labels)
            return f"{len(value)} records"
        if all(_is_scalar(item) for item in value):
            return _join_limited([str(item) for item in value])
        return f"{len(value)} records"
    if isinstance(value, dict):
        if not value:
            return "0"
        if all(_is_scalar(item) for item in value.values()):
            pairs = [f"{_label(key)}: {item}" for key, item in list(value.items())[:8]]
            suffix = f", +{len(value) - 8} more" if len(value) > 8 else ""
            return ", ".join(pairs) + suffix
        return f"{len(value)} fields"
    return str(value)


def _render_toc(items: list[tuple[str, str]]) -> str:
    unique = []
    seen: set[str] = set()
    for anchor, label in items:
        if not anchor or anchor in seen:
            continue
        seen.add(anchor)
        unique.append((anchor, label))
    if len(unique) < 4:
        return ""
    links = "".join(f"<li><a href=\"#{_html(anchor)}\">{_html(label)}</a></li>" for anchor, label in unique)
    return f"<nav class=\"report-toc\" aria-label=\"Table of contents\"><h2>Layer Index</h2><ol>{links}</ol></nav>"


def _section_anchor(section: dict[str, Any]) -> str:
    return _slug("section", section.get("sectionId") or section.get("title") or "section")


def _slug(*parts: Any) -> str:
    text = "-".join(str(part or "") for part in parts)
    slug = "".join(char.lower() if char.isalnum() else "-" for char in text).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "section"


def _html_cell(value: Any, header: Any) -> str:
    rendered = _summary_value(value) if isinstance(value, dict | list) else str("" if value is None else value)
    badge = _badge_class(rendered, header)
    if badge:
        return f"<span class=\"badge {badge}\">{_html(rendered)}</span>"
    return _html(rendered)


def _badge_html(value: Any, header: Any) -> str:
    rendered = str("" if value is None else value)
    badge = _badge_class(rendered, header)
    class_name = f"badge {badge}" if badge else "badge"
    return f'<span class="{_html(class_name)}">{_html(rendered)}</span>'


def _badge_class(value: str, header: Any) -> str:
    header_text = str(header or "").strip().lower()
    if header_text not in {"severity", "priority", "risk", "assessment", "result", "status"}:
        return ""
    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return f"badge-{normalized}"
    if header_text == "status" and normalized == "confirmed":
        return "badge-ok"
    if normalized in {"confirmed_bola", "confirmed_bfla", "confirmed_bopla", "possible_broken_access_control", "broken access"}:
        return "badge-high"
    if normalized in {"candidate", "planned", "inconclusive"}:
        return "badge-medium"
    if normalized in {"enforced", "pass", "ok", "valid"}:
        return "badge-ok"
    return ""


def _is_numeric_summary(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int | float):
        return True
    return isinstance(value, str) and value.strip().isdigit()


def _string_items(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _new_string_items(items: Any, rendered: set[str]) -> list[str]:
    values = []
    for item in _string_items(items):
        if item in rendered:
            continue
        rendered.add(item)
        values.append(item)
    return values


def _join_limited(values: list[str], limit: int = 8) -> str:
    clipped = values[:limit]
    suffix = f", +{len(values) - limit} more" if len(values) > limit else ""
    return ", ".join(clipped) + suffix


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _html(value: Any) -> str:
    return html.escape(str("" if value is None else value), quote=True)


def _md(value: Any) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ").strip()
