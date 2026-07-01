# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from ..errors import McpError
from .models import TemplateMetadata


BUILTIN_TEMPLATES: dict[str, TemplateMetadata] = {
    "standard_markdown_report": TemplateMetadata(
        template_id="standard_markdown_report",
        name="Standard Markdown Report",
        context_type="report",
        description="Full workspace report with summary, scope, coverage, findings, and evidence index.",
    ),
    "assessment_summary_report": TemplateMetadata(
        template_id="assessment_summary_report",
        name="Assessment Summary Report",
        context_type="report",
        description="Workspace assessment summary with actions, technologies, findings, and pending observations.",
    ),
    "standard_finding": TemplateMetadata(
        template_id="standard_finding",
        name="Standard Finding Draft",
        context_type="finding",
        description="Single finding draft with impact, evidence, reproduction steps, and remediation.",
    ),
    "standard_evidence_pack": TemplateMetadata(
        template_id="standard_evidence_pack",
        name="Standard Evidence Pack",
        context_type="evidence_pack",
        description="Evidence pack for internal review, QA, retesting, or handover.",
    ),
    "standard_coverage": TemplateMetadata(
        template_id="standard_coverage",
        name="Standard Coverage Summary",
        context_type="coverage",
        description="Coverage summary with targets, adapter usage, active actions, and follow-up areas.",
    ),
    "standard_layer_report": TemplateMetadata(
        template_id="standard_layer_report",
        name="Standard Layer Report",
        context_type="layer_report",
        format="html",
        description="Normalized HTML report for one passive workspace layer such as perimeter, JS, auth, or access control.",
    ),
    "standard_workspace_report": TemplateMetadata(
        template_id="standard_workspace_report",
        name="Standard Workspace Report",
        context_type="workspace_report",
        format="html",
        description="Normalized HTML report combining all selected passive workspace layers.",
    ),
}


def list_templates(args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    context_type = str(args.get("contextType", "") or "")
    templates = [
        item.as_dict()
        for item in BUILTIN_TEMPLATES.values()
        if not context_type or item.context_type == context_type
    ]
    return {"templates": templates}


def template_for(template_id: str) -> TemplateMetadata:
    try:
        return BUILTIN_TEMPLATES[template_id]
    except KeyError as exc:
        raise McpError(-32602, f"Unknown documentation template: {template_id}") from exc
