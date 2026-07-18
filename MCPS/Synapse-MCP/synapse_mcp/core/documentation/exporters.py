# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import evidence, workspace
from ..errors import McpError
from . import builder
from . import layers
from .layer_renderer import render_layer_report as render_layer_content
from .layer_renderer import render_workspace_report as render_workspace_content
from .renderer import render
from .templates import template_for


def render_markdown(args: dict[str, Any]) -> dict[str, Any]:
    template_id = args.get("template", args.get("templateId", "standard_markdown_report"))
    context = _context_from_args(args, default_template=template_id)
    result = render(template_id, context).as_dict()
    path = _write_output(args, result["content"], "md", _default_markdown_name(template_id))
    result["path"] = str(path)
    result.update(_context_presentation_metadata(context))
    return result


def render_assessment_summary(args: dict[str, Any]) -> dict[str, Any]:
    args = {**args, "contextType": args.get("contextType", "report")}
    template_id = args.get("template", args.get("templateId", "assessment_summary_report"))
    context = _context_from_args(args, default_template=template_id)
    result = render(template_id, context).as_dict()
    path = _write_output(args, result["content"], "md", "assessment-summary.md")
    result["path"] = str(path)
    result.update(_context_presentation_metadata(context))
    return result


def build_layer_report_context(args: dict[str, Any]) -> dict[str, Any]:
    return layers.build_layer_report_context(args)


def build_workspace_report_context(args: dict[str, Any]) -> dict[str, Any]:
    return layers.build_workspace_report_context(args)


def render_layer_report(args: dict[str, Any]) -> dict[str, Any]:
    context = layers.build_layer_report_context(args)
    payload = context["layerReport"]
    format_name = str(args.get("format") or "html").lower()
    if format_name not in {"html", "markdown"}:
        raise McpError(-32602, "format must be html or markdown.")
    content = render_layer_content(payload, format_name)
    extension = "html" if format_name == "html" else "md"
    default_name = f"{workspace.slug(str(payload.get('layer') or 'layer'))}-report.{extension}"
    path = _write_output(args, content, extension, default_name)
    evidence.log_event(
        "documentation.render_layer_report",
        f"Rendered {payload.get('layer', 'layer')} report for workspace {args.get('workspaceId', '')}.",
        {
            "workspaceId": args.get("workspaceId", ""),
            "layer": payload.get("layer", ""),
            "format": format_name,
            "path": str(path),
            **_presentation_metadata(payload),
        },
    )
    return {
        "contextType": "layer_report",
        "workspaceId": payload.get("workspaceId", ""),
        "layer": payload.get("layer", ""),
        "format": format_name,
        "path": str(path),
        "bytes": len(content.encode("utf-8")),
        "summary": payload.get("summary", {}),
        **_presentation_metadata(payload),
    } | ({"content": content} if args.get("returnContent") is True else {})


def render_workspace_report(args: dict[str, Any]) -> dict[str, Any]:
    context = layers.build_workspace_report_context(args)
    payload = context["workspaceReport"]
    format_name = str(args.get("format") or "html").lower()
    if format_name not in {"html", "markdown"}:
        raise McpError(-32602, "format must be html or markdown.")
    content = render_workspace_content(payload, format_name)
    extension = "html" if format_name == "html" else "md"
    path = _write_output(args, content, extension, f"workspace-report.{extension}")
    evidence.log_event(
        "documentation.render_workspace_report",
        f"Rendered workspace report for {args.get('workspaceId', '')}.",
        {
            "workspaceId": args.get("workspaceId", ""),
            "layers": payload.get("summary", {}).get("layers", []),
            "format": format_name,
            "path": str(path),
            **_presentation_metadata(payload),
        },
    )
    return {
        "contextType": "workspace_report",
        "workspaceId": payload.get("workspaceId", ""),
        "format": format_name,
        "path": str(path),
        "bytes": len(content.encode("utf-8")),
        "summary": payload.get("summary", {}),
        **_presentation_metadata(payload),
    } | ({"content": content} if args.get("returnContent") is True else {})


def export_json(args: dict[str, Any]) -> dict[str, Any]:
    context = _context_from_args(args, default_template=args.get("template", "standard_markdown_report"))
    content = json.dumps(context, indent=2, ensure_ascii=False)
    path = _write_output(args, content, "json", "context.json")
    evidence.log_event(
        "documentation.export_json",
        f"Exported documentation JSON context for workspace {args.get('workspaceId', '')}.",
        {"workspaceId": args.get("workspaceId", ""), "path": str(path), "contextType": context.get("contextType", "")},
    )
    return {"format": "json", "path": str(path), "bytes": len(content.encode("utf-8")), "contextType": context.get("contextType", "")}


def _context_from_args(args: dict[str, Any], *, default_template: str) -> dict[str, Any]:
    if isinstance(args.get("context"), dict):
        return args["context"]
    context_type = str(args.get("contextType", "") or "")
    if not context_type:
        context_type = template_for(default_template).context_type
    if context_type == "report":
        return builder.build_report_context(args)
    if context_type == "finding":
        return builder.build_finding_context(args)
    if context_type == "evidence_pack":
        return builder.build_evidence_pack(args)
    if context_type == "coverage":
        return builder.summarize_coverage(args)
    if context_type == "layer_report":
        return layers.build_layer_report_context(args)
    if context_type == "workspace_report":
        return layers.build_workspace_report_context(args)
    raise McpError(-32602, "contextType must be one of: report, finding, evidence_pack, coverage, layer_report, workspace_report.")


def _write_output(args: dict[str, Any], content: str, extension: str, default_name: str) -> Path:
    path = workspace.resolve_report_output_path(
        args["workspaceId"],
        args.get("outputPath", ""),
        extension=extension,
        default_name=default_name,
        allow_external=args.get("allowExternalOutput") is True,
        artifact="documentation",
    )
    path.write_text(content, encoding="utf-8")
    return path


def _default_markdown_name(template_id: str) -> str:
    if template_id == "assessment_summary_report":
        return "assessment-summary.md"
    return "report.md"


def _presentation_metadata(payload: dict[str, Any]) -> dict[str, str]:
    redaction = payload.get("redaction") if isinstance(payload.get("redaction"), dict) else {}
    if not redaction and isinstance(payload.get("policy"), dict):
        redaction = payload["policy"]
    policy_mode = str(redaction.get("mode", "high_level") or "high_level")
    presentation = str(redaction.get("presentation", "") or "")
    if not presentation:
        presentation = {"safe": "high_level", "high_level": "high_level", "internal": "operator", "raw": "operator_raw"}.get(
            policy_mode,
            "high_level",
        )
    return {"presentation": presentation, "redactionPolicy": policy_mode}


def _context_presentation_metadata(context: dict[str, Any]) -> dict[str, str]:
    for key in ("report", "workspaceReport", "layerReport", "evidencePack", "findingContext"):
        payload = context.get(key)
        if isinstance(payload, dict):
            return _presentation_metadata(payload)
    return _presentation_metadata(context)
