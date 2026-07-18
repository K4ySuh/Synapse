# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Documentation context builders, renderers, and exporters."""

from .builder import (
    build_evidence_pack,
    build_finding_context,
    build_finding_draft,
    build_report_context,
    summarize_coverage,
)
from .batching import plan_scope_groups, prepare_validation_batch, render_workspace_report_batches
from .exporters import (
    build_layer_report_context,
    build_workspace_report_context,
    export_json,
    render_assessment_summary,
    render_layer_report,
    render_markdown,
    render_workspace_report,
)
from .layers import list_layers
from .templates import list_templates

__all__ = [
    "build_evidence_pack",
    "build_finding_context",
    "build_finding_draft",
    "build_layer_report_context",
    "build_report_context",
    "build_workspace_report_context",
    "export_json",
    "list_layers",
    "list_templates",
    "plan_scope_groups",
    "prepare_validation_batch",
    "render_layer_report",
    "render_markdown",
    "render_assessment_summary",
    "render_workspace_report",
    "render_workspace_report_batches",
    "summarize_coverage",
]
