# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


RedactionMode = Literal["safe", "high_level", "internal", "raw"]
ContextType = Literal["report", "finding", "evidence_pack", "coverage", "layer_report", "workspace_report"]


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


class DocumentationModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)


class RedactionPolicy(DocumentationModel):
    mode: RedactionMode = "high_level"
    include_raw_http: bool = False
    include_request_bodies: bool = False
    include_response_bodies: bool = False
    include_credentials: bool = False
    include_approval_metadata: bool = True
    include_hashes: bool = True


class TemplateMetadata(DocumentationModel):
    template_id: str
    name: str
    context_type: ContextType
    format: str = "markdown"
    description: str
    built_in: bool = True


class RenderResult(DocumentationModel):
    template_id: str
    context_type: ContextType
    format: str
    content: str
    path: str | None = None
    bytes: int = 0


class CoverageSummary(DocumentationModel):
    workspace_id: str
    targets_in_scope: list[str] = Field(default_factory=list)
    targets_with_workspace_state: list[str] = Field(default_factory=list)
    targets_with_traffic: list[str] = Field(default_factory=list)
    targets_scanned: list[str] = Field(default_factory=list)
    adapters_used: list[str] = Field(default_factory=list)
    passive_only_modules: list[str] = Field(default_factory=list)
    active_modules: list[str] = Field(default_factory=list)
    actions_performed: list[dict[str, Any]] = Field(default_factory=list)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    untested_areas: list[str] = Field(default_factory=list)
    actions_requiring_follow_up: list[str] = Field(default_factory=list)


class FindingDraftContext(DocumentationModel):
    workspace_id: str
    target: str
    finding: dict[str, Any]
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)


class EvidencePackContext(DocumentationModel):
    workspace_id: str
    target: str
    finding: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    scope_status: dict[str, Any] = Field(default_factory=dict)
    policy: RedactionPolicy = Field(default_factory=RedactionPolicy)


class ReportContext(DocumentationModel):
    workspace_id: str
    project: dict[str, Any]
    scope: dict[str, Any]
    executive_summary: dict[str, Any]
    coverage: dict[str, Any]
    targets: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    appendices: list[dict[str, Any]] = Field(default_factory=list)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)


class LayerReportSection(DocumentationModel):
    section_id: str
    title: str
    kind: str = "table"
    summary: str = ""
    headers: list[str] = Field(default_factory=list)
    rows: list[list[Any]] = Field(default_factory=list)
    items: list[dict[str, Any]] = Field(default_factory=list)
    tree: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LayerTargetContext(DocumentationModel):
    target: str
    summary: dict[str, Any] = Field(default_factory=dict)
    sections: list[LayerReportSection] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)


class LayerReportContext(DocumentationModel):
    workspace_id: str
    layer: str
    title: str
    generated_at: str
    summary: dict[str, Any] = Field(default_factory=dict)
    targets: list[LayerTargetContext] = Field(default_factory=list)
    sections: list[LayerReportSection] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)


class WorkspaceReportContext(DocumentationModel):
    workspace_id: str
    title: str
    generated_at: str
    layers: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    gaps: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    redaction: RedactionPolicy = Field(default_factory=RedactionPolicy)
