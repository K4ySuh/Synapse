# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from .models import RiskTier, to_camel
from ..url_hygiene import canonical_url_identity, normalize_parameter_name, redact_url_query_values


Confidence = Literal["low", "medium", "high"]
Priority = Literal["info", "low", "medium", "high", "critical"]
SophisticationTier = Literal["low", "medium", "high"]
PretextStatus = Literal["draft", "approved"]
AdapterMode = Literal[
    "passive_analysis",
    "test_planning",
    "active_testing",
    "command_building",
    "result_ingestion",
]


class WorkspaceModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="allow")

    def as_dict(self, *, by_alias: bool = True, exclude_none: bool = True) -> dict[str, Any]:
        return self.model_dump(by_alias=by_alias, exclude_none=exclude_none)


class ServiceEntity(WorkspaceModel):
    type: str = "service"
    host: str = ""
    address: str = ""
    port: int | None = None
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    source: str = ""


class EndpointEntity(WorkspaceModel):
    type: str = "endpoint"
    url: str
    method: str = "GET"
    host: str = ""
    path: str = ""
    query_parameters: list[str] = Field(default_factory=list)
    source: str = ""


class ParameterEntity(WorkspaceModel):
    type: str = "parameter"
    name: str
    location: str = "query"
    method: str = "GET"
    url: str = ""
    path: str = ""
    input_type: str = ""
    value_preview: str = ""


class ObservationEntity(WorkspaceModel):
    type: str
    value: Any = ""
    confidence: Confidence = "low"
    priority: Priority = "low"
    priority_score: int = 0
    reason: str = ""
    reasons: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class FindingEntity(WorkspaceModel):
    type: str = "finding"
    id: str = ""
    key: str = ""
    title: str
    status: str = "candidate"
    severity: RiskTier = "info"
    confidence: Confidence = "low"
    description: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    operator_reviewed: bool = False


class PretextCandidateEntity(WorkspaceModel):
    type: Literal["pretext_candidate"] = "pretext_candidate"
    subject: str
    sender_persona: str
    body_template: str
    sophistication_tier: SophisticationTier
    source_observation_refs: list[str] = Field(default_factory=list)
    status: PretextStatus = "draft"


class ActionEntity(WorkspaceModel):
    type: str = "action"
    action_id: str = ""
    key: str = ""
    tool: str = ""
    target: str = ""
    summary: str = ""
    risk_tier: RiskTier = "low"
    requires_confirmation: bool = False
    mitre_technique_id: str | None = None


class DetectionGapFindingEntity(WorkspaceModel):
    type: Literal["detection_gap"] = "detection_gap"
    key: str = ""
    action_ref: str
    mitre_technique_id: str
    detected: bool | None = None
    criticality: RiskTier
    expected_detection_sources: list[str] = Field(default_factory=list)
    notes: str = ""


class WorkspaceEntityBundle(WorkspaceModel):
    services: list[ServiceEntity | dict[str, Any]] = Field(default_factory=list)
    endpoints: list[EndpointEntity | dict[str, Any]] = Field(default_factory=list)
    parameters: list[ParameterEntity | dict[str, Any]] = Field(default_factory=list)
    findings: list[FindingEntity | dict[str, Any]] = Field(default_factory=list)
    actions: list[ActionEntity | dict[str, Any]] = Field(default_factory=list)
    observations: list[ObservationEntity | dict[str, Any]] = Field(default_factory=list)
    pretext_candidates: list[PretextCandidateEntity | dict[str, Any]] = Field(default_factory=list)
    detection_gaps: list[DetectionGapFindingEntity | dict[str, Any]] = Field(default_factory=list)

    def as_ingest_entities(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "services": _dump_entity_list(self.services),
            "endpoints": _dump_entity_list(self.endpoints),
            "parameters": _dump_entity_list(self.parameters),
            "findings": _dump_entity_list(self.findings),
            "actions": _dump_entity_list(self.actions),
            "observations": _dump_entity_list(self.observations),
            "pretextCandidates": _dump_entity_list(self.pretext_candidates),
            "detectionGaps": _dump_entity_list(self.detection_gaps),
        }


class EvidenceReference(WorkspaceModel):
    evidence_id: str = ""
    source: str = ""
    path: str = ""
    description: str = ""


class RecommendedTest(WorkspaceModel):
    name: str
    description: str
    sends_traffic: bool
    requires_confirmation: bool
    risk_tier: RiskTier = "low"
    payload_strategy: str = ""
    notes: list[str] = Field(default_factory=list)


class AdapterResult(WorkspaceModel):
    adapter: str
    mode: AdapterMode
    summary: str
    workspace_id: str | None = None
    target: str | None = None
    entities: WorkspaceEntityBundle = Field(default_factory=WorkspaceEntityBundle)
    recommended_tests: list[RecommendedTest | dict[str, Any]] = Field(default_factory=list)
    evidence: list[EvidenceReference | dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def as_ingest_payload(self) -> dict[str, Any]:
        payload = self.as_dict()
        payload["entities"] = self.entities.as_ingest_entities()
        return payload


class ContributionProducer(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    version: str = Field(min_length=1, max_length=40)
    model_config = ConfigDict(strict=True, extra="forbid")


class ContributionEndpoint(EndpointEntity):
    """The initially supported endpoint fields; no caller-authored review state."""

    type: Literal["endpoint"] = "endpoint"
    url: str = Field(min_length=1, max_length=2048)
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    model_config = ConfigDict(strict=True, extra="forbid", alias_generator=to_camel, populate_by_name=True)


class ContributionObservation(ObservationEntity):
    type: str = Field(min_length=1, max_length=80)
    value: JsonValue
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    model_config = ConfigDict(strict=True, extra="forbid", alias_generator=to_camel, populate_by_name=True)


class ContributionEntities(BaseModel):
    endpoints: list[ContributionEndpoint] = Field(default_factory=list, max_length=100)
    observations: list[ContributionObservation] = Field(default_factory=list, max_length=100)
    model_config = ConfigDict(strict=True, extra="forbid")


class ContributionEnvelope(BaseModel):
    """Version 1.0 saved-data contribution carried by workspace.ingest_data."""

    schema_version: Literal["1.0"]
    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    producer: ContributionProducer
    source_timestamp: str | None = Field(default=None, max_length=40)
    entities: ContributionEntities
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    artifact_refs: list[str] = Field(default_factory=list, max_length=32)
    model_config = ConfigDict(strict=True, extra="forbid", alias_generator=to_camel, populate_by_name=True)

    @field_validator("source_timestamp")
    @classmethod
    def timestamp_has_timezone(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("sourceTimestamp must be an ISO 8601 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("sourceTimestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def require_entities(self) -> "ContributionEnvelope":
        if not self.entities.endpoints and not self.entities.observations:
            raise ValueError("entities must contain at least one endpoint or observation")
        if len(self.entities.endpoints) + len(self.entities.observations) > 100:
            raise ValueError("entities may contain at most 100 total records")
        return self


class ContributionReceipt(BaseModel):
    schema_version: Literal["1.0"]
    submission_id: str
    workspace_id: str
    target: str
    request_id: str
    producer: ContributionProducer
    consumer_ref: str
    canonical_record_ids: dict[str, list[str]]
    evidence_ids: list[str]
    artifact_ids: list[str]
    inserted_counts: dict[str, int]
    updated_counts: dict[str, int]
    validation_diagnostics: list[dict[str, JsonValue]]
    committed_revision: int
    model_config = ConfigDict(strict=True, extra="forbid", alias_generator=to_camel, populate_by_name=True)


def candidate_observation(
    *,
    candidate_type: str,
    value: Any,
    reason: str,
    parameter: str = "",
    method: str = "",
    location: str = "",
    url: str = "",
    confidence: Confidence = "low",
    priority: Priority = "low",
    priority_score: int = 0,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ObservationEntity:
    payload: dict[str, Any] = {
        "type": candidate_type,
        "value": value,
        "confidence": confidence,
        "priority": priority,
        "priority_score": priority_score,
        "reason": reason,
        "reasons": [reason] if reason else [],
        "tags": tags or [],
        # Every candidate joins the common validation lifecycle at "proposed"; the
        # workspace validation call moves it to confirmed/refuted/inconclusive.
        "validation_status": "proposed",
    }
    if parameter:
        payload["parameter"] = parameter
    if method:
        payload["method"] = method.upper()
    if location:
        payload["location"] = location
    if url:
        payload["url"] = url
    if metadata:
        payload.update(metadata)
    return ObservationEntity(**payload)


def passive_finding(
    *,
    key: str,
    title: str,
    severity: RiskTier,
    reason: str,
    host: str,
    affected_urls: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    confidence: Confidence = "high",
    impact: str = "",
    remediation: str = "",
    tags: list[str] | None = None,
    category: str = "",
) -> dict[str, Any]:
    """Build a passively-verified finding (not a test candidate).

    For issues that are determinable from data already in the workspace — missing
    security headers, insecure cookie flags, weak TLS posture — where active testing
    is not required to confirm them. Emitted as a confirmed but not-yet-operator-reviewed
    finding, deduped by a stable ``key`` and collapsing affected URLs into ``affectedUrls``.
    """
    finding: dict[str, Any] = {
        "type": "finding",
        "key": key,
        "title": title,
        "status": "confirmed",
        "severity": severity,
        "confidence": confidence,
        "operatorReviewed": False,
        "description": reason,
        "reasons": [reason] if reason else [],
        "affectedAssets": [host] if host else [],
        "affectedUrls": sorted({str(url) for url in (affected_urls or []) if url}),
        "evidenceIds": [eid for eid in (evidence_ids or []) if isinstance(eid, str)],
        "impact": impact,
        "remediation": remediation,
        "tags": tags or [],
    }
    if category:
        finding["category"] = category
    return finding


def _surface_slug(value: Any) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip().lower()).strip("-")
    return slug or "candidate"


def surface_candidate_id(method: str, url: str, location: str, parameter: str) -> str:
    identity = canonical_url_identity(url) or redact_url_query_values(url) or str(url)
    return f"tc_{_surface_slug(method)}_{_surface_slug(identity)}_{_surface_slug(location)}_{_surface_slug(normalize_parameter_name(parameter))}"[:170]


def surface_candidate(
    *,
    vuln_class: str,
    url: str,
    reason: str,
    method: str = "GET",
    parameter: str = "",
    location: str = "query",
    priority: Priority = "low",
    priority_score: int = 0,
    confidence: Confidence = "low",
    test_plan_summary: str = "",
    subtype: str = "",
    tags: list[str] | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Build one consolidated ``test_candidate`` observation for an injectable surface.

    Different injection adapters that flag the SAME (method, url, parameter, location) produce
    the SAME ``candidateId``, so ingestion merges them into a single observation whose
    ``candidateFor`` unions the vuln classes and whose ``candidateDetails`` keeps per-class
    context — replacing one separate ``*_candidate`` observation per adapter and collapsing
    duplicate stored evidence. Returned as a plain dict (camelCase), like ``passive_finding``.
    """
    method = (method or "GET").upper()
    url = redact_url_query_values(url) or url
    parameter = normalize_parameter_name(parameter)
    score = int(priority_score or 0)
    prefixed_reason = f"[{vuln_class}] {reason}" if reason else ""
    detail: dict[str, Any] = {
        "reasons": [reason] if reason else [],
        "priority": priority,
        "priorityScore": score,
        "confidence": confidence,
        "validationStatus": "proposed",
    }
    if test_plan_summary:
        detail["testPlanSummary"] = test_plan_summary
    if subtype:
        detail["subtype"] = subtype
    return {
        "type": "test_candidate",
        "candidateId": surface_candidate_id(method, url, location, parameter),
        "value": url,
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "candidateFor": [vuln_class],
        "candidateDetails": {vuln_class: detail},
        "priority": priority,
        "priorityScore": score,
        "confidence": confidence,
        "reason": prefixed_reason,
        "reasons": [prefixed_reason] if prefixed_reason else [],
        "tags": list(tags or []) + ["test-candidate", vuln_class],
        "evidenceIds": [eid for eid in (evidence_ids or []) if isinstance(eid, str)],
    }


def _dump_entity_list(items: list[Any]) -> list[dict[str, Any]]:
    dumped = []
    for item in items:
        if isinstance(item, WorkspaceModel):
            dumped.append(item.as_dict())
        elif isinstance(item, BaseModel):
            dumped.append(item.model_dump(by_alias=True, exclude_none=True))
        elif isinstance(item, dict):
            dumped.append(dict(item))
    return dumped
