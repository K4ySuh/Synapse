# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Revision-aware, deterministic, budgeted application context compilation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from hashlib import sha256
import ipaddress
import json
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from synapse_mcp.state.contracts import ContextRepositorySnapshot, WorkspaceRepository


COUNTER_ID = "utf8_bytes_v1"
_TERMINAL_TASK_STATES = frozenset({"completed", "failed", "cancelled", "succeeded", "unknown"})
_SEVERITY_PRIORITY = {"critical": 100, "high": 80, "medium": 60, "low": 40, "info": 20}
_SECTION_ORDER = (
    "workItems",
    "confirmedFacts",
    "coverageGaps",
    "activeTasks",
    "recentActions",
    "candidates",
    "recommendations",
    "resourceLinks",
)


def _camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


class ContextModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        populate_by_name=True,
        alias_generator=_camel_case,
    )


class ContextQueryInput(ContextModel):
    workspace_id: str = Field(min_length=1)
    intent: str | None = None
    targets: list[str] = Field(default_factory=list)
    entity_types: list[str] = Field(default_factory=list)
    since_revision: int | None = Field(default=None, ge=0)
    max_tokens: int = Field(default=1500, ge=100)
    include_evidence_summaries: bool = False
    target: str | None = Field(default=None, description="Deprecated alias for targets.")
    purpose: str | None = Field(default=None, description="Deprecated alias for intent.")
    work_item_id: str | None = Field(default=None, min_length=1)
    claim_id: str | None = Field(default=None, min_length=1)
    claimant: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def normalize_aliases(self) -> "ContextQueryInput":
        if self.claim_id and not self.work_item_id:
            raise ValueError("claimId requires workItemId")
        intent = str(self.intent or self.purpose or "next_step_planning").strip()
        if not intent:
            raise ValueError("intent must not be empty")
        targets = [str(item).strip() for item in self.targets if str(item).strip()]
        if self.target and self.target.strip():
            targets.append(self.target.strip())
        entity_types = [str(item).strip() for item in self.entity_types if str(item).strip()]
        object.__setattr__(self, "intent", intent)
        object.__setattr__(self, "targets", list(dict.fromkeys(targets)))
        object.__setattr__(self, "entity_types", list(dict.fromkeys(entity_types)))
        return self


class ContextBudget(ContextModel):
    requested: int
    used: int
    counter: Literal["utf8_bytes_v1"] = COUNTER_ID
    status: Literal["complete", "truncated", "budget_too_small"]
    minimum_required: int


class ScopeTargetStatus(ContextModel):
    target: str
    status: Literal["in_scope", "out_of_scope", "scope_unset"]
    reason: str


class ScopeSafety(ContextModel):
    status: Literal["in_scope", "partially_in_scope", "out_of_scope", "scope_unset", "no_targets"]
    reason: str
    authorized_hosts: list[str]
    authorized_patterns: list[str]
    authorized_cidrs: list[str]
    targets: list[ScopeTargetStatus]


class AuthoritySafety(ContextModel):
    profile: str
    status: Literal[
        "legacy_profile",
        "observe_only",
        "grant_not_selected",
        "grant_not_found",
        "active",
        "revoked",
    ]
    grant_selected: bool
    grant_state: str
    grant_revision: int | None = None
    expires_at: str | None = None


class ContradictionSafety(ContextModel):
    count: int
    protected: Literal[True] = True


class ContextSafety(ContextModel):
    scope: ScopeSafety
    authority: AuthoritySafety
    contradictions: ContradictionSafety


class ContextItem(ContextModel):
    item_id: str
    kind: str
    target: str | None = None
    summary: str
    lifecycle: str
    confidence: str | None = None
    priority: int
    evidence_references: list[str] = Field(default_factory=list)
    changed_revision: int
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class ContextWarning(ContextModel):
    warning_id: str
    code: str
    summary: str
    target: str | None = None
    source: str
    changed_revision: int


class ContextRecommendation(ContextModel):
    recommendation_id: str
    summary: str
    rationale: str
    source_references: list[str]
    priority: int


class ContextResourceLink(ContextModel):
    reference: str
    artifact_type: str
    media_type: str
    version: str
    size: int = Field(ge=0)
    evidence_reference: str
    summary: str | None = None


class ContextOmission(ContextModel):
    section: str
    reason: Literal["budget_exhausted", "change_log_pruned"]
    count: int = Field(ge=1)
    continuation: str


class ContextQueryResult(ContextModel):
    workspace_id: str
    revision: int
    base_revision: int | None = None
    intent: str
    targets: list[str]
    budget: ContextBudget
    safety: ContextSafety
    confirmed_facts: list[ContextItem]
    candidates: list[ContextItem]
    contradictions: list[ContextWarning]
    coverage_gaps: list[ContextItem]
    recent_actions: list[ContextItem]
    active_tasks: list[ContextItem]
    work_items: list[ContextItem]
    recommendations: list[ContextRecommendation]
    resource_links: list[ContextResourceLink]
    omissions: list[ContextOmission]
    full_refresh_required: bool


class ContextQueryError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ContextCounter(Protocol):
    identity: str

    def __call__(self, payload: bytes) -> int: ...


class Utf8ByteCounter:
    identity = COUNTER_ID

    def __call__(self, payload: bytes) -> int:
        return len(payload)


@dataclass(frozen=True, slots=True)
class ContextTrust:
    execution_profile: str
    selected_grant_id: str = ""
    principal_id: str = ""
    authority_session_id: str = ""


def context_artifact_reference(workspace_id: str, artifact_id: str, trust: ContextTrust) -> str:
    principal = sha256(trust.principal_id.encode("utf-8")).hexdigest()
    authority = sha256(trust.authority_session_id.encode("utf-8")).hexdigest()
    return f"context-artifact:{workspace_id}:{artifact_id}:{principal}:{authority}"


def canonical_context_bytes(result: ContextQueryResult) -> bytes:
    return json.dumps(
        result.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _target_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or value).strip().lower().rstrip(".")


def _scope_match(target: str, scope: Mapping[str, Any]) -> tuple[str, str]:
    host = _target_host(target)
    hosts = {str(item).lower().rstrip(".") for item in scope.get("hosts", []) if str(item).strip()}
    patterns = [str(item).lower().rstrip(".") for item in scope.get("patterns", []) if str(item).strip()]
    cidrs = [str(item) for item in scope.get("cidrs", []) if str(item).strip()]
    if not hosts and not patterns and not cidrs:
        return "scope_unset", "No workspace scope snapshot is configured."
    if host in hosts:
        return "in_scope", "Target matches an exact authorized host."
    if any(fnmatch(host, pattern) for pattern in patterns):
        return "in_scope", "Target matches an authorized host pattern."
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        for cidr in cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return "in_scope", "Target belongs to an authorized CIDR."
            except ValueError:
                continue
    return "out_of_scope", "Target does not match the committed workspace scope snapshot."


def _payload(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("payload")
    return value if isinstance(value, Mapping) else {}


def _evidence_refs(payload: Mapping[str, Any]) -> list[str]:
    values = payload.get("evidenceIds")
    return sorted({str(item) for item in values if str(item).strip()}) if isinstance(values, list) else []


def _summary(payload: Mapping[str, Any], fallback: str) -> str:
    for key in ("title", "summary", "name", "url", "path", "key", "id", "entityId"):
        if payload.get(key) not in (None, ""):
            return str(payload[key])
    return fallback


def _attributes(payload: Mapping[str, Any]) -> dict[str, JsonValue]:
    names = (
        "method",
        "url",
        "path",
        "port",
        "protocol",
        "name",
        "product",
        "version",
        "status",
        "severity",
        "operatorReviewed",
        "analysisEligible",
        "isReportable",
    )
    return {
        name: value
        for name in names
        if (value := payload.get(name)) is None or isinstance(value, (str, int, float, bool, list, dict))
        if name in payload
    }


def _priority(payload: Mapping[str, Any]) -> int:
    try:
        explicit = int(payload.get("priorityScore") or 0)
    except (TypeError, ValueError):
        explicit = 0
    severity = _SEVERITY_PRIORITY.get(str(payload.get("severity") or "").lower(), 0)
    return max(explicit, severity)


def _item_sort(item: ContextItem) -> tuple[int, str]:
    return (-item.priority, item.item_id)


def _recommendation_sort(item: ContextRecommendation) -> tuple[int, str]:
    return (-item.priority, item.recommendation_id)


class ContextCompiler:
    """Compile exact repository truth into a closed, bounded context result."""

    def __init__(
        self,
        repository: WorkspaceRepository,
        *,
        payload_encoder: Callable[[ContextQueryResult], bytes],
        counter: ContextCounter | None = None,
    ) -> None:
        self.repository = repository
        self.counter = counter or Utf8ByteCounter()
        self.payload_encoder = payload_encoder
        if self.counter.identity != COUNTER_ID:
            raise ValueError("The Phase 4 compiler currently publishes utf8_bytes_v1 accounting.")

    def compile(self, query: ContextQueryInput, *, trust: ContextTrust) -> ContextQueryResult:
        if query.workspace_id != self.repository.workspace_id:
            raise ContextQueryError("context_workspace_mismatch", "Context query workspace does not match its repository.")
        snapshot = self.repository.context_snapshot(since_revision=query.since_revision)
        if query.since_revision is not None and query.since_revision > snapshot.revision:
            raise ContextQueryError(
                "context_revision_future",
                f"sinceRevision {query.since_revision} is newer than committed revision {snapshot.revision}.",
            )
        pruned = self._cursor_pruned(snapshot, query.since_revision)
        target_names, target_ids = self._targets(snapshot, query.targets)
        scope_safety, scope_warnings = self._scope_safety(snapshot, target_names)
        authority_safety = self._authority_safety(snapshot, trust)
        stored_warnings = self._contradictions(
            snapshot,
            target_ids,
            authority_safety,
        )
        contradictions = sorted(
            {item.warning_id: item for item in (*scope_warnings, *stored_warnings)}.values(),
            key=lambda item: item.warning_id,
        )
        safety = ContextSafety(
            scope=scope_safety,
            authority=authority_safety,
            contradictions=ContradictionSafety(count=len(contradictions)),
        )
        sections = {name: [] for name in _SECTION_ORDER}
        if not pruned:
            sections = self._sections(snapshot, query, target_ids, target_names, trust)
        extra_omissions = (
            [
                ContextOmission(
                    section="delta",
                    reason="change_log_pruned",
                    count=max(snapshot.revision - int(query.since_revision or 0), 1),
                    continuation="Retry context.query without sinceRevision to request a full refresh.",
                )
            ]
            if pruned
            else []
        )
        return self._pack(
            snapshot=snapshot,
            query=query,
            targets=target_names,
            safety=safety,
            contradictions=contradictions,
            sections=sections,
            full_refresh_required=pruned,
            extra_omissions=extra_omissions,
        )

    @staticmethod
    def _cursor_pruned(snapshot: ContextRepositorySnapshot, since_revision: int | None) -> bool:
        if since_revision is None:
            return False
        if snapshot.store_version != "sqlite-v2":
            return True
        if since_revision >= snapshot.revision:
            return False
        earliest = snapshot.earliest_change_revision
        return earliest is None or earliest > since_revision + 1

    @staticmethod
    def _targets(
        snapshot: ContextRepositorySnapshot,
        requested: Sequence[str],
    ) -> tuple[list[str], set[str]]:
        by_name = {str(item.get("naturalKey") or ""): str(item.get("targetId") or "") for item in snapshot.targets}
        if requested:
            names = sorted(dict.fromkeys(str(item) for item in requested))
        else:
            names = sorted(name for name in by_name if name)
        ids = {by_name[name] for name in names if name in by_name and by_name[name]}
        return names, ids

    @staticmethod
    def _scope_safety(
        snapshot: ContextRepositorySnapshot,
        targets: Sequence[str],
    ) -> tuple[ScopeSafety, list[ContextWarning]]:
        scope = snapshot.scope
        statuses = []
        warnings = []
        for target in targets:
            status, reason = _scope_match(target, scope)
            statuses.append(ScopeTargetStatus(target=target, status=status, reason=reason))
            if status != "in_scope":
                warnings.append(
                    ContextWarning(
                        warning_id=f"scope:{target}",
                        code="target_scope_unset" if status == "scope_unset" else "target_out_of_scope",
                        summary=reason,
                        target=target,
                        source="current_scope",
                        changed_revision=snapshot.revision,
                    )
                )
        values = {item.status for item in statuses}
        if not statuses:
            status = "no_targets"
            reason = "No target filter was supplied and the workspace has no targets."
        elif values == {"in_scope"}:
            status = "in_scope"
            reason = "Every selected target is in the committed workspace scope."
        elif values == {"scope_unset"}:
            status = "scope_unset"
            reason = "Workspace scope is not configured."
        elif "in_scope" in values:
            status = "partially_in_scope"
            reason = "Only part of the selected target set is currently in scope."
        else:
            status = "out_of_scope"
            reason = "No selected target is currently in scope."
        return (
            ScopeSafety(
                status=status,
                reason=reason,
                authorized_hosts=sorted(str(item) for item in scope.get("hosts", []) if str(item).strip()),
                authorized_patterns=sorted(str(item) for item in scope.get("patterns", []) if str(item).strip()),
                authorized_cidrs=sorted(str(item) for item in scope.get("cidrs", []) if str(item).strip()),
                targets=statuses,
            ),
            warnings,
        )

    @staticmethod
    def _authority_safety(snapshot: ContextRepositorySnapshot, trust: ContextTrust) -> AuthoritySafety:
        profile = trust.execution_profile
        if profile == "legacy":
            return AuthoritySafety(profile=profile, status="legacy_profile", grant_selected=False, grant_state="not_applicable")
        if profile == "observe":
            return AuthoritySafety(profile=profile, status="observe_only", grant_selected=False, grant_state="not_applicable")
        if not trust.selected_grant_id:
            return AuthoritySafety(profile=profile, status="grant_not_selected", grant_selected=False, grant_state="missing")
        grants = snapshot.authority.get("grants") if isinstance(snapshot.authority.get("grants"), Mapping) else {}
        entry = grants.get(trust.selected_grant_id)
        if not isinstance(entry, Mapping):
            return AuthoritySafety(profile=profile, status="grant_not_found", grant_selected=True, grant_state="missing")
        revision = int(entry.get("currentRevision") or 0)
        revisions = entry.get("revisions") if isinstance(entry.get("revisions"), Mapping) else {}
        grant = revisions.get(str(revision)) if isinstance(revisions.get(str(revision)), Mapping) else {}
        revoked = bool(grant.get("revokedAt"))
        return AuthoritySafety(
            profile=profile,
            status="revoked" if revoked else "active",
            grant_selected=True,
            grant_state="revoked" if revoked else "active",
            grant_revision=revision or None,
            expires_at=str(grant.get("expiresAt")) if grant.get("expiresAt") else None,
        )

    def _contradictions(
        self,
        snapshot: ContextRepositorySnapshot,
        target_ids: set[str],
        authority: AuthoritySafety,
    ) -> list[ContextWarning]:
        target_names = {str(item.get("targetId") or ""): str(item.get("naturalKey") or "") for item in snapshot.targets}
        warnings = []
        for record in snapshot.entities:
            if str(record.get("targetId") or "") not in target_ids:
                continue
            payload = _payload(record)
            kind = str(payload.get("type") or record.get("entityType") or "").lower()
            target = target_names.get(str(record.get("targetId") or ""))
            identity = str(record.get("entityId") or record.get("naturalKey") or kind)
            if "contradiction" in kind or "conflict" in kind:
                warnings.append(
                    ContextWarning(
                        warning_id=f"stored:{identity}",
                        code="stored_contradiction",
                        summary=_summary(payload, "Stored observations conflict."),
                        target=target,
                        source="stored_observation",
                        changed_revision=int(record.get("updatedRevision") or snapshot.revision),
                    )
                )
            stored_scope = str(payload.get("scopeStatus") or "").lower()
            current_scope, reason = _scope_match(target or "", snapshot.scope)
            if stored_scope in {"in_scope", "allowed", "authorized"} and current_scope != "in_scope":
                warnings.append(
                    ContextWarning(
                        warning_id=f"scope-drift:{identity}",
                        code="scope_observation_stale",
                        summary=reason,
                        target=target,
                        source="scope_contradiction",
                        changed_revision=snapshot.revision,
                    )
                )
            stored_authority = str(payload.get("authorityStatus") or "").lower()
            if stored_authority in {"allow", "allowed", "authorized"} and authority.status != "active":
                warnings.append(
                    ContextWarning(
                        warning_id=f"authority-drift:{identity}",
                        code="authority_observation_stale",
                        summary="Stored authorization evidence is not covered by the currently selected authority state.",
                        target=target,
                        source="authority_contradiction",
                        changed_revision=snapshot.revision,
                    )
                )
        return warnings

    @staticmethod
    def _changed(snapshot: ContextRepositorySnapshot, since_revision: int | None) -> set[str] | None:
        if since_revision is None:
            return None
        return {str(item.get("entityId") or "") for item in snapshot.changes}

    @staticmethod
    def _row_changed(
        record: Mapping[str, Any],
        changed: set[str] | None,
        since_revision: int | None,
    ) -> bool:
        if since_revision is None:
            return True
        identities = {
            str(record.get(name) or "")
            for name in ("targetId", "entityId", "findingId", "relationId", "evidenceId", "artifactId", "actionId", "dispatchId", "taskId", "workItemId")
        }
        return bool((changed or set()) & identities)

    def _sections(
        self,
        snapshot: ContextRepositorySnapshot,
        query: ContextQueryInput,
        target_ids: set[str],
        target_names: Sequence[str],
        trust: ContextTrust,
    ) -> dict[str, list[Any]]:
        target_by_id = {str(item.get("targetId") or ""): str(item.get("naturalKey") or "") for item in snapshot.targets}
        selected_entity_ids = {
            str(item.get("entityId") or "")
            for item in snapshot.entities
            if str(item.get("targetId") or "") in target_ids
        }
        requested_types = {item.lower().removesuffix("s") for item in query.entity_types}
        changed = self._changed(snapshot, query.since_revision)
        facts: list[ContextItem] = []
        candidates: list[ContextItem] = []
        gaps: list[ContextItem] = []
        for target in snapshot.targets:
            if str(target.get("targetId") or "") not in target_ids:
                continue
            if requested_types and "target" not in requested_types:
                continue
            if not self._row_changed(target, changed, query.since_revision):
                continue
            payload = _payload(target)
            facts.append(
                ContextItem(
                    item_id=str(target.get("targetId") or target.get("naturalKey")),
                    kind="target",
                    target=str(target.get("naturalKey") or "") or None,
                    summary=_summary(payload, str(target.get("naturalKey") or "Workspace target")),
                    lifecycle="observed",
                    priority=90,
                    changed_revision=int(target.get("updatedRevision") or snapshot.revision),
                    attributes={"kind": str(target.get("kind") or "host")},
                )
            )
        for record in snapshot.entities:
            if str(record.get("targetId") or "") not in target_ids:
                continue
            payload = _payload(record)
            kind = str(payload.get("type") or record.get("entityType") or "entity")
            normalized_kind = kind.lower().removesuffix("s")
            if requested_types and normalized_kind not in requested_types:
                continue
            if not self._row_changed(record, changed, query.since_revision):
                continue
            lowered = kind.lower()
            if "contradiction" in lowered or "conflict" in lowered:
                continue
            identity = str(record.get("entityId") or record.get("naturalKey") or kind)
            item = ContextItem(
                item_id=identity,
                kind=kind,
                target=target_by_id.get(str(record.get("targetId") or "")) or None,
                summary=_summary(payload, identity),
                lifecycle=str(record.get("lifecycle") or payload.get("status") or "observed"),
                confidence=str(payload.get("confidence")) if payload.get("confidence") else None,
                priority=_priority(payload),
                evidence_references=_evidence_refs(payload),
                changed_revision=int(record.get("updatedRevision") or snapshot.revision),
                attributes=_attributes(payload),
            )
            if "gap" in lowered:
                gaps.append(item)
            elif "candidate" in lowered or payload.get("candidateFor"):
                candidates.append(item)
            else:
                facts.append(item)
        for record in snapshot.findings:
            if str(record.get("targetId") or "") not in target_ids:
                continue
            if requested_types and "finding" not in requested_types:
                continue
            if not self._row_changed(record, changed, query.since_revision):
                continue
            payload = _payload(record)
            identity = str(record.get("findingId") or record.get("naturalKey") or "finding")
            status = str(record.get("status") or payload.get("status") or "candidate")
            item = ContextItem(
                item_id=identity,
                kind="finding",
                target=target_by_id.get(str(record.get("targetId") or "")) or None,
                summary=_summary(payload, identity),
                lifecycle=status,
                confidence=str(payload.get("confidence")) if payload.get("confidence") else None,
                priority=_priority({**payload, "severity": record.get("severity")}),
                evidence_references=_evidence_refs(payload),
                changed_revision=int(record.get("updatedRevision") or snapshot.revision),
                attributes=_attributes({**payload, "status": status, "severity": record.get("severity")}),
            )
            (facts if status == "confirmed" else candidates).append(item)
        for relation in snapshot.relations:
            if not {
                str(relation.get("sourceEntityId") or ""),
                str(relation.get("targetEntityId") or ""),
            } & selected_entity_ids:
                continue
            if requested_types and "relation" not in requested_types:
                continue
            if not self._row_changed(relation, changed, query.since_revision):
                continue
            identity = str(relation.get("relationId") or "relation")
            facts.append(
                ContextItem(
                    item_id=identity,
                    kind="relation",
                    summary=f"{relation.get('sourceEntityId')} {relation.get('relationType')} {relation.get('targetEntityId')}",
                    lifecycle="observed",
                    priority=30,
                    changed_revision=int(relation.get("createdRevision") or snapshot.revision),
                    attributes={"relationType": str(relation.get("relationType") or "related")},
                )
            )
        if query.since_revision is None:
            if target_names and not any(item.kind.lower() == "endpoint" for item in facts):
                gaps.append(
                    ContextItem(
                        item_id="gap:no-endpoints",
                        kind="coverage_gap",
                        summary="No endpoint facts are recorded for the selected targets.",
                        lifecycle="open",
                        priority=70,
                        changed_revision=snapshot.revision,
                    )
                )
            if not snapshot.evidence:
                gaps.append(
                    ContextItem(
                        item_id="gap:no-evidence",
                        kind="coverage_gap",
                        summary="No evidence metadata is recorded in the workspace.",
                        lifecycle="open",
                        priority=60,
                        changed_revision=snapshot.revision,
                    )
                )
        actions = [self._action_item(item, snapshot.revision) for item in (*snapshot.actions, *snapshot.dispatches) if self._row_changed(item, changed, query.since_revision)]
        tasks = [self._task_item(item, snapshot.revision) for item in snapshot.tasks if str(item.get("state") or "").lower() not in _TERMINAL_TASK_STATES and self._row_changed(item, changed, query.since_revision)]
        selected_work_ids: set[str] = set()
        if query.work_item_id:
            selected = next(
                (item for item in snapshot.work_items if str(item.get("workItemId") or "") == query.work_item_id),
                None,
            )
            if selected is not None:
                selected_work_ids.add(query.work_item_id)
                parent = str(selected.get("parentWorkItemId") or "")
                if parent:
                    selected_work_ids.add(parent)
                selected_work_ids.update(
                    str(item.get("workItemId") or "")
                    for item in selected.get("dependencies", [])
                    if isinstance(item, Mapping)
                )
        work_items = []
        if query.work_item_id or query.claimant:
            for item in snapshot.work_items:
                identity = str(item.get("workItemId") or "")
                claims = item.get("claims") if isinstance(item.get("claims"), Sequence) else ()
                claimant_match = bool(
                    query.claimant
                    and any(
                        isinstance(claim, Mapping)
                        and str(claim.get("worker") or "") == query.claimant
                        and str(claim.get("state") or "") == "active"
                        for claim in claims
                    )
                )
                if identity not in selected_work_ids and not claimant_match:
                    continue
                if identity != query.work_item_id and not self._row_changed(item, changed, query.since_revision):
                    continue
                work_items.append(self._work_item(item, snapshot.revision))
        recommendations = [
            ContextRecommendation(
                recommendation_id=f"recommend:{item.item_id}",
                summary=f"Review {item.kind.replace('_', ' ')} context.",
                rationale=item.summary,
                source_references=[item.item_id],
                priority=item.priority,
            )
            for item in (*sorted(gaps, key=_item_sort), *sorted(candidates, key=_item_sort))
        ]
        evidence_by_id = {str(item.get("evidenceId") or ""): item for item in snapshot.evidence}
        resources = []
        for item in snapshot.evidence_artifacts:
            if not self._row_changed(item, changed, query.since_revision):
                continue
            evidence_id = str(item.get("evidenceId") or "")
            evidence = evidence_by_id.get(evidence_id, {})
            if str(evidence.get("targetId") or "") not in target_ids:
                continue
            resources.append(
                ContextResourceLink(
                    reference=context_artifact_reference(
                        snapshot.workspace_id,
                        str(item.get("artifactId") or ""),
                        trust,
                    ),
                    artifact_type="evidence",
                    media_type=str(item.get("mediaType") or "application/octet-stream"),
                    version=str(item.get("digest") or ""),
                    size=int(item.get("size") or 0),
                    evidence_reference=evidence_id,
                    summary=str(evidence.get("summary") or "") if query.include_evidence_summaries else None,
                )
            )
        return {
            "workItems": sorted(work_items, key=_item_sort),
            "confirmedFacts": sorted(facts, key=_item_sort),
            "coverageGaps": sorted(gaps, key=_item_sort),
            "activeTasks": sorted(tasks, key=_item_sort),
            "recentActions": sorted(actions, key=_item_sort),
            "candidates": sorted(candidates, key=_item_sort),
            "recommendations": sorted(recommendations, key=_recommendation_sort),
            "resourceLinks": sorted(resources, key=lambda item: (item.evidence_reference, item.reference)),
        }

    @staticmethod
    def _action_item(record: Mapping[str, Any], revision: int) -> ContextItem:
        payload = _payload(record)
        identity = str(record.get("dispatchId") or record.get("actionId") or "action")
        return ContextItem(
            item_id=identity,
            kind="dispatch" if record.get("dispatchId") else "action",
            target=str(payload.get("target") or "") or None,
            summary=_summary(payload, str(record.get("actionName") or record.get("actionId") or identity)),
            lifecycle=str(record.get("state") or payload.get("status") or "recorded"),
            priority=_priority(payload),
            evidence_references=_evidence_refs(payload),
            changed_revision=int(record.get("updatedRevision") or revision),
            attributes={"state": str(record.get("state") or "recorded")},
        )

    @staticmethod
    def _task_item(record: Mapping[str, Any], revision: int) -> ContextItem:
        payload = _payload(record)
        identity = str(record.get("taskId") or "task")
        return ContextItem(
            item_id=identity,
            kind="task",
            target=str(payload.get("target") or "") or None,
            summary=_summary(payload, str(record.get("actionId") or identity)),
            lifecycle=str(record.get("state") or "unknown"),
            priority=80,
            changed_revision=int(record.get("updatedRevision") or revision),
            attributes={"taskRevision": int(record.get("taskRevision") or 0)},
        )

    @staticmethod
    def _work_item(record: Mapping[str, Any], revision: int) -> ContextItem:
        references = record.get("references") if isinstance(record.get("references"), Sequence) else ()
        evidence_references = [
            str(item.get("id") or "")
            for item in references
            if isinstance(item, Mapping) and str(item.get("type") or "") == "evidence"
        ]
        targets = record.get("targets") if isinstance(record.get("targets"), Sequence) else ()
        return ContextItem(
            item_id=str(record.get("workItemId") or "work-item"),
            kind="work_item",
            target=str(targets[0]) if targets else None,
            summary=str(record.get("objective") or "Operational work item"),
            lifecycle=str(record.get("status") or "planned"),
            priority=100,
            evidence_references=evidence_references,
            changed_revision=int(record.get("currentWorkspaceRevision") or revision),
            attributes={
                "role": str(record.get("role") or ""),
                "parentWorkItemId": record.get("parentWorkItemId"),
                "dependencies": list(record.get("dependencies") or []),
                "requiredPacks": list(record.get("requiredPacks") or []),
                "selectedPacks": list(record.get("selectedPacks") or []),
                "targets": list(targets),
                "contextQuery": dict(record.get("contextQuery") or {}),
                "completionContract": dict(record.get("completionContract") or {}),
                "progressSummary": str(record.get("progressSummary") or ""),
                "resultSummary": str(record.get("resultSummary") or ""),
                "blockerReason": str(record.get("blockerReason") or ""),
                "handoffReason": str(record.get("handoffReason") or ""),
                "nextRecommendedWork": str(record.get("nextRecommendedWork") or ""),
                "unresolvedGaps": list(record.get("unresolvedGaps") or []),
                "claims": list(record.get("claims") or []),
                "references": list(references),
                "activeOrUnknownExecution": list(record.get("activeOrUnknownExecution") or []),
                "handoffs": list(record.get("handoffs") or []),
                "baseWorkspaceRevision": int(record.get("baseWorkspaceRevision") or 0),
                "lastSeenWorkspaceRevision": int(record.get("lastSeenWorkspaceRevision") or 0),
                "version": int(record.get("version") or 0),
                "automaticReplay": False,
            },
        )

    def _pack(
        self,
        *,
        snapshot: ContextRepositorySnapshot,
        query: ContextQueryInput,
        targets: list[str],
        safety: ContextSafety,
        contradictions: list[ContextWarning],
        sections: dict[str, list[Any]],
        full_refresh_required: bool,
        extra_omissions: list[ContextOmission],
    ) -> ContextQueryResult:
        included = {name: [] for name in _SECTION_ORDER}

        def omissions() -> list[ContextOmission]:
            result = list(extra_omissions)
            for name in _SECTION_ORDER:
                remaining = len(sections[name]) - len(included[name])
                if remaining > 0:
                    result.append(
                        ContextOmission(
                            section=name,
                            reason="budget_exhausted",
                            count=remaining,
                            continuation="Increase maxTokens or narrow targets/entityTypes and repeat the same revision query.",
                        )
                    )
            return result

        minimum_required = 0

        def build(status: Literal["complete", "truncated", "budget_too_small"]) -> ContextQueryResult:
            result = ContextQueryResult(
                workspace_id=snapshot.workspace_id,
                revision=snapshot.revision,
                base_revision=query.since_revision,
                intent=str(query.intent),
                targets=targets,
                budget=ContextBudget(
                    requested=query.max_tokens,
                    used=0,
                    status=status,
                    minimum_required=minimum_required,
                ),
                safety=safety,
                confirmed_facts=list(included["confirmedFacts"]),
                candidates=list(included["candidates"]),
                contradictions=contradictions,
                coverage_gaps=list(included["coverageGaps"]),
                recent_actions=list(included["recentActions"]),
                active_tasks=list(included["activeTasks"]),
                work_items=list(included["workItems"]),
                recommendations=list(included["recommendations"]),
                resource_links=list(included["resourceLinks"]),
                omissions=omissions(),
                full_refresh_required=full_refresh_required,
            )
            return self._fix_used(result)

        for _iteration in range(12):
            protected = build("truncated")
            measured = protected.budget.used
            if minimum_required == measured:
                break
            minimum_required = measured
        if query.max_tokens < minimum_required:
            return build("budget_too_small")

        stopped = False
        for name in _SECTION_ORDER:
            for item in sections[name]:
                included[name].append(item)
                remaining = sum(len(sections[key]) - len(included[key]) for key in _SECTION_ORDER)
                candidate = build("complete" if remaining == 0 and not extra_omissions else "truncated")
                if candidate.budget.used <= query.max_tokens:
                    continue
                included[name].pop()
                stopped = True
                break
            if stopped:
                break
        remaining = sum(len(sections[key]) - len(included[key]) for key in _SECTION_ORDER)
        status: Literal["complete", "truncated"] = "complete" if remaining == 0 and not extra_omissions else "truncated"
        result = build(status)
        if result.budget.used > query.max_tokens:
            # The protected minimum was computed before its own decimal width
            # stabilized only if a custom counter violates monotonicity.
            return build("budget_too_small")
        return result

    def _fix_used(self, result: ContextQueryResult) -> ContextQueryResult:
        for _iteration in range(12):
            measured = self.counter(self.payload_encoder(result))
            if result.budget.used == measured:
                return result
            result.budget.used = measured
        raise RuntimeError("Context budget accounting did not reach a fixed point.")
