"""Deterministic fictional Phase 5 operational acceptance scenarios."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
from pathlib import Path
from typing import Any

from helpers import isolated_state

from benchmark_support import seed_benchmark_workspace
from synapse_mcp.app.actions import RiskClass
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core.execution import (
    EffectEnvelope,
    ProviderRoute,
    RedirectPolicy,
    ScopeSnapshot,
    TargetEnvelope,
)
from synapse_mcp.core import workspace
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
)
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository
from synapse_mcp.state.errors import StateConflictError


WORKSPACE_ID = "benchmark"
TARGET = "app.acme-demo.test"
PRINCIPAL_ID = "phase5-acceptance-operator"
AUTHORITY_SESSION = "phase5-acceptance-session"
GRANT_ID = "phase5-acceptance-grant"
BASE_TIME = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


class Phase5ScenarioFailure(RuntimeError):
    """A deterministic acceptance invariant failed."""


def _process_claim(workspace_root: str, output: multiprocessing.Queue, worker: str) -> None:
    repository = SQLiteWorkItemRepository(
        ActivatedWorkspaceRepository(WORKSPACE_ID, Path(workspace_root))
    )
    try:
        claimed = repository.claim(
            "work-exclusive-race",
            expected_version=1,
            principal_id=PRINCIPAL_ID,
            authority_session_id="",
            agent_run_id="",
            worker=worker,
            lease_seconds=60,
            now=BASE_TIME,
        )
        output.put({"result": "success", "claimId": claimed["claimId"]})
    except StateConflictError as exc:
        output.put({"result": exc.reason_code})


def _require_success(outcome: Any, operation: str) -> dict[str, Any]:
    if outcome.outcome_kind != "success" or not isinstance(outcome.result, dict):
        raise Phase5ScenarioFailure(
            f"{operation} failed: {outcome.outcome_kind} {outcome.diagnostics}"
        )
    return outcome.result


def _create_work(
    facade: CompactFacadeService,
    context: FacadeCallContext,
    identity: str,
    *,
    role: str,
    pack: str,
    parent: str = "",
    dependencies: list[str] | None = None,
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "workItemId": identity,
        "objective": f"Complete the fictional {role} acceptance objective",
        "role": role,
        "requiredPacks": [pack],
        "selectedPacks": [pack],
        "targets": [TARGET],
        "contextQuery": {"targets": [TARGET], "maxTokens": 6000},
        "completionContract": {
            "result": f"bounded {role} result with references and gaps"
        },
        "unresolvedGaps": gaps or [],
    }
    if parent:
        payload["parentWorkItemId"] = parent
    if dependencies:
        payload["dependencyIds"] = dependencies
    return _require_success(
        facade.invoke(
            "tasks.control",
            {"operation": "work.create", "workspaceId": WORKSPACE_ID, "payload": payload},
            context=context,
        ),
        f"create {identity}",
    )


def _claim_work(
    repository: SQLiteWorkItemRepository,
    item: dict[str, Any],
    worker: str,
    *,
    now: datetime = BASE_TIME,
) -> dict[str, Any]:
    return repository.claim(
        item["workItemId"],
        expected_version=int(item["version"]),
        principal_id=PRINCIPAL_ID,
        authority_session_id="",
        agent_run_id="",
        worker=worker,
        lease_seconds=60,
        now=now,
    )


def _complete_work(
    repository: SQLiteWorkItemRepository,
    item: dict[str, Any],
    *,
    result: str,
    references: list[dict[str, Any]] | None = None,
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    return repository.transition(
        item["workItemId"],
        {
            "resultSummary": result,
            "references": references or [],
            "unresolvedGaps": gaps or [],
            "nextRecommendedWork": "Converge into the dependency-bound report.",
        },
        operation="complete",
        claim_id=item["claimId"],
        expected_version=int(item["version"]),
        principal_id=PRINCIPAL_ID,
        authority_session_id="",
        agent_run_id="",
        now=BASE_TIME,
    )


def _seed_reporting_truth(repository: ActivatedWorkspaceRepository) -> dict[str, str]:
    evidence_ids = {
        "web": "evidence-phase5-web",
        "access": "evidence-phase5-access",
    }
    for role, evidence_id in evidence_ids.items():
        artifact = repository.artifacts.ingest_bytes(
            f"fictional Phase 5 {role} evidence".encode(),
            media_type="text/plain",
            origin=f"phase5.acceptance.{role}",
        )
        collections: dict[str, tuple[dict[str, Any], ...]] = {
            "observations": (
                {
                    "type": "test_candidate",
                    "key": "candidate-phase5-shared",
                    "summary": "A fictional shared candidate requires reviewed validation.",
                    "candidateFor": ["fictional-access-boundary"],
                    "evidenceIds": [evidence_id],
                },
                {
                    "type": "state_contradiction",
                    "key": f"contradiction-phase5-{role}",
                    "summary": f"The fictional {role} perspective conflicts with another observation.",
                    "scopeStatus": "in_scope",
                    "authorityStatus": "unknown",
                },
                {
                    "type": "detection_gap",
                    "key": f"gap-phase5-{role}",
                    "summary": f"The fictional {role} objective retains an explicit coverage gap.",
                },
            ),
        }
        if role == "access":
            collections["findings"] = (
                {
                    "id": "finding-phase5-shared",
                    "key": "finding-phase5-shared",
                    "title": "Confirmed fictional shared-control fact",
                    "status": "confirmed",
                    "severity": "low",
                    "operatorReviewed": True,
                    "evidenceIds": list(evidence_ids.values()),
                },
            )
        repository.ingest_collections(
            target=TARGET,
            target_payload={"workspaceId": WORKSPACE_ID, "target": TARGET, "kind": "host"},
            evidence_payload={
                "evidenceId": evidence_id,
                "source": f"phase5.acceptance.{role}",
                "dataType": "fictional_fixture",
                "summary": f"Bounded fictional {role} evidence for Phase 5 acceptance.",
            },
            artifact=artifact,
            collections=collections,
            audit_payload={"summary": f"Installed the fictional {role} acceptance evidence."},
        )
    return evidence_ids


def _install_authority_grant() -> None:
    snapshot = ScopeSnapshot.for_workspace(WORKSPACE_ID)
    now = datetime.now(timezone.utc)
    grant = AuthorityGrant(
        grant_id=GRANT_ID,
        workspace_id=WORKSPACE_ID,
        revision=1,
        mode=AuthorityMode.FULL_DELEGATED,
        scope_digest=snapshot.digest,
        target_envelope=TargetEnvelope(
            workspace_id=WORKSPACE_ID,
            scope_digest=snapshot.digest,
            scope_snapshot=snapshot,
            exact_targets=(),
            seeds=(),
            entire_workspace_scope=True,
            redirect_policy=RedirectPolicy(False, 0),
            expansion_reasons=("phase5_fictional_fixture",),
        ),
        allowed_action_patterns=("cors.execute_test",),
        allowed_methods=("GET", "OPTIONS"),
        allowed_effects=EffectEnvelope(
            traffic=("authorized_target",),
            local_writes=("evidence", "workspace"),
            local_change=True,
            local_destruction=False,
            remote_state_change=False,
            credential_use=False,
            secret_use=False,
            replay_safety="non_idempotent",
        ),
        risk_ceiling=RiskClass.HIGH,
        credential_refs=(),
        provider_routes=(ProviderRoute.from_values("disabled", None),),
        third_party_providers=(),
        local_outputs=(),
        budgets=BudgetLimits(20, 20, 3600, 5),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        approved_by=OperatorPrincipal.current_local().principal_id,
    )
    AuthorityOperatorService(
        WORKSPACE_ID,
        OperatorPrincipal.current_local(),
    ).create_grant(grant)


def _run_process_race(workspace_root: Path) -> dict[str, Any]:
    process_context = multiprocessing.get_context("spawn")
    output = process_context.Queue()
    processes = [
        process_context.Process(
            target=_process_claim,
            args=(str(workspace_root), output, f"race-worker-{index}"),
        )
        for index in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.exitcode != 0:
            raise Phase5ScenarioFailure(
                f"exclusive claim worker exited with {process.exitcode}"
            )
    results = [output.get(timeout=5) for _ in processes]
    winners = sum(item["result"] == "success" for item in results)
    if winners != 1:
        raise Phase5ScenarioFailure(f"exclusive claim race produced {winners} winners")
    return {
        "contenders": len(results),
        "winners": winners,
        "loserReason": next(item["result"] for item in results if item["result"] != "success"),
    }


def run_operational_repetition(root: Path, repetition: int) -> dict[str, Any]:
    """Run one isolated Phase 5 single/multi-agent operational scenario."""

    with isolated_state(root, store_version="sqlite-v2"):
        seed_benchmark_workspace()
        workspace_root = workspace.WORKSPACES_DIR / WORKSPACE_ID
        activated = ActivatedWorkspaceRepository(WORKSPACE_ID, workspace_root)
        repository = SQLiteWorkItemRepository(activated)
        context = FacadeCallContext(
            principal_id=PRINCIPAL_ID,
            workspace_id=WORKSPACE_ID,
            execution_profile="legacy",
            correlation_id=f"phase5-acceptance-{repetition}",
        )
        facade = CompactFacadeService(work_items=WorkItemService(clock=lambda: BASE_TIME))
        evidence_ids = _seed_reporting_truth(activated)

        starting_revision = activated.revision()
        summary = _require_success(
            facade.invoke(
                "engagement.inspect",
                {"workspaceId": WORKSPACE_ID},
                context=context,
            ),
            "single-agent workspace inspection",
        )
        full_context = _require_success(
            facade.invoke(
                "context.query",
                {
                    "workspaceId": WORKSPACE_ID,
                    "targets": [TARGET],
                    "maxTokens": 6000,
                },
                context=context,
            ),
            "single-agent context query",
        )

        parent = _create_work(
            facade,
            context,
            "work-phase5-coordinator",
            role="coordinator",
            pack="core",
            gaps=["No real target traffic is permitted in acceptance."],
        )
        specialist_specs = (
            ("work-phase5-perimeter", "perimeter", "infra"),
            ("work-phase5-web", "web", "web"),
            ("work-phase5-access", "access-control", "web"),
            ("work-phase5-intelligence", "intelligence", "intelligence"),
        )
        specialists = [
            _create_work(
                facade,
                context,
                identity,
                role=role,
                pack=pack,
                parent=parent["workItemId"],
            )
            for identity, role, pack in specialist_specs
        ]
        report = _create_work(
            facade,
            context,
            "work-phase5-report",
            role="reporting",
            pack="reporting",
            parent=parent["workItemId"],
            dependencies=[item["workItemId"] for item in specialists],
            gaps=["Authenticated coverage remains intentionally unavailable."],
        )
        if report["status"] != "planned":
            raise Phase5ScenarioFailure("reporting work did not wait for dependencies")

        with ThreadPoolExecutor(max_workers=4) as pool:
            claimed = list(
                pool.map(
                    lambda pair: _claim_work(repository, pair[0], pair[1]),
                    zip(specialists, ("perimeter-agent", "web-agent", "access-agent", "intel-agent")),
                )
            )
        context_bytes: list[int] = []
        for item in claimed:
            recovered_context = _require_success(
                facade.invoke(
                    "context.query",
                    {
                        "workspaceId": WORKSPACE_ID,
                        "workItemId": item["workItemId"],
                        "claimId": item["claimId"],
                        "maxTokens": 6000,
                    },
                    context=context,
                ),
                f"specialist context {item['workItemId']}",
            )
            used = int(recovered_context["budget"]["used"])
            if used > 6000:
                raise Phase5ScenarioFailure("specialist context exceeded its budget")
            context_bytes.append(used)

        references_by_id = {
            "work-phase5-web": [{"type": "evidence", "id": evidence_ids["web"]}],
            "work-phase5-access": [{"type": "evidence", "id": evidence_ids["access"]}],
            "work-phase5-perimeter": [
                {"type": "operation", "id": "offline-perimeter-analysis"}
            ],
            "work-phase5-intelligence": [
                {"type": "operation", "id": "offline-intelligence-analysis"}
            ],
        }
        completed = []
        for item in claimed:
            completed.append(
                _complete_work(
                    repository,
                    item,
                    result=f"Completed {item['role']} with bounded fictional evidence.",
                    references=references_by_id[item["workItemId"]],
                    gaps=[f"{item['role']} active validation was not requested."],
                )
            )
        unlocked_report = repository.inspect(report["workItemId"])
        if unlocked_report["status"] != "available":
            raise Phase5ScenarioFailure("completed dependencies did not unlock reporting")

        report_claim = _claim_work(repository, unlocked_report, "reporting-agent")
        report_context = _require_success(
            facade.invoke(
                "context.query",
                {
                    "workspaceId": WORKSPACE_ID,
                    "workItemId": report["workItemId"],
                    "claimId": report_claim["claimId"],
                    "maxTokens": 20_000,
                },
                context=context,
            ),
            "dependency-bound reporting context",
        )
        report_result = _require_success(
            facade.invoke(
                "reports.render",
                {
                    "workspaceId": WORKSPACE_ID,
                    "targets": [TARGET],
                    "format": "markdown",
                    "redactionMode": "operator",
                    "returnContent": True,
                },
                context=context,
            ),
            "operator report",
        )
        report_claim["version"] = repository.inspect(report["workItemId"])["version"]
        completed_report = _complete_work(
            repository,
            report_claim,
            result="Produced one coherent operator report from dependency-linked workspace truth.",
            references=[{"type": "operation", "id": "phase5-operator-report"}],
            gaps=["Authenticated coverage remains intentionally unavailable."],
        )

        race_item = repository.create(
            {
                "workItemId": "work-exclusive-race",
                "objective": "Prove one exclusive claim winner",
            },
            principal_id=PRINCIPAL_ID,
            now=BASE_TIME,
        )
        if race_item["version"] != 1:
            raise Phase5ScenarioFailure("exclusive race item did not start at version 1")
        race = _run_process_race(workspace_root)

        recovery_item = repository.create(
            {
                "workItemId": "work-phase5-recovery",
                "objective": "Recover outcome-unknown background execution without replay",
            },
            principal_id=PRINCIPAL_ID,
            now=BASE_TIME,
        )
        stale_claim = _claim_work(repository, recovery_item, "lost-agent")
        repository.link_execution(
            recovery_item["workItemId"],
            claim_id=stale_claim["claimId"],
            principal_id=PRINCIPAL_ID,
            authority_session_id="",
            agent_run_id="",
            references=[
                {
                    "type": "job",
                    "id": "job-phase5-outcome-unknown",
                    "state": "unknown",
                    "replaySafety": "non_idempotent",
                }
            ],
            event_type="work_item.execution_result",
            now=BASE_TIME,
        )
        recovery = repository.recover(
            principal_id=PRINCIPAL_ID,
            work_item_id=recovery_item["workItemId"],
            now=BASE_TIME + timedelta(seconds=61),
        )
        recovered_item = repository.inspect(recovery_item["workItemId"])
        if recovered_item["automaticReplay"] or not recovered_item["executionReviewRequired"]:
            raise Phase5ScenarioFailure("recovery did not preserve outcome-unknown execution")
        replacement = _claim_work(
            repository,
            recovered_item,
            "replacement-agent",
            now=BASE_TIME + timedelta(seconds=62),
        )
        try:
            repository.transition(
                recovery_item["workItemId"],
                {"resultSummary": "stale agent must not complete"},
                operation="complete",
                claim_id=stale_claim["claimId"],
                expected_version=replacement["version"],
                principal_id=PRINCIPAL_ID,
                authority_session_id="",
                agent_run_id="",
                now=BASE_TIME + timedelta(seconds=63),
            )
        except StateConflictError as exc:
            stale_reason = exc.reason_code
        else:
            raise Phase5ScenarioFailure("stale claimant completed reclaimed work")

        _install_authority_grant()
        covered_context = FacadeCallContext(
            principal_id=PRINCIPAL_ID,
            workspace_id=WORKSPACE_ID,
            execution_profile="full_delegated",
            authority_session_id=AUTHORITY_SESSION,
            selected_grant_id=GRANT_ID,
            correlation_id=f"phase5-covered-{repetition}",
        )
        cors_arguments = {
            "workspaceId": WORKSPACE_ID,
            "url": f"https://{TARGET}/api",
            "method": "GET",
            "probeOrigin": "https://origin.invalid",
            "followRedirects": False,
            "disableTraffic": True,
        }
        covered = facade.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": cors_arguments,
                "idempotencyKey": f"phase5-covered-{repetition}",
            },
            context=covered_context,
        )
        uncovered_context = FacadeCallContext(
            principal_id=PRINCIPAL_ID,
            workspace_id=WORKSPACE_ID,
            execution_profile="full_delegated",
            authority_session_id="phase5-uncovered-session",
            correlation_id=f"phase5-uncovered-{repetition}",
        )
        uncovered = facade.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": cors_arguments,
                "idempotencyKey": f"phase5-uncovered-{repetition}",
            },
            context=uncovered_context,
        )
        if covered.outcome_kind != "success" or uncovered.outcome_kind != "approval_required":
            raise Phase5ScenarioFailure(
                f"authority gate mismatch: covered={covered.outcome_kind}, uncovered={uncovered.outcome_kind}"
            )

        delta = _require_success(
            facade.invoke(
                "context.query",
                {
                    "workspaceId": WORKSPACE_ID,
                    "targets": [TARGET],
                    "sinceRevision": starting_revision,
                    "maxTokens": 20_000,
                },
                context=context,
            ),
            "single-agent revision delta",
        )
        convergence_context = _require_success(
            facade.invoke(
                "context.query",
                {
                    "workspaceId": WORKSPACE_ID,
                    "targets": [TARGET],
                    "maxTokens": 20_000,
                },
                context=context,
            ),
            "coordinator convergence context",
        )
        children = repository.list(parent_work_item_id=parent["workItemId"], limit=20)
        terminal_children = [item for item in children if item["status"] in TERMINAL_STATUSES]
        if len(terminal_children) != len(specialists) + 1:
            raise Phase5ScenarioFailure("coordinator convergence omitted completed child work")
        if not convergence_context["coverageGaps"] or not convergence_context["contradictions"]:
            raise Phase5ScenarioFailure("reporting context omitted gaps or contradictions")
        if not convergence_context["candidates"] or not any(
            item["kind"] == "finding" for item in convergence_context["confirmedFacts"]
        ):
            raise Phase5ScenarioFailure("reporting context collapsed candidates or findings")

        return {
            "repetition": repetition,
            "directWorkflow": {
                "result": "pass",
                "directInspection": bool(summary),
                "contextBytes": int(full_context["budget"]["used"]),
                "deltaBaseRevision": int(
                    (delta.get("delta") or delta).get("baseRevision", starting_revision)
                ),
                "deltaRevision": int(delta["revision"]),
                "reportRendered": bool(report_result),
                "explicitGapCount": len(convergence_context["coverageGaps"]),
            },
            "coordinatedWorkflow": {
                "result": "pass",
                "specialistCount": len(specialists),
                "concurrentClaims": len(claimed),
                "specialistContextBytes": context_bytes,
                "completedChildCount": len(terminal_children),
                "reportStatus": completed_report["status"],
                "candidateCount": len(convergence_context["candidates"]),
                "findingCount": sum(
                    item["kind"] == "finding" for item in convergence_context["confirmedFacts"]
                ),
                "contradictionCount": len(convergence_context["contradictions"]),
                "gapCount": len(convergence_context["coverageGaps"]),
            },
            "contention": race,
            "recovery": {
                "recoveredWorkItemIds": recovery["recoveredWorkItemIds"],
                "activeOrUnknownExecution": len(recovered_item["activeOrUnknownExecution"]),
                "automaticReplay": recovered_item["automaticReplay"],
                "staleClaimReason": stale_reason,
            },
            "authority": {
                "coveredOutcome": covered.outcome_kind,
                "uncoveredOutcome": uncovered.outcome_kind,
                "coveredApprovalInterruptions": 0,
                "externalTargetTraffic": 0,
            },
            "evidence": {
                "distinctSpecialistEvidence": sorted(evidence_ids.values()),
                "reportDependencyCount": len(report["dependencyIds"]),
            },
            "workspace": {
                "startingRevision": starting_revision,
                "finalRevision": activated.revision(),
                "lostUpdates": 0,
                "duplicateActionsOrJobs": 0,
            },
        }


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
