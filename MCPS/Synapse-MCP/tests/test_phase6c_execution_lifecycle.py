"""Task 6C gates for versioned execution contracts and durable run state."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from helpers import isolated_state, wait_for_job

from synapse_mcp.app.actions import (
    ActionRegistry,
    ActionRequest,
    ExecutionContext,
    ExecutionUnknown,
    REGISTRY,
    ProfilePolicyEvaluator,
    RiskClass,
    Success,
)
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core import background_jobs, workspace
from synapse_mcp.core.execution import EffectEnvelope, ExecutionPlan, ExecutionPlanError
from synapse_mcp.core.execution_lifecycle import (
    EffectValidationVerdict,
    ExecutionIntent,
    ExecutionRun,
    ExecutionRunState,
    LifecycleContractError,
    NoOpExecutionObserver,
    NormalizedEffectObservation,
    ObservationCoverage,
    ObservationCoverageStatus,
    ObservationSource,
    ObservationTrustClass,
    ObserverResult,
    validate_observed_effects,
)
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityRepositoryError,
    BudgetLimits,
    StateChangePolicy,
    WorkspaceAuthorityRepository,
)
from synapse_mcp.state import (
    ActivatedWorkspaceRepository,
    SQLiteWorkItemRepository,
    StateBundleService,
    StateSelectionError,
    execution_lifecycle_repository,
)
from synapse_mcp.state.connections import immediate_transaction
from synapse_mcp.state import migrations as state_migrations
from synapse_mcp.state.migrations import MIGRATION_NAMES, apply_migrations


NOW = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)


def _plan(workspace_id: str, *, correlation_id: str = "phase6c-correlation") -> ExecutionPlan:
    descriptor = REGISTRY.get("workspace.summary")
    request = ActionRequest(
        descriptor.input_model.model_validate({"workspaceId": workspace_id}),
        ExecutionContext(workspace_id, correlation_id, 45.0, None),
    )
    return REGISTRY.resolve_execution_plan("workspace.summary", request)


def _grant(plan: ExecutionPlan, *, grant_id: str = "grant-phase6c") -> AuthorityGrant:
    return AuthorityGrant(
        grant_id=grant_id,
        workspace_id=plan.intent.workspace_id,
        revision=1,
        mode=AuthorityMode.FULL_DELEGATED,
        scope_digest=plan.intent.target_envelope.scope_digest,
        target_envelope=plan.intent.target_envelope,
        allowed_action_patterns=(plan.action_id,),
        allowed_methods=plan.intent.methods,
        allowed_effects=plan.effects,
        risk_ceiling=RiskClass.HIGH,
        credential_refs=plan.intent.credential_refs,
        provider_routes=plan.intent.providers,
        third_party_providers=(),
        local_outputs=plan.intent.local_outputs,
        budgets=BudgetLimits(None, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1),
        approved_by="operator:phase6c",
    )


def _process_authorize(
    workspaces_root: str,
    plan: ExecutionPlan,
    barrier: multiprocessing.Barrier,
    output: multiprocessing.Queue,
) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    try:
        barrier.wait(timeout=10)
        result = WorkspaceAuthorityRepository("phase6c-process", clock=lambda: NOW).authorize(
            plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="phase6c-session",
            selected_grant_id="grant-phase6c",
            idempotency_key="phase6c-one-dispatch",
        )
        output.put({"kind": result.decision.kind, "runId": result.receipt.execution_run_id})
    except BaseException as exc:
        output.put({"kind": "error", "reason": getattr(exc, "reason_code", type(exc).__name__)})


class _OutsideEnvelopeObserver:
    def finalize(self, run: ExecutionRun, *, outcome_kind: str, observed_at: str) -> ObserverResult:
        del outcome_kind
        observation = NormalizedEffectObservation(
            observation_id=f"observation-{run.identity.execution_run_id}",
            execution_run_id=run.identity.execution_run_id,
            sequence=1,
            source=ObservationSource(ObservationTrustClass.RUNTIME_OBSERVED, "phase6c-fixture"),
            effect_class="local_output",
            observed_effects=EffectEnvelope(local_change=True, replay_safety="idempotent_write"),
            observed_at=observed_at,
            detail={},
        ).sealed()
        coverage = (
            ObservationCoverage(
                "local_output",
                ObservationCoverageStatus.OBSERVED,
                "phase6c-fixture",
            ),
        )
        validation = validate_observed_effects(
            run,
            (observation,),
            coverage,
            validation_id=f"validation-{run.identity.execution_run_id}",
            validated_at=observed_at,
        )
        return ObserverResult((observation,), validation)


class Phase6CExecutionLifecycleContractTests(unittest.TestCase):
    def test_execution_plan_v1_round_trip_and_tamper_rejection_remain_stable(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary)):
            workspace.create_workspace("phase6c-plan", hosts=["plan.example"])
            plan = _plan("phase6c-plan")
            serialized = plan.to_dict()
            self.assertEqual(serialized["version"], 1)
            self.assertEqual(ExecutionPlan.from_dict(serialized), plan)
            intent = ExecutionIntent.from_plan(plan)
            self.assertEqual(ExecutionIntent.from_dict(intent.to_dict()), intent)

            altered = json.loads(json.dumps(serialized))
            altered["correlationId"] = "altered"
            with self.assertRaises(ExecutionPlanError) as raised:
                ExecutionPlan.from_dict(altered)
            self.assertEqual(raised.exception.reason_code, "execution_plan_tampered")

    def test_intent_and_authorization_fingerprint_mismatch_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-contract", hosts=["contract.example"])
            repository = WorkspaceAuthorityRepository("phase6c-contract", clock=lambda: NOW)
            plan = _plan("phase6c-contract")
            repository.create_grant(_grant(plan))
            result = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-mismatch",
            )
            run = ExecutionRun.from_dict(repository.inspect_execution_run(result.receipt.execution_run_id))

            wrong_plan = _plan("phase6c-contract", correlation_id="different-correlation")
            mismatched = replace(
                run,
                intent=ExecutionIntent.from_plan(wrong_plan),
                run_fingerprint="",
            ).sealed()
            with self.assertRaises(LifecycleContractError) as raised:
                mismatched.verify()
            self.assertEqual(raised.exception.reason_code, "execution_authorization_mismatch")

    def test_noop_observer_never_claims_effect_coverage(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-noop", hosts=["noop.example"])
            repository = WorkspaceAuthorityRepository("phase6c-noop", clock=lambda: NOW)
            plan = _plan("phase6c-noop")
            repository.create_grant(_grant(plan))
            result = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-noop",
            )
            receipt = result.receipt
            repository.mark_dispatched(receipt)
            repository.transition_dispatch(
                receipt.dispatch_id,
                "succeeded",
                outcome_kind="success",
                observer=NoOpExecutionObserver(),
            )

            runtime = ActivatedWorkspaceRepository("phase6c-noop", workspace.workspace_path("phase6c-noop"))
            run = runtime.inspect_execution_run(receipt.execution_run_id)
            validations = runtime.effect_validations(receipt.execution_run_id)
            self.assertEqual(run["state"], "outcome_committed")
            self.assertEqual(run["outcomeKind"], "success")
            self.assertEqual(len(validations), 1)
            self.assertEqual(validations[0]["verdict"], EffectValidationVerdict.UNOBSERVABLE)
            self.assertEqual(validations[0]["coverage"][0]["status"], "not_instrumented")
            self.assertEqual(runtime.execution_observations(receipt.execution_run_id), [])

    def test_narrated_observation_cannot_set_effect_validation_truth(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-narrated", hosts=["narrated.example"])
            repository = WorkspaceAuthorityRepository("phase6c-narrated", clock=lambda: NOW)
            plan = _plan("phase6c-narrated")
            repository.create_grant(_grant(plan))
            receipt = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-narrated",
            ).receipt
            run = ExecutionRun.from_dict(repository.inspect_execution_run(receipt.execution_run_id))
            narrated = NormalizedEffectObservation(
                observation_id="observation-model-narrative",
                execution_run_id=receipt.execution_run_id,
                sequence=1,
                source=ObservationSource(ObservationTrustClass.MODEL_REPORTED, "model-assertion"),
                effect_class="local_output",
                observed_effects=EffectEnvelope(local_change=True, replay_safety="idempotent_write"),
                observed_at="2026-09-02T09:00:01Z",
                detail={"assertion": "untrusted"},
            ).sealed()
            validation = validate_observed_effects(
                run,
                (narrated,),
                (
                    ObservationCoverage(
                        "execution_effects",
                        ObservationCoverageStatus.UNOBSERVABLE,
                        "model-assertion",
                    ),
                ),
                validation_id="validation-model-narrative",
                validated_at="2026-09-02T09:00:02Z",
            )
            self.assertEqual(validation.verdict, EffectValidationVerdict.UNOBSERVABLE)
            self.assertEqual(validation.observed_effects, EffectEnvelope())
            self.assertEqual(validation.observation_fingerprints, ())

    def test_observation_detail_rejects_raw_secret_and_opaque_identity_fields(self) -> None:
        common = {
            "observation_id": "observation-sensitive-detail",
            "execution_run_id": "run-sensitive-detail",
            "sequence": 1,
            "source": ObservationSource(ObservationTrustClass.RUNTIME_OBSERVED, "runtime-boundary"),
            "effect_class": "credential_use",
            "observed_effects": EffectEnvelope(credential_use=True),
            "observed_at": "2026-09-02T09:00:01Z",
        }
        with self.assertRaises(LifecycleContractError) as secret:
            NormalizedEffectObservation(**common, detail={"password": "fixture-value"})
        self.assertEqual(secret.exception.reason_code, "observation_secret_forbidden")
        with self.assertRaises(LifecycleContractError) as opaque:
            NormalizedEffectObservation(**common, detail={"token": "fixture-value"})
        self.assertEqual(opaque.exception.reason_code, "observation_opaque_identity_forbidden")

    def test_trusted_observation_outside_envelope_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-outside", hosts=["outside.example"])
            repository = WorkspaceAuthorityRepository("phase6c-outside", clock=lambda: NOW)
            plan = _plan("phase6c-outside")
            repository.create_grant(_grant(plan))
            receipt = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-outside",
            ).receipt
            run = ExecutionRun.from_dict(repository.inspect_execution_run(receipt.execution_run_id))
            observed = NormalizedEffectObservation(
                observation_id="observation-runtime-outside",
                execution_run_id=receipt.execution_run_id,
                sequence=1,
                source=ObservationSource(ObservationTrustClass.RUNTIME_OBSERVED, "runtime-boundary"),
                effect_class="local_output",
                observed_effects=EffectEnvelope(local_change=True, replay_safety="idempotent_write"),
                observed_at="2026-09-02T09:00:01Z",
                detail={},
            ).sealed()
            validation = validate_observed_effects(
                run,
                (observed,),
                (
                    ObservationCoverage(
                        "local_output",
                        ObservationCoverageStatus.OBSERVED,
                        "runtime-boundary",
                    ),
                ),
                validation_id="validation-runtime-outside",
                validated_at="2026-09-02T09:00:02Z",
            )
            self.assertEqual(validation.verdict, EffectValidationVerdict.OUTSIDE_ENVELOPE)
            self.assertEqual(validation.discrepancies[0].dimension, "effect_envelope")

    def test_validation_fingerprint_mismatch_is_rejected_atomically(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-validation-binding", hosts=["binding.example"])
            repository = WorkspaceAuthorityRepository("phase6c-validation-binding", clock=lambda: NOW)
            plan = _plan("phase6c-validation-binding")
            repository.create_grant(_grant(plan))
            receipt = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-validation-binding",
            ).receipt
            repository.mark_dispatched(receipt)
            run = ExecutionRun.from_dict(repository.inspect_execution_run(receipt.execution_run_id))
            observation = NormalizedEffectObservation(
                observation_id="observation-validation-binding",
                execution_run_id=receipt.execution_run_id,
                sequence=1,
                source=ObservationSource(ObservationTrustClass.RUNTIME_OBSERVED, "runtime-boundary"),
                effect_class="execution_effects",
                observed_effects=EffectEnvelope(),
                observed_at="2026-09-02T09:00:01Z",
                detail={},
            ).sealed()
            coverage = (
                ObservationCoverage(
                    "execution_effects",
                    ObservationCoverageStatus.OBSERVED,
                    "runtime-boundary",
                ),
            )
            repository.record_execution_observations(receipt, (observation,), coverage=coverage)
            valid = validate_observed_effects(
                run,
                (observation,),
                coverage,
                validation_id="validation-binding",
                validated_at="2026-09-02T09:00:02Z",
            )
            mismatched = replace(
                valid,
                observation_fingerprints=("0" * 64,),
                validation_fingerprint="",
            ).sealed()
            with self.assertRaises(AuthorityRepositoryError) as raised:
                repository.record_effect_validation(
                    receipt,
                    mismatched,
                    outcome_kind="success",
                )
            self.assertEqual(raised.exception.reason_code, "effect_validation_binding_mismatch")
            self.assertEqual(repository.inspect_execution_run(receipt.execution_run_id)["state"], "observing")
            runtime = ActivatedWorkspaceRepository(
                "phase6c-validation-binding",
                workspace.workspace_path("phase6c-validation-binding"),
            )
            self.assertEqual(runtime.effect_validations(receipt.execution_run_id), [])

    def test_outside_envelope_verdict_forces_registry_outcome_unknown(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-registry-outside", hosts=["outside.example"])
            plan = _plan("phase6c-registry-outside")
            authority = WorkspaceAuthorityRepository("phase6c-registry-outside")
            authority.create_grant(_grant(plan))
            descriptor = REGISTRY.get("workspace.summary")
            request = ActionRequest(
                descriptor.input_model.model_validate({"workspaceId": "phase6c-registry-outside"}),
                ExecutionContext(
                    "phase6c-registry-outside",
                    "phase6c-registry-outside",
                    45.0,
                    None,
                    execution_profile="full_delegated",
                    authority_session_id="phase6c-session",
                    selected_grant_id="grant-phase6c",
                    idempotency_key="phase6c-registry-outside",
                ),
            )
            registry = ActionRegistry(ProfilePolicyEvaluator(_OutsideEnvelopeObserver()))
            registry.register(descriptor)
            registry.freeze()
            outcome = registry.execute("workspace.summary", request)
            self.assertIsInstance(outcome, ExecutionUnknown)
            self.assertEqual(outcome.reason_code, "authority_result_commit_unknown")
            dispatch = next(iter(authority.snapshot()["dispatches"].values()))
            self.assertEqual(dispatch["state"], "unknown")
            run_id = dispatch["executionRunId"]
            self.assertEqual(authority.inspect_execution_run(run_id)["state"], "execution_unknown")
            runtime = ActivatedWorkspaceRepository(
                "phase6c-registry-outside",
                workspace.workspace_path("phase6c-registry-outside"),
            )
            self.assertEqual(runtime.effect_validations(run_id)[0]["verdict"], "outside_envelope")

    def test_restart_reconstructs_authorized_dispatched_unknown_and_committed_runs(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-restart", hosts=["restart.example"])
            repository = WorkspaceAuthorityRepository("phase6c-restart", clock=lambda: NOW)
            plan = _plan("phase6c-restart")
            repository.create_grant(_grant(plan))
            receipts = []
            for suffix in ("authorized", "dispatched", "unknown", "committed"):
                receipts.append(
                    repository.authorize(
                        plan,
                        risk_class=RiskClass.NONE,
                        profile="full_delegated",
                        authority_session_id="phase6c-session",
                        selected_grant_id="grant-phase6c",
                        idempotency_key=f"phase6c-{suffix}",
                    ).receipt
                )
            repository.mark_dispatched(receipts[1])
            repository.mark_dispatched(receipts[2])
            repository.transition_dispatch(
                receipts[2].dispatch_id,
                "unknown",
                outcome_kind="execution_unknown",
            )
            repository.mark_dispatched(receipts[3])
            repository.transition_dispatch(receipts[3].dispatch_id, "succeeded", outcome_kind="success")

            reconstructed = WorkspaceAuthorityRepository("phase6c-restart", clock=lambda: NOW)
            states = [
                reconstructed.inspect_execution_run(receipt.execution_run_id)["state"]
                for receipt in receipts
            ]
            self.assertEqual(
                states,
                ["authorized", "dispatch_started", "execution_unknown", "outcome_committed"],
            )

    def test_restart_reconstructs_observing_and_validation_pending_boundaries(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-boundaries", hosts=["boundaries.example"])
            repository = WorkspaceAuthorityRepository("phase6c-boundaries", clock=lambda: NOW)
            plan = _plan("phase6c-boundaries")
            repository.create_grant(_grant(plan))
            observing = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-observing",
            ).receipt
            validating = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-validating",
            ).receipt
            repository.mark_dispatched(observing)
            repository.mark_execution_observing(observing)
            repository.mark_dispatched(validating)
            run = ExecutionRun.from_dict(repository.inspect_execution_run(validating.execution_run_id))
            validation = NoOpExecutionObserver().finalize(
                run,
                outcome_kind="success",
                observed_at="2026-09-02T09:00:01Z",
            ).validation
            repository.record_effect_validation(validating, validation, outcome_kind="success")

            reconstructed = WorkspaceAuthorityRepository("phase6c-boundaries", clock=lambda: NOW)
            self.assertEqual(
                reconstructed.inspect_execution_run(observing.execution_run_id)["state"],
                "observing",
            )
            pending = reconstructed.inspect_execution_run(validating.execution_run_id)
            self.assertEqual(pending["state"], "validation_pending")
            self.assertEqual(pending["finalValidationId"], validation.validation_id)
            reconstructed.transition_dispatch(
                validating.dispatch_id,
                "succeeded",
                outcome_kind="success",
            )
            self.assertEqual(
                reconstructed.inspect_execution_run(validating.execution_run_id)["state"],
                "outcome_committed",
            )

    def test_supervised_resume_creates_one_run_only_after_exact_step_up(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-supervised", hosts=["supervised.example"])
            repository = WorkspaceAuthorityRepository("phase6c-supervised", clock=lambda: NOW)
            plan = _plan("phase6c-supervised")
            grant = replace(
                _grant(plan),
                mode=AuthorityMode.SUPERVISED,
                state_change_policy=StateChangePolicy.REQUIRE_STEP_UP,
            )
            repository.create_grant(grant)
            denied = repository.authorize(
                plan,
                risk_class=RiskClass.HIGH,
                profile="supervised",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-supervised",
            )
            self.assertEqual(denied.decision.kind, "approval_required")
            runtime = ActivatedWorkspaceRepository(
                "phase6c-supervised",
                workspace.workspace_path("phase6c-supervised"),
            )
            with runtime.connection_factory.connect() as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM execution_runs").fetchone()[0], 0)
            request_state_id = denied.decision.request_state_id
            repository.issue_request_step_up(
                request_state_id,
                approved_by="operator:phase6c",
                expires_at=NOW + timedelta(minutes=5),
            )
            resumed = repository.authorize(
                plan,
                risk_class=RiskClass.HIGH,
                profile="supervised",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-supervised",
                request_state_id=request_state_id,
            )
            self.assertEqual(resumed.decision.kind, "allow")
            self.assertTrue(resumed.receipt.execution_run_id)
            run = repository.inspect_execution_run(resumed.receipt.execution_run_id)
            self.assertEqual(run["identity"]["correlationId"], plan.correlation_id)
            self.assertEqual(run["authorizationBinding"]["profile"], "supervised")

    def test_expired_work_claim_cannot_orphan_registry_run_finalization(self) -> None:
        class SequenceClock:
            def __init__(self) -> None:
                self.values = iter((NOW, NOW + timedelta(seconds=1), NOW + timedelta(seconds=16)))

            def __call__(self) -> datetime:
                return next(self.values, NOW + timedelta(seconds=16))

        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-work", hosts=["work.example"])
            lifecycle = WorkspaceAuthorityRepository("phase6c-work")
            plan = _plan("phase6c-work")
            lifecycle.create_grant(_grant(plan))
            work_repository = SQLiteWorkItemRepository(
                ActivatedWorkspaceRepository("phase6c-work", workspace.workspace_path("phase6c-work"))
            )
            item = work_repository.create(
                {"workItemId": "phase6c-expiring-work", "objective": "Exercise an expiring claim."},
                principal_id="operator:phase6c",
                now=NOW,
            )
            claimed = work_repository.claim(
                item["workItemId"],
                expected_version=item["version"],
                principal_id="operator:phase6c",
                authority_session_id="phase6c-session",
                agent_run_id="agent-run-phase6c",
                worker="phase6c-worker",
                lease_seconds=15,
                now=NOW,
            )
            facade = CompactFacadeService(work_items=WorkItemService(clock=SequenceClock()))
            response = facade.invoke(
                "actions.run_passive",
                {
                    "actionId": "workspace.summary",
                    "arguments": {"workspaceId": "phase6c-work"},
                    "idempotencyKey": "phase6c-expiring-run",
                    "workItem": {
                        "workItemId": item["workItemId"],
                        "claimId": claimed["claimId"],
                    },
                },
                context=FacadeCallContext(
                    principal_id="operator:phase6c",
                    workspace_id="phase6c-work",
                    execution_profile="full_delegated",
                    authority_session_id="phase6c-session",
                    selected_grant_id="grant-phase6c",
                    agent_run_id="agent-run-phase6c",
                    correlation_id="phase6c-work-call",
                ),
            )
            self.assertEqual(response.outcome_kind, "success", response)
            inspected = work_repository.inspect(item["workItemId"], now=NOW + timedelta(seconds=16))
            attempt = inspected["executionAttempts"][0]
            self.assertEqual(attempt["state"], "succeeded")
            self.assertEqual(attempt["executionRunState"], "outcome_committed")
            self.assertTrue(attempt["executionRunId"])
            self.assertTrue(attempt["effectValidationId"])

    def test_background_continuation_carries_and_finalizes_the_origin_run(self) -> None:
        from synapse_mcp.adapters.web import crawler_adapter

        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-background", hosts=["background.example"])
            arguments = {
                "workspaceId": "phase6c-background",
                "target": "https://background.example/",
                "disableTraffic": True,
                "maxPages": 1,
                "maxDepth": 0,
                "includeInScopeHosts": False,
                "analyzeScripts": False,
                "followGetForms": False,
                "background": True,
                "confirm": False,
            }
            def request(
                action_id: str,
                values: dict,
                correlation: str,
                *,
                idempotency_key: str = "phase6c-background-dispatch",
            ) -> ActionRequest:
                selected = REGISTRY.get(action_id)
                return ActionRequest(
                    selected.input_model.model_validate(values),
                    ExecutionContext(
                        "phase6c-background",
                        correlation,
                        45.0,
                        None,
                        execution_profile="full_delegated",
                        authority_session_id="phase6c-session",
                        selected_grant_id="grant-phase6c-background",
                        idempotency_key=idempotency_key,
                    ),
                )

            with patch.object(workspace, "timestamped_filename", side_effect=lambda suffix: f"fixed-{suffix}"):
                planning = request("crawler.crawl", arguments, "phase6c-background-correlation")
                plan = REGISTRY.resolve_execution_plan("crawler.crawl", planning)
                WorkspaceAuthorityRepository("phase6c-background").create_grant(
                    _grant(plan, grant_id="grant-phase6c-background")
                )
                with patch.object(crawler_adapter, "synapse_python", return_value=sys.executable):
                    started = REGISTRY.execute(
                        "crawler.crawl",
                        request("crawler.crawl", arguments, "phase6c-background-correlation"),
                    )
            self.assertIsInstance(started, Success)
            payload = started.payload.model_dump(mode="json", by_alias=True)
            job_id = payload["job"]["jobId"]
            authority = WorkspaceAuthorityRepository("phase6c-background")
            dispatch = authority.snapshot()["dispatches"]
            self.assertEqual(len(dispatch), 1)
            dispatch_value = next(iter(dispatch.values()))
            run_id = dispatch_value["executionRunId"]
            self.assertEqual(background_jobs.snapshot_record(job_id)["executionRunId"], run_id)
            self.assertEqual(authority.inspect_execution_run(run_id)["state"], "observing")

            terminal = None
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status_request = request(
                    "jobs.status",
                    {"jobId": job_id, "includeResult": True},
                    "phase6c-background-status",
                    idempotency_key="",
                )
                terminal = REGISTRY.execute("jobs.status", status_request)
                self.assertIsInstance(terminal, Success)
                status = terminal.payload.model_dump(mode="json", by_alias=True)["status"]
                if status in {"completed", "failed", "timed_out", "canceled"}:
                    break
                time.sleep(0.05)
            self.assertEqual(status, "completed")
            reconstructed = WorkspaceAuthorityRepository("phase6c-background")
            self.assertEqual(reconstructed.inspect_execution_run(run_id)["state"], "outcome_committed")
            self.assertEqual(
                reconstructed.inspect_execution_run(run_id)["identity"]["jobId"],
                job_id,
            )
            wait_for_job(job_id, require_runtime_quiescent=True)

    def test_thread_idempotency_reservation_creates_exactly_one_run(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-thread", hosts=["thread.example"])
            repository = WorkspaceAuthorityRepository("phase6c-thread", clock=lambda: NOW)
            plan = _plan("phase6c-thread")
            repository.create_grant(_grant(plan))
            barrier = threading.Barrier(4)
            results: list[str] = []
            lock = threading.Lock()

            def reserve() -> None:
                barrier.wait()
                try:
                    value = WorkspaceAuthorityRepository("phase6c-thread", clock=lambda: NOW).authorize(
                        plan,
                        risk_class=RiskClass.NONE,
                        profile="full_delegated",
                        authority_session_id="phase6c-session",
                        selected_grant_id="grant-phase6c",
                        idempotency_key="phase6c-shared",
                    )
                    outcome = f"run:{value.receipt.execution_run_id}"
                except AuthorityRepositoryError as exc:
                    outcome = exc.reason_code
                with lock:
                    results.append(outcome)

            threads = [threading.Thread(target=reserve) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertEqual(sum(item.startswith("run:") for item in results), 1, results)
            runtime = ActivatedWorkspaceRepository("phase6c-thread", workspace.workspace_path("phase6c-thread"))
            with runtime.connection_factory.connect() as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM execution_runs").fetchone()[0], 1)

    def test_process_idempotency_reservation_creates_exactly_one_run(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-process", hosts=["process.example"])
            repository = WorkspaceAuthorityRepository("phase6c-process", clock=lambda: NOW)
            plan = _plan("phase6c-process")
            repository.create_grant(_grant(plan))
            context = multiprocessing.get_context("fork")
            barrier = context.Barrier(2)
            output = context.Queue()
            processes = [
                context.Process(
                    target=_process_authorize,
                    args=(str(workspace.WORKSPACES_DIR), plan, barrier, output),
                )
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            values = [output.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(sum(item["kind"] == "allow" for item in values), 1, values)
            runtime = ActivatedWorkspaceRepository("phase6c-process", workspace.workspace_path("phase6c-process"))
            with runtime.connection_factory.connect() as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM execution_runs").fetchone()[0], 1)

    def test_bundle_round_trip_preserves_run_and_validation_references(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            root = Path(temporary)
            workspace.create_workspace("phase6c-bundle", hosts=["bundle.example"])
            repository = WorkspaceAuthorityRepository("phase6c-bundle", clock=lambda: NOW)
            plan = _plan("phase6c-bundle")
            repository.create_grant(_grant(plan))
            receipt = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase6c-session",
                selected_grant_id="grant-phase6c",
                idempotency_key="phase6c-bundle",
            ).receipt
            repository.mark_dispatched(receipt)
            repository.transition_dispatch(receipt.dispatch_id, "succeeded", outcome_kind="success")
            bundle = root / "bundle"
            service = StateBundleService(workspace.WORKSPACES_DIR.parent)
            service.export("phase6c-bundle", bundle)

            source_root = workspace.workspace_path("phase6c-bundle")
            moved = root / "source-workspace"
            source_root.rename(moved)
            imported = service.import_bundle(bundle)
            self.assertEqual(imported["workspaceId"], "phase6c-bundle")
            runtime = ActivatedWorkspaceRepository("phase6c-bundle", workspace.workspace_path("phase6c-bundle"))
            restored = runtime.inspect_execution_run(receipt.execution_run_id)
            self.assertEqual(restored["identity"]["dispatchId"], receipt.dispatch_id)
            self.assertEqual(restored["finalValidationId"], runtime.effect_validations(receipt.execution_run_id)[0]["validationId"])

    def test_json_v1_refuses_lifecycle_repository_without_migration(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="json-v1"):
            workspace.create_workspace("phase6c-json", hosts=["json.example"])
            with self.assertRaises(StateSelectionError) as raised:
                execution_lifecycle_repository("phase6c-json", workspace.WORKSPACES_DIR)
            self.assertEqual(raised.exception.reason_code, "execution_lifecycle_requires_sqlite_v2")
            self.assertFalse((workspace.workspace_path("phase6c-json") / "state-v2" / "state.sqlite3").exists())

    def test_migration_0006_is_ordered_and_installs_lifecycle_tables(self) -> None:
        self.assertEqual(MIGRATION_NAMES[-1], "0006_execution_lifecycle.sql")
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6c-schema", hosts=["schema.example"])
            runtime = ActivatedWorkspaceRepository("phase6c-schema", workspace.workspace_path("phase6c-schema"))
            with runtime.connection_factory.connect() as connection:
                apply_migrations(connection)
                tables = {
                    str(row[0])
                    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
            self.assertTrue({"execution_runs", "execution_observations", "effect_validations"}.issubset(tables))

    def test_migration_0006_upgrades_existing_v2_without_inventing_run_truth(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            with patch.object(state_migrations, "MIGRATION_NAMES", MIGRATION_NAMES[:-1]):
                workspace.create_workspace("phase6c-upgrade", hosts=["upgrade.example"])
                runtime = ActivatedWorkspaceRepository(
                    "phase6c-upgrade",
                    workspace.workspace_path("phase6c-upgrade"),
                )
                with runtime.connection_factory.connect() as connection:
                    state_migrations.apply_migrations(connection)
                    with immediate_transaction(connection):
                        connection.execute(
                            "INSERT INTO actions(action_id, workspace_id, action_name, state, payload_json, "
                            "created_revision, updated_revision, created_at, updated_at) "
                            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                "workspace.summary",
                                "phase6c-upgrade",
                                "workspace.summary",
                                "completed",
                                "{}",
                                1,
                                1,
                                "2026-09-01T09:00:00Z",
                                "2026-09-01T09:00:01Z",
                            ),
                        )
                        connection.execute(
                            "INSERT INTO action_dispatches(dispatch_id, workspace_id, action_id, state, "
                            "idempotency_key, payload_json, created_revision, updated_revision, created_at, updated_at) "
                            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                "dispatch-pre-6c",
                                "phase6c-upgrade",
                                "workspace.summary",
                                "succeeded",
                                "pre-6c",
                                '{"dispatchId":"dispatch-pre-6c","state":"succeeded"}',
                                1,
                                1,
                                "2026-09-01T09:00:00Z",
                                "2026-09-01T09:00:01Z",
                            ),
                        )

            with runtime.connection_factory.connect() as connection:
                apply_migrations(connection)
                dispatch = connection.execute(
                    "SELECT state, payload_json FROM action_dispatches WHERE dispatch_id='dispatch-pre-6c'"
                ).fetchone()
                migration = connection.execute(
                    "SELECT name FROM schema_migrations WHERE version=6"
                ).fetchone()
                run_count = connection.execute("SELECT count(*) FROM execution_runs").fetchone()[0]
            self.assertEqual(tuple(dispatch), ("succeeded", '{"dispatchId":"dispatch-pre-6c","state":"succeeded"}'))
            self.assertEqual(str(migration[0]), "0006_execution_lifecycle.sql")
            self.assertEqual(run_count, 0)


if __name__ == "__main__":
    unittest.main()
