"""Phase 6A.1 gates for durable work-linked execution attempts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import multiprocessing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state

from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core import workspace
from synapse_mcp.state import (
    ActivatedWorkspaceRepository,
    SQLiteWorkItemRepository,
    StateBundleService,
)
from synapse_mcp.state.errors import StateConflictError, StateStoreError


BASE_TIME = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


class _SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = iter(values)
        self._last = values[-1]

    def __call__(self) -> datetime:
        return next(self._values, self._last)


class _FailingFinalizer(WorkItemService):
    def finalize_execution_attempt(self, *args, **kwargs):
        raise StateStoreError(
            "fixture_result_commit_unknown",
            "The fixture simulates a crash after execution and before result linkage.",
        )


def _process_linked_action(
    workspaces_root: str,
    claim_id: str,
    ready: multiprocessing.Queue,
    start: multiprocessing.Event,
    output: multiprocessing.Queue,
) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    context = FacadeCallContext(
        principal_id="operator:test",
        workspace_id="phase6a",
        execution_profile="legacy",
        correlation_id=f"phase6a-process-{claim_id}",
    )
    facade = CompactFacadeService(
        work_items=WorkItemService(clock=lambda: BASE_TIME)
    )
    ready.put(claim_id)
    start.wait(timeout=10)
    result = facade.invoke(
        "actions.run_passive",
        {
            "actionId": "workspace.summary",
            "arguments": {"workspaceId": "phase6a"},
            "idempotencyKey": "phase6a-shared-dispatch",
            "workItem": {
                "workItemId": "work-process-dispatch",
                "claimId": claim_id,
            },
        },
        context=context,
    )
    output.put(
        {
            "outcomeKind": result.outcome_kind,
            "reasonCode": result.diagnostics.get("reasonCode", ""),
            "executionReference": (
                result.diagnostics.get("workItem", {}).get("executionReference", "")
            ),
        }
    )


class Phase6AWorkExecutionReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root, store_version="sqlite-v2")
        self.state.__enter__()
        self.addCleanup(self.state.__exit__, None, None, None)
        workspace.create_workspace("phase6a", hosts=["phase6a.example"])
        self.workspace_root = workspace.WORKSPACES_DIR / "phase6a"
        self.repository = SQLiteWorkItemRepository(
            ActivatedWorkspaceRepository("phase6a", self.workspace_root)
        )
        self.context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="phase6a",
            execution_profile="legacy",
            correlation_id="phase6a-test",
        )

    def _create_and_claim(self, *, identity: str, exclusive: bool = True):
        item = self.repository.create(
            {
                "workItemId": identity,
                "objective": "Exercise fictional offline work execution",
                "exclusive": exclusive,
            },
            principal_id="operator:test",
            now=BASE_TIME,
        )
        return self.repository.claim(
            identity,
            expected_version=item["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker="phase6a-worker",
            lease_seconds=15,
            now=BASE_TIME,
        )

    def _bind(self, claimed, *, key: str = "phase6a-attempt"):
        return self.repository.bind_execution_attempt(
            claimed["workItemId"],
            claim_id=claimed["claimId"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            action_id="workspace.summary",
            replay_safety="pure_read",
            idempotency_key=key,
            now=BASE_TIME,
        )

    def test_result_finalization_survives_claim_expiry_and_returns_latest_version(self) -> None:
        claimed = self._create_and_claim(identity="work-expiring-result")
        clock = _SequenceClock(
            BASE_TIME,
            BASE_TIME + timedelta(seconds=1),
            BASE_TIME + timedelta(seconds=16),
        )
        facade = CompactFacadeService(work_items=WorkItemService(clock=clock))

        result = facade.invoke(
            "actions.run_passive",
            {
                "actionId": "workspace.summary",
                "arguments": {"workspaceId": "phase6a"},
                "idempotencyKey": "phase6a-expiring-result",
                "workItem": {
                    "workItemId": claimed["workItemId"],
                    "claimId": claimed["claimId"],
                },
            },
            context=self.context,
        )

        self.assertEqual(result.outcome_kind, "success")
        work_link = result.diagnostics["workItem"]
        inspected = self.repository.inspect(claimed["workItemId"])
        self.assertEqual(work_link["version"], inspected["version"])
        self.assertEqual(work_link["executionReference"], inspected["executionAttempts"][0]["executionReference"])
        self.assertEqual(inspected["executionAttempts"][0]["state"], "succeeded")
        self.assertEqual(inspected["references"][0]["executionState"], "success")
        self.assertFalse(inspected["executionReviewRequired"])

    def test_crash_boundaries_classify_bound_attempts_and_never_replay(self) -> None:
        unbound = self._create_and_claim(identity="work-before-binding")
        self.repository.recover(
            principal_id="operator:test",
            work_item_id=unbound["workItemId"],
            now=BASE_TIME + timedelta(seconds=16),
        )
        self.assertFalse(self.repository.inspect(unbound["workItemId"])["executionReviewRequired"])

        planned = self._create_and_claim(identity="work-after-binding")
        planned_attempt = self._bind(planned, key="phase6a-planned")
        self.repository.recover(
            principal_id="operator:test",
            work_item_id=planned["workItemId"],
            now=BASE_TIME + timedelta(seconds=16),
        )
        planned_state = self.repository.inspect(planned["workItemId"])
        self.assertEqual(planned_state["executionAttempts"][0]["state"], "planned")
        self.assertTrue(planned_state["executionReviewRequired"])
        self.assertEqual(len(planned_state["activeOrUnknownExecution"]), 1)
        with self.assertRaises(StateConflictError) as planned_replay:
            replacement = self.repository.claim(
                planned["workItemId"],
                expected_version=planned_state["version"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                worker="replacement",
                lease_seconds=60,
                now=BASE_TIME + timedelta(seconds=17),
            )
            self.repository.bind_execution_attempt(
                planned["workItemId"],
                claim_id=replacement["claimId"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                action_id="workspace.summary",
                replay_safety="pure_read",
                idempotency_key="phase6a-replay",
                now=BASE_TIME + timedelta(seconds=17),
            )
        self.assertEqual(planned_replay.exception.reason_code, "work_item_execution_reconciliation_required")
        self.assertEqual(
            planned_replay.exception.details["executionReference"],
            planned_attempt["executionReference"],
        )

        started = self._create_and_claim(identity="work-after-dispatch-start")
        started_attempt = self._bind(started, key="phase6a-started")
        self.repository.start_execution_attempt(
            started_attempt["executionReference"],
            principal_id="operator:test",
            authority_session_id="",
            now=BASE_TIME + timedelta(seconds=1),
        )
        self.repository.recover(
            principal_id="operator:test",
            work_item_id=started["workItemId"],
            now=BASE_TIME + timedelta(seconds=16),
        )
        started_state = self.repository.inspect(started["workItemId"])
        self.assertEqual(started_state["executionAttempts"][0]["state"], "started")
        self.assertTrue(started_state["executionReviewRequired"])
        self.assertEqual(len(started_state["activeOrUnknownExecution"]), 1)
        self.assertFalse(started_state["automaticReplay"])

    def test_pre_attempt_active_reference_remains_reconciliation_required(self) -> None:
        claimed = self._create_and_claim(identity="work-legacy-active-execution")
        linked = self.repository.link_execution(
            claimed["workItemId"],
            claim_id=claimed["claimId"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            references=[
                {
                    "type": "action",
                    "id": "workspace.summary",
                    "state": "active",
                    "replaySafety": "pure_read",
                }
            ],
            event_type="work_item.execution_linked",
            now=BASE_TIME + timedelta(seconds=1),
        )

        with self.assertRaises(StateConflictError) as replay:
            self.repository.bind_execution_attempt(
                claimed["workItemId"],
                claim_id=claimed["claimId"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                action_id="workspace.summary",
                replay_safety="pure_read",
                idempotency_key="phase6a-legacy-replay",
                now=BASE_TIME + timedelta(seconds=2),
            )

        self.assertEqual(replay.exception.reason_code, "work_item_execution_reconciliation_required")
        self.assertEqual(replay.exception.details["executionState"], "active")
        self.assertEqual(self.repository.inspect(claimed["workItemId"])["version"], linked["version"])

    def test_success_before_result_commit_returns_durable_unknown_reference(self) -> None:
        claimed = self._create_and_claim(identity="work-result-commit-crash")
        service = _FailingFinalizer(clock=lambda: BASE_TIME)
        facade = CompactFacadeService(work_items=service)

        result = facade.invoke(
            "actions.run_passive",
            {
                "actionId": "workspace.summary",
                "arguments": {"workspaceId": "phase6a"},
                "idempotencyKey": "phase6a-result-commit-crash",
                "workItem": {
                    "workItemId": claimed["workItemId"],
                    "claimId": claimed["claimId"],
                },
            },
            context=self.context,
        )

        self.assertEqual(result.outcome_kind, "execution_unknown")
        self.assertEqual(result.diagnostics["priorOutcomeKind"], "success")
        execution_reference = result.diagnostics["workItem"]["executionReference"]
        inspected = self.repository.inspect(claimed["workItemId"])
        self.assertEqual(inspected["executionAttempts"][0]["executionReference"], execution_reference)
        self.assertEqual(inspected["executionAttempts"][0]["state"], "started")
        self.assertTrue(inspected["executionReviewRequired"])

    def test_recovery_before_late_result_does_not_orphan_finalization(self) -> None:
        claimed = self._create_and_claim(identity="work-recovered-before-result")
        attempt = self._bind(claimed, key="phase6a-late-result")
        self.repository.start_execution_attempt(
            attempt["executionReference"],
            principal_id="operator:test",
            authority_session_id="",
            now=BASE_TIME + timedelta(seconds=1),
        )
        recovered = self.repository.recover(
            principal_id="operator:test",
            work_item_id=claimed["workItemId"],
            now=BASE_TIME + timedelta(seconds=16),
        )
        finalized = self.repository.finalize_execution_attempt(
            attempt["executionReference"],
            principal_id="operator:test",
            authority_session_id="",
            outcome_kind="success",
            state="succeeded",
            references=[
                {
                    "type": "action",
                    "id": "workspace.summary",
                    "state": "success",
                    "replaySafety": "pure_read",
                }
            ],
            now=BASE_TIME + timedelta(seconds=17),
        )

        self.assertEqual(recovered["recoveredWorkItemIds"], [claimed["workItemId"]])
        self.assertEqual(finalized["status"], "available")
        self.assertEqual(finalized["executionAttempts"][0]["state"], "succeeded")
        self.assertFalse(finalized["executionReviewRequired"])
        self.assertEqual(finalized["executionReference"], attempt["executionReference"])

    def test_attempt_start_and_finalization_preserve_trusted_identity_binding(self) -> None:
        claimed = self._create_and_claim(identity="work-attempt-binding")
        attempt = self._bind(claimed, key="phase6a-bound-identity")
        with self.assertRaises(StateConflictError) as principal:
            self.repository.start_execution_attempt(
                attempt["executionReference"],
                principal_id="operator:other",
                authority_session_id="",
                now=BASE_TIME + timedelta(seconds=1),
            )
        self.assertEqual(principal.exception.reason_code, "work_item_execution_principal_mismatch")

        started = self.repository.start_execution_attempt(
            attempt["executionReference"],
            principal_id="operator:test",
            authority_session_id="",
            now=BASE_TIME + timedelta(seconds=1),
        )
        with self.assertRaises(StateConflictError) as session:
            self.repository.finalize_execution_attempt(
                attempt["executionReference"],
                principal_id="operator:test",
                authority_session_id="other-session",
                outcome_kind="success",
                state="succeeded",
                references=[],
                now=BASE_TIME + timedelta(seconds=2),
            )
        self.assertEqual(session.exception.reason_code, "work_item_execution_session_mismatch")
        self.assertEqual(
            self.repository.inspect(claimed["workItemId"])["version"],
            started["version"],
        )

    def test_two_processes_get_one_bound_attempt_and_one_dispatch_winner(self) -> None:
        first = self._create_and_claim(identity="work-process-dispatch", exclusive=False)
        second = self.repository.claim(
            first["workItemId"],
            expected_version=first["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker="phase6a-worker-two",
            lease_seconds=60,
            now=BASE_TIME,
        )
        claim_ids = [first["claimId"], second["claimId"]]
        process_context = multiprocessing.get_context("spawn")
        ready = process_context.Queue()
        output = process_context.Queue()
        start = process_context.Event()
        processes = [
            process_context.Process(
                target=_process_linked_action,
                args=(str(workspace.WORKSPACES_DIR), claim_id, ready, start, output),
            )
            for claim_id in claim_ids
        ]
        for process in processes:
            process.start()
        for _process in processes:
            ready.get(timeout=10)
        start.set()
        for process in processes:
            process.join(timeout=20)
            self.assertEqual(process.exitcode, 0)
        results = [output.get(timeout=5) for _process in processes]

        self.assertEqual(sum(item["outcomeKind"] == "success" for item in results), 1)
        loser = next(item for item in results if item["outcomeKind"] != "success")
        self.assertEqual(loser["reasonCode"], "work_item_execution_reconciliation_required")
        inspected = self.repository.inspect(first["workItemId"])
        self.assertEqual(len(inspected["executionAttempts"]), 1)
        self.assertEqual(inspected["executionAttempts"][0]["state"], "succeeded")

    def test_bundle_round_trip_preserves_bound_attempt_identity_and_state(self) -> None:
        claimed = self._create_and_claim(identity="work-attempt-bundle")
        attempt = self._bind(claimed, key="phase6a-bundle-attempt")
        self.repository.start_execution_attempt(
            attempt["executionReference"],
            principal_id="operator:test",
            authority_session_id="",
            now=BASE_TIME + timedelta(seconds=1),
        )
        bundle = self.root / "phase6a-bundle"
        exported = StateBundleService(self.root).export("phase6a", bundle)

        with TemporaryDirectory() as imported_root:
            imported = StateBundleService(Path(imported_root)).import_bundle(bundle)
            restored = SQLiteWorkItemRepository(
                ActivatedWorkspaceRepository(
                    "phase6a",
                    Path(imported_root) / "workspaces" / "phase6a",
                )
            ).inspect(claimed["workItemId"])

        self.assertEqual(imported["contentDigest"], exported["contentDigest"])
        self.assertEqual(
            restored["executionAttempts"][0]["executionReference"],
            attempt["executionReference"],
        )
        self.assertEqual(restored["executionAttempts"][0]["state"], "started")
        self.assertTrue(restored["executionReviewRequired"])


if __name__ == "__main__":
    unittest.main()
