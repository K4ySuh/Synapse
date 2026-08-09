from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

from helpers import isolated_state
from synapse_mcp.app.actions import (
    ActionRequest,
    ExecutionContext,
    REGISTRY,
    RiskClass,
)
from synapse_mcp.core import workspace
from synapse_mcp.policy import (
    Allow,
    ApprovalRequired,
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    AuthorityRepositoryError,
    AuthorityRevisionConflict,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
    WorkspaceAuthorityRepository,
)


NOW = datetime(2026, 8, 9, 20, 0, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _plan(workspace_id: str = "authority"):
    descriptor = REGISTRY.get("workspace.summary")
    request = ActionRequest(
        descriptor.input_model.model_validate({"workspaceId": workspace_id}),
        ExecutionContext(workspace_id, "repository-test", 45.0, None),
    )
    return REGISTRY.resolve_execution_plan("workspace.summary", request)


def _grant(plan, *, limit: int | None = None, grant_id: str = "grant-repository") -> AuthorityGrant:
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
        budgets=BudgetLimits(limit, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        approved_by="operator:test",
    )


class AuthorityRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.state = isolated_state(Path(self.tmp.name))
        self.state.__enter__()
        workspace.create_workspace("authority", hosts=["a.example"])
        self.clock = MutableClock(NOW)
        self.repository = WorkspaceAuthorityRepository("authority", clock=self.clock)
        self.plan = _plan()

    def tearDown(self) -> None:
        self.state.__exit__(None, None, None)
        self.tmp.cleanup()

    def test_private_atomic_schema_and_revision_history(self) -> None:
        grant = self.repository.create_grant(_grant(self.plan))
        self.assertEqual(os.stat(self.repository.path).st_mode & 0o777, 0o600)
        snapshot = self.repository.snapshot()
        self.assertEqual(snapshot["schemaVersion"], 1)
        self.assertEqual(snapshot["revision"], 1)
        revised = replace(grant, revision=2, expires_at=grant.expires_at + timedelta(hours=1))
        self.repository.revise_grant(revised, expected_grant_revision=1)
        snapshot = self.repository.snapshot()
        self.assertEqual(set(snapshot["grants"][grant.grant_id]["revisions"]), {"1", "2"})
        with self.assertRaises(AuthorityRevisionConflict):
            self.repository.revise_grant(replace(revised, revision=3), expected_grant_revision=1)

    def test_authorize_reserves_atomically_and_transitions_legally(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=1))
        result = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="first",
        )
        self.assertIsInstance(result.decision, Allow)
        self.assertIsNotNone(result.receipt)
        dispatch = self.repository.inspect_dispatch(result.receipt.dispatch_id)
        self.assertEqual(dispatch["state"], "authorized")
        self.assertEqual(self.repository.budget_usage("grant-repository").dispatches_used, 1)
        self.repository.mark_dispatched(result.receipt)
        self.repository.transition_dispatch(result.receipt.dispatch_id, "succeeded")
        self.assertEqual(self.repository.budget_usage("grant-repository").active_dispatches, 0)

    def test_concurrent_budget_reservation_has_one_winner(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=1))
        barrier = threading.Barrier(2)

        def authorize(number: int):
            barrier.wait()
            return WorkspaceAuthorityRepository("authority", clock=self.clock).authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="repository-session",
                selected_grant_id="grant-repository",
                idempotency_key=f"concurrent-{number}",
            ).decision

        with ThreadPoolExecutor(max_workers=2) as pool:
            decisions = list(pool.map(authorize, (1, 2)))
        self.assertEqual(sum(isinstance(item, Allow) for item in decisions), 1)
        self.assertEqual(sum(isinstance(item, ApprovalRequired) for item in decisions), 1)
        self.assertEqual(self.repository.budget_usage("grant-repository").dispatches_used, 1)

    def test_crash_boundaries_survive_restart_and_unknown_is_not_replayed(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=4))
        before = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="before-dispatch",
        )
        restarted = WorkspaceAuthorityRepository("authority", clock=self.clock)
        self.assertEqual(restarted.inspect_dispatch(before.receipt.dispatch_id)["state"], "authorized")
        restarted.mark_dispatched(before.receipt)
        restarted.transition_dispatch(before.receipt.dispatch_id, "unknown")
        with self.assertRaisesRegex(AuthorityRepositoryError, "will not be replayed") as raised:
            restarted.authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="repository-session",
                selected_grant_id="grant-repository",
                idempotency_key="before-dispatch",
            )
        self.assertEqual(raised.exception.reason_code, "dispatch_reconciliation_required")

    def test_explicit_idempotent_retry_links_failed_dispatch(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=3))
        first = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="retry-key",
        )
        self.repository.mark_dispatched(first.receipt)
        self.repository.transition_dispatch(first.receipt.dispatch_id, "failed")
        second = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="retry-key",
        )
        self.assertNotEqual(first.receipt.dispatch_id, second.receipt.dispatch_id)
        self.assertEqual(
            self.repository.inspect_dispatch(second.receipt.dispatch_id)["priorDispatchId"],
            first.receipt.dispatch_id,
        )

    def test_operator_cancels_authorized_and_reconciles_unknown_dispatches(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=3))
        principal = OperatorPrincipal("operator:test", "test_fixture", True)
        service = AuthorityOperatorService("authority", principal)

        reserved = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="cancel-reservation",
        )
        cancelled = service.reconcile_or_cancel_dispatch(reserved.receipt.dispatch_id, "cancelled")
        self.assertEqual(cancelled["state"], "cancelled")

        uncertain = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="unknown-dispatch",
        )
        self.repository.mark_dispatched(uncertain.receipt)
        self.repository.transition_dispatch(uncertain.receipt.dispatch_id, "unknown")
        before_revision = self.repository.inspect_dispatch(uncertain.receipt.dispatch_id)["revision"]
        reconciled = service.reconcile_or_cancel_dispatch(uncertain.receipt.dispatch_id, "failed")
        self.assertEqual(reconciled["state"], "unknown")
        self.assertEqual(reconciled["reconciliation"]["resolution"], "failed")
        self.assertEqual(reconciled["revision"], before_revision + 1)
        self.assertTrue(
            any(
                item.get("kind") == "dispatch_reconciled"
                and item.get("dispatchId") == uncertain.receipt.dispatch_id
                for item in self.repository.snapshot()["decisions"]
            )
        )
        self.assertEqual(self.repository.budget_usage("grant-repository").active_dispatches, 0)

    def test_revocation_is_immediate_but_history_remains(self) -> None:
        grant = self.repository.create_grant(_grant(self.plan))
        revoked = self.repository.revoke_grant(grant.grant_id, expected_grant_revision=1, revoked_at=NOW)
        self.assertEqual(revoked.revision, 2)
        result = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id=grant.grant_id,
        )
        self.assertIsInstance(result.decision, ApprovalRequired)
        self.assertEqual(str(result.decision.reason), "grant_revoked")
        self.assertEqual(self.repository.inspect_grant(grant.grant_id, 1).revoked_at, None)

    def test_revocation_and_authorization_race_is_serialized(self) -> None:
        self.repository.create_grant(_grant(self.plan, limit=2))
        barrier = threading.Barrier(2)

        def authorize():
            barrier.wait()
            return WorkspaceAuthorityRepository("authority", clock=self.clock).authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="repository-session",
                selected_grant_id="grant-repository",
                idempotency_key="revocation-race",
            ).decision

        def revoke():
            barrier.wait()
            return WorkspaceAuthorityRepository("authority", clock=self.clock).revoke_grant(
                "grant-repository",
                expected_grant_revision=1,
                revoked_at=NOW,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            authorization_future = pool.submit(authorize)
            revocation_future = pool.submit(revoke)
            decision = authorization_future.result()
            revoked = revocation_future.result()
        self.assertEqual(revoked.revision, 2)
        if isinstance(decision, Allow):
            dispatch = self.repository.list_dispatches()[0]
            self.assertEqual(dispatch["grantRevision"], 1)
        else:
            self.assertIsInstance(decision, ApprovalRequired)
            self.assertEqual(str(decision.reason), "grant_revoked")

    def test_result_commit_survives_process_restart(self) -> None:
        self.repository.create_grant(_grant(self.plan))
        allowed = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
        )
        self.repository.mark_dispatched(allowed.receipt)
        self.repository.transition_dispatch(allowed.receipt.dispatch_id, "succeeded")
        restarted = WorkspaceAuthorityRepository("authority", clock=self.clock)
        self.assertEqual(restarted.inspect_dispatch(allowed.receipt.dispatch_id)["state"], "succeeded")
        self.assertEqual(restarted.budget_usage("grant-repository").active_dispatches, 0)

    def test_opaque_request_state_expires_and_contains_no_arguments(self) -> None:
        denied = self.repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
        )
        self.assertIsInstance(denied.decision, ApprovalRequired)
        request_state_id = denied.decision.request_state_id
        serialized = self.repository.snapshot()["requestStates"][request_state_id]
        self.assertNotIn("arguments", serialized)
        self.assertNotIn("requestBody", serialized)
        with self.assertRaisesRegex(AuthorityRepositoryError, "does not match"):
            self.repository.authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="different-session",
                request_state_id=request_state_id,
            )
        self.clock.value = NOW + timedelta(minutes=16)
        with self.assertRaisesRegex(AuthorityRepositoryError, "unknown|expired"):
            self.repository.authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="repository-session",
                request_state_id=request_state_id,
            )

    def test_compaction_bounds_ephemeral_state_but_preserves_unresolved_dispatch(self) -> None:
        repository = WorkspaceAuthorityRepository("authority", clock=self.clock, decision_retention=3)
        repository.create_grant(_grant(self.plan, limit=10))
        allowed = repository.authorize(
            self.plan,
            risk_class=RiskClass.NONE,
            profile="full_delegated",
            authority_session_id="repository-session",
            selected_grant_id="grant-repository",
            idempotency_key="unresolved",
        )
        repository.mark_dispatched(allowed.receipt)
        for _ in range(8):
            repository.authorize(
                self.plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="repository-session",
            )
        snapshot = repository.snapshot()
        self.assertLessEqual(len(snapshot["requestStates"]), 3)
        self.assertIn(allowed.receipt.dispatch_id, snapshot["dispatches"])
        self.assertTrue(any(item.get("dispatchId") == allowed.receipt.dispatch_id for item in snapshot["decisions"]))

    def test_corrupt_and_unsupported_files_fail_closed_without_rewrite(self) -> None:
        self.repository.path.parent.mkdir(parents=True, exist_ok=True)
        self.repository.path.write_text("{broken", encoding="utf-8")
        before = self.repository.path.read_bytes()
        with self.assertRaisesRegex(AuthorityRepositoryError, "corrupt"):
            self.repository.snapshot()
        self.assertEqual(self.repository.path.read_bytes(), before)
        self.repository.path.write_text('{"schemaVersion":999}', encoding="utf-8")
        unsupported = self.repository.path.read_bytes()
        with self.assertRaisesRegex(AuthorityRepositoryError, "unsupported"):
            self.repository.snapshot()
        self.assertEqual(self.repository.path.read_bytes(), unsupported)


if __name__ == "__main__":
    unittest.main()
