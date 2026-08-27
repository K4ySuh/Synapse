"""Phase 5C gates for shared operational work items and specialist recovery."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import multiprocessing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state

from synapse_mcp.app.facade import CompactFacadeService, CompactProjection, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core import workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository, StateBundleService
from synapse_mcp.state.errors import StateConflictError
from synapse_mcp.state.migrations import migration_hash, migration_text
from synapse_mcp.state.selector import selected_store_version


BASE_TIME = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _process_claim(workspace_root: str, output: multiprocessing.Queue, worker: str) -> None:
    repository = SQLiteWorkItemRepository(
        ActivatedWorkspaceRepository("phase5c", Path(workspace_root))
    )
    try:
        result = repository.claim(
            "work-race",
            expected_version=1,
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker=worker,
            lease_seconds=60,
            now=BASE_TIME,
        )
        output.put(("success", result["claimId"], result["version"]))
    except StateConflictError as exc:
        output.put((exc.reason_code, exc.details.get("currentVersion"), exc.details.get("currentWorkspaceRevision")))


class Phase5CWorkItemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root, store_version="sqlite-v2")
        self.state.__enter__()
        self.addCleanup(self.state.__exit__, None, None, None)
        workspace.create_workspace("phase5c", hosts=["phase5c.example"])
        self.workspace_root = workspace.WORKSPACES_DIR / "phase5c"
        self.activated = ActivatedWorkspaceRepository("phase5c", self.workspace_root)
        self.repository = SQLiteWorkItemRepository(self.activated)
        self.context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="phase5c",
            execution_profile="legacy",
            correlation_id="phase5c-test",
        )
        self.work_items = WorkItemService(clock=lambda: BASE_TIME)
        self.facade = CompactFacadeService(work_items=self.work_items)

    def create(self, **values):
        return self.repository.create(
            {"objective": "Analyze fictional offline context", **values},
            principal_id="operator:test",
            now=BASE_TIME,
        )

    def claim(self, item, *, worker="worker-a", now=BASE_TIME, expected_version=None):
        return self.repository.claim(
            item["workItemId"],
            expected_version=int(expected_version or item["version"]),
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker=worker,
            lease_seconds=60,
            now=now,
        )

    def transition(self, item, claim_id, operation, **values):
        return self.repository.transition(
            item["workItemId"],
            values,
            operation=operation,
            claim_id=claim_id,
            expected_version=item["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            now=BASE_TIME,
        )

    def test_compact_facade_lifecycle_is_typed_and_legacy_job_operations_remain_valid(self) -> None:
        created = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.create",
                "workspaceId": "phase5c",
                "payload": {
                    "objective": "Inventory fictional perimeter context",
                    "role": "perimeter",
                    "requiredPacks": ["infra"],
                    "targets": ["phase5c.example"],
                    "completionContract": {"evidence": "one bounded inventory"},
                },
            },
            context=self.context,
        )
        self.assertEqual(created.outcome_kind, "success")
        claimed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.claim",
                "workspaceId": "phase5c",
                "workItemId": created.result["workItemId"],
                "expectedVersion": 1,
                "worker": "specialist-a",
            },
            context=self.context,
        )
        self.assertEqual(claimed.outcome_kind, "success")
        updated = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.update",
                "workspaceId": "phase5c",
                "workItemId": created.result["workItemId"],
                "claimId": claimed.result["claimId"],
                "expectedVersion": claimed.result["version"],
                "payload": {"progressSummary": "Offline inventory complete."},
            },
            context=self.context,
        )
        completed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.complete",
                "workspaceId": "phase5c",
                "workItemId": created.result["workItemId"],
                "claimId": claimed.result["claimId"],
                "expectedVersion": updated.result["version"],
                "payload": {"resultSummary": "Inventory recorded with no active traffic."},
            },
            context=self.context,
        )
        self.assertEqual(completed.result["status"], "completed")
        listed = self.facade.invoke(
            "tasks.control",
            {"operation": "work.list", "workspaceId": "phase5c", "payload": {"statuses": ["completed"]}},
            context=self.context,
        )
        self.assertEqual(listed.result["count"], 1)
        legacy_list = self.facade.invoke(
            "tasks.control",
            {"operation": "list", "workspaceId": "phase5c", "activeOnly": True},
            context=self.context,
        )
        self.assertNotEqual(legacy_list.diagnostics.get("reasonCode"), "work_item_operation_invalid")

    def test_existing_two_migration_database_upgrades_in_place_to_work_items(self) -> None:
        root = self.root / "workspaces" / "upgrade-v2"
        database = root / "state-v2" / "state.sqlite3"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        try:
            connection.executescript(migration_text("0001_initial.sql"))
            connection.executescript(migration_text("0002_runtime_adoption.sql"))
            for version, name in enumerate(("0001_initial.sql", "0002_runtime_adoption.sql"), start=1):
                connection.execute(
                    "INSERT INTO schema_migrations(version, name, schema_hash) VALUES(?, ?, ?)",
                    (version, name, migration_hash(name)),
                )
            old_manifest = "\n".join(
                f"{name}:{migration_hash(name)}" for name in ("0001_initial.sql", "0002_runtime_adoption.sql")
            )
            connection.execute(
                "INSERT INTO store_metadata(key, value) VALUES('schema_hash', ?)",
                (sha256(old_manifest.encode("utf-8")).hexdigest(),),
            )
            connection.execute(
                "INSERT INTO store_metadata(key, value) VALUES('store_version', 'sqlite-v2')"
            )
            connection.execute(
                "INSERT INTO workspaces(workspace_id, created_at, updated_at) VALUES('upgrade-v2', ?, ?)",
                (BASE_TIME.isoformat(), BASE_TIME.isoformat()),
            )
            connection.execute(
                "INSERT INTO workspace_revisions(workspace_id, revision, updated_at) VALUES('upgrade-v2', 1, ?)",
                (BASE_TIME.isoformat(),),
            )
            connection.commit()
        finally:
            connection.close()
        upgraded = ActivatedWorkspaceRepository("upgrade-v2", root)
        self.assertEqual(upgraded.revision(), 1)
        with upgraded.connection_factory.connect() as checked:
            self.assertIsNotNone(
                checked.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='work_items'").fetchone()
            )
            self.assertEqual(int(checked.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]), 3)

    def test_two_processes_race_for_one_exclusive_claim_and_exactly_one_wins(self) -> None:
        self.repository.create(
            {"workItemId": "work-race", "objective": "Exclusive fictional analysis"},
            principal_id="operator:test",
            now=BASE_TIME,
        )
        process_context = multiprocessing.get_context("spawn")
        output = process_context.Queue()
        processes = [
            process_context.Process(
                target=_process_claim,
                args=(str(self.workspace_root), output, f"worker-{index}"),
            )
            for index in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=20)
            self.assertEqual(process.exitcode, 0)
        results = [output.get(timeout=5) for _process in processes]
        self.assertEqual(sum(result[0] == "success" for result in results), 1)
        loser = next(result for result in results if result[0] != "success")
        self.assertIn(loser[0], {"work_item_version_conflict", "work_item_already_claimed"})
        self.assertEqual(len([claim for claim in self.repository.inspect("work-race")["claims"] if claim["state"] == "active"]), 1)

    def test_nonexclusive_analysis_accepts_independent_active_claims(self) -> None:
        item = self.create(exclusive=False)
        first = self.claim(item, worker="analysis-a")
        second = self.claim(first, worker="analysis-b")
        active = [claim for claim in second["claims"] if claim["state"] == "active"]
        self.assertEqual({claim["worker"] for claim in active}, {"analysis-a", "analysis-b"})

    def test_stale_version_returns_current_version_and_workspace_revision(self) -> None:
        item = self.create()
        claimed = self.claim(item)
        with self.assertRaises(StateConflictError) as future:
            self.repository.update(
                item["workItemId"],
                {"lastSeenWorkspaceRevision": claimed["currentWorkspaceRevision"] + 1},
                claim_id=claimed["claimId"],
                expected_version=claimed["version"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                now=BASE_TIME,
            )
        self.assertEqual(future.exception.reason_code, "work_item_revision_future")
        self.assertEqual(future.exception.details["currentVersion"], claimed["version"])
        with self.assertRaises(StateConflictError) as conflict:
            self.repository.heartbeat(
                item["workItemId"],
                claim_id=claimed["claimId"],
                expected_version=1,
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                lease_seconds=60,
                now=BASE_TIME,
            )
        self.assertEqual(conflict.exception.reason_code, "work_item_version_conflict")
        self.assertEqual(conflict.exception.details["currentVersion"], 2)
        self.assertGreaterEqual(conflict.exception.details["currentWorkspaceRevision"], 3)

    def test_heartbeat_renews_only_the_matching_active_claim(self) -> None:
        item = self.create()
        claimed = self.claim(item)
        renewed = self.repository.heartbeat(
            item["workItemId"],
            claim_id=claimed["claimId"],
            expected_version=claimed["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            lease_seconds=120,
            now=BASE_TIME + timedelta(seconds=10),
        )
        self.assertEqual(renewed["version"], 3)
        with self.assertRaises(StateConflictError) as mismatched:
            self.repository.heartbeat(
                item["workItemId"],
                claim_id=claimed["claimId"],
                expected_version=renewed["version"],
                principal_id="operator:other",
                authority_session_id="",
                agent_run_id="",
                lease_seconds=120,
                now=BASE_TIME + timedelta(seconds=20),
            )
        self.assertEqual(mismatched.exception.reason_code, "work_item_claim_principal_mismatch")

    def test_lease_recovery_preserves_unknown_execution_and_never_replays_it(self) -> None:
        item = self.create()
        claimed = self.claim(item)
        linked = self.repository.link_execution(
            item["workItemId"],
            claim_id=claimed["claimId"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            references=[
                {"type": "dispatch", "id": "dispatch-unknown", "state": "unknown", "replaySafety": "non_idempotent"}
            ],
            event_type="work_item.execution_result",
            now=BASE_TIME,
        )
        recovered = self.repository.recover(
            principal_id="operator:test",
            work_item_id=item["workItemId"],
            now=BASE_TIME + timedelta(seconds=61),
        )
        self.assertEqual(recovered["recoveredWorkItemIds"], [item["workItemId"]])
        inspected = self.repository.inspect(item["workItemId"])
        self.assertEqual(inspected["status"], "available")
        self.assertTrue(inspected["executionReviewRequired"])
        self.assertFalse(inspected["automaticReplay"])
        self.assertEqual(inspected["activeOrUnknownExecution"][0]["id"], "dispatch-unknown")
        reclaimed = self.claim(inspected, worker="recovery-agent", now=BASE_TIME + timedelta(seconds=62))
        self.assertTrue(reclaimed["executionReviewRequired"])
        with self.assertRaises(StateConflictError) as stale:
            self.repository.transition(
                item["workItemId"],
                {"resultSummary": "stale claimant result"},
                operation="complete",
                claim_id=claimed["claimId"],
                expected_version=reclaimed["version"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                now=BASE_TIME + timedelta(seconds=63),
            )
        self.assertEqual(stale.exception.reason_code, "work_item_claim_inactive")
        self.assertGreater(linked["version"], claimed["version"])

    def test_concurrent_execution_links_merge_without_lost_references(self) -> None:
        item = self.create()
        claimed = self.claim(item)

        def link(identity: str):
            return self.repository.link_execution(
                item["workItemId"],
                claim_id=claimed["claimId"],
                principal_id="operator:test",
                authority_session_id="",
                agent_run_id="",
                references=[{"type": "operation", "id": identity, "state": "completed"}],
                event_type="work_item.execution_result",
                now=BASE_TIME,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(link, ("operation-a", "operation-b")))
        self.assertEqual(len(results), 2)
        final = self.repository.inspect(item["workItemId"])
        self.assertEqual(final["version"], 4)
        references = final["references"]
        self.assertEqual({item["id"] for item in references}, {"operation-a", "operation-b"})

    def test_dependencies_unlock_downstream_exactly_once(self) -> None:
        first = self.create(workItemId="work-dependency-a")
        second = self.create(workItemId="work-dependency-b")
        downstream = self.create(
            workItemId="work-downstream",
            dependencyIds=[first["workItemId"], second["workItemId"]],
        )
        self.assertEqual(downstream["status"], "planned")
        first_claim = self.claim(first, worker="first")
        self.transition(first_claim, first_claim["claimId"], "complete", resultSummary="first complete")
        self.assertEqual(self.repository.inspect("work-downstream")["status"], "planned")
        second_claim = self.claim(second, worker="second")
        self.transition(second_claim, second_claim["claimId"], "complete", resultSummary="second complete")
        unlocked = self.repository.inspect("work-downstream")
        self.assertEqual(unlocked["status"], "available")
        with self.activated.connection_factory.connect() as connection:
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM work_item_events WHERE workspace_id='phase5c' "
                    "AND work_item_id='work-downstream' AND event_type='work_item.dependencies_completed'"
                ).fetchone()[0]
            )
        self.assertEqual(count, 1)

    def test_blocked_and_failed_dependency_states_remain_visible(self) -> None:
        blocked = self.create(workItemId="work-blocked-parent")
        blocked_claim = self.claim(blocked)
        self.transition(blocked_claim, blocked_claim["claimId"], "block", reason="Missing operator-reviewed input")
        blocked_child = self.create(workItemId="work-blocked-child", dependencyIds=[blocked["workItemId"]])
        self.assertEqual(blocked_child["dependencyStates"][blocked["workItemId"]], "blocked")
        failed = self.create(workItemId="work-failed-parent")
        failed_claim = self.claim(failed)
        self.transition(
            failed_claim,
            failed_claim["claimId"],
            "complete",
            status="failed",
            resultSummary="Deterministic offline analysis failed.",
        )
        failed_child = self.create(workItemId="work-failed-child", dependencyIds=[failed["workItemId"]])
        self.assertEqual(failed_child["dependencyStates"][failed["workItemId"]], "failed")
        self.assertEqual(failed_child["status"], "planned")

    def test_restart_reconstructs_dependencies_claims_leases_and_handoffs(self) -> None:
        parent = self.create(workItemId="work-parent")
        child = self.create(workItemId="work-child", parentWorkItemId=parent["workItemId"], dependencyIds=[parent["workItemId"]])
        parent_claim = self.claim(parent, worker="coordinator")
        handed_off = self.transition(
            parent_claim,
            parent_claim["claimId"],
            "handoff",
            reason="Specialist review requested",
            completedWork="Initial triage",
            outstandingWork="Independent validation",
            assignee={"role": "reviewer"},
        )
        restarted = SQLiteWorkItemRepository(ActivatedWorkspaceRepository("phase5c", self.workspace_root))
        restored_parent = restarted.inspect(parent["workItemId"])
        restored_child = restarted.inspect(child["workItemId"])
        self.assertEqual(restored_parent["handoffReason"], "Specialist review requested")
        self.assertEqual(restored_parent["claims"][0]["state"], "handed_off")
        self.assertEqual(restored_parent["claims"][0]["leaseExpiresAt"], parent_claim["claims"][0]["leaseExpiresAt"])
        self.assertEqual(restored_child["parentWorkItemId"], parent["workItemId"])
        self.assertEqual(restored_child["dependencyStates"][parent["workItemId"]], "available")
        self.assertTrue(handed_off["handoffs"])

    def test_context_query_recovers_bounded_specialist_state_after_chat_loss(self) -> None:
        created = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.create",
                "workspaceId": "phase5c",
                "payload": {
                    "objective": "Resume bounded fictional web analysis",
                    "role": "web",
                    "targets": ["phase5c.example"],
                    "requiredPacks": ["web"],
                    "completionContract": {"result": "evidence-backed candidate summary"},
                    "unresolvedGaps": ["authenticated coverage unavailable"],
                },
            },
            context=self.context,
        ).result
        claimed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.claim",
                "workspaceId": "phase5c",
                "workItemId": created["workItemId"],
                "expectedVersion": created["version"],
                "worker": "web-specialist",
            },
            context=self.context,
        ).result
        self.repository.link_execution(
            created["workItemId"],
            claim_id=claimed["claimId"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            references=[{"type": "operation", "id": "offline-analysis", "state": "completed"}],
            event_type="work_item.execution_result",
            now=BASE_TIME,
        )
        envelope = self.facade.invoke(
            "context.query",
            {
                "workspaceId": "phase5c",
                "workItemId": created["workItemId"],
                "claimId": claimed["claimId"],
                "maxTokens": 10_000,
            },
            context=self.context,
        )
        self.assertEqual(envelope.outcome_kind, "success")
        self.assertEqual(len(envelope.result["workItems"]), 1)
        recovered = envelope.result["workItems"][0]
        self.assertEqual(recovered["summary"], "Resume bounded fictional web analysis")
        self.assertEqual(recovered["attributes"]["role"], "web")
        self.assertEqual(recovered["attributes"]["completionContract"]["result"], "evidence-backed candidate summary")
        self.assertIn("authenticated coverage unavailable", recovered["attributes"]["unresolvedGaps"])
        self.assertLessEqual(envelope.result["budget"]["used"], 10_000)

    def test_action_linkage_is_non_authoritative_and_appears_in_work_item_audit(self) -> None:
        item = self.create()
        claimed = self.claim(item)
        result = self.facade.invoke(
            "actions.run_passive",
            {
                "actionId": "workspace.summary",
                "arguments": {"workspaceId": "phase5c"},
                "workItem": {"workItemId": item["workItemId"], "claimId": claimed["claimId"]},
            },
            context=self.context,
        )
        self.assertEqual(result.outcome_kind, "success")
        inspected = self.repository.inspect(item["workItemId"])
        action = next(reference for reference in inspected["references"] if reference["type"] == "action")
        self.assertEqual(action["id"], "workspace.summary")
        self.assertEqual(action["executionState"], "success")
        self.assertEqual(action["replaySafety"], "pure_read")
        self.assertFalse(inspected["automaticReplay"])

    def test_claim_and_worker_label_cannot_satisfy_uncovered_authority(self) -> None:
        item = self.create()
        authority_context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="phase5c",
            execution_profile="full_delegated",
            authority_session_id="phase5c-authority",
            correlation_id="phase5c-authority-test",
        )
        claimed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.claim",
                "workspaceId": "phase5c",
                "workItemId": item["workItemId"],
                "expectedVersion": item["version"],
                "worker": "self-declared-authorized-worker",
            },
            context=authority_context,
        )
        self.assertEqual(claimed.outcome_kind, "success")

        uncovered = self.facade.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": {
                    "workspaceId": "phase5c",
                    "url": "https://phase5c.example/api",
                    "followRedirects": False,
                },
                "workItem": {
                    "workItemId": item["workItemId"],
                    "claimId": claimed.result["claimId"],
                },
            },
            context=authority_context,
        )
        self.assertEqual(uncovered.outcome_kind, "approval_required")
        self.assertIsNotNone(uncovered.operation_handle)
        inspected = self.repository.inspect(item["workItemId"])
        action = next(reference for reference in inspected["references"] if reference["type"] == "action")
        self.assertEqual(action["executionState"], "approval_required")

    def test_json_v1_and_cross_workspace_work_item_access_fail_closed(self) -> None:
        workspace.create_workspace("legacy-work", hosts=["legacy.example"], store_version="json-v1")
        self.assertEqual(selected_store_version(workspace.WORKSPACES_DIR / "legacy-work"), "json-v1")
        legacy_context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="legacy-work",
            execution_profile="legacy",
        )
        unavailable = self.facade.invoke(
            "tasks.control",
            {"operation": "work.create", "workspaceId": "legacy-work", "payload": {"objective": "unsupported"}},
            context=legacy_context,
        )
        self.assertEqual(unavailable.diagnostics["reasonCode"], "work_items_require_sqlite_v2")
        item = self.create()
        workspace.create_workspace("other-work", hosts=["other.example"])
        other_context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="other-work",
            execution_profile="legacy",
        )
        crossed = self.facade.invoke(
            "tasks.control",
            {"operation": "work.inspect", "workspaceId": "other-work", "workItemId": item["workItemId"]},
            context=other_context,
        )
        self.assertEqual(crossed.diagnostics["reasonCode"], "work_item_not_found")

    def test_state_bundle_round_trip_preserves_operational_work_truth(self) -> None:
        parent = self.create(workItemId="work-bundle-parent")
        child = self.create(
            workItemId="work-bundle-child",
            parentWorkItemId=parent["workItemId"],
            dependencyIds=[parent["workItemId"]],
        )
        claim = self.claim(parent)
        self.repository.link_execution(
            parent["workItemId"],
            claim_id=claim["claimId"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            references=[{"type": "operation", "id": "bundle-operation", "state": "unknown"}],
            event_type="work_item.execution_result",
            now=BASE_TIME,
        )
        bundle_path = self.root / "phase5c-bundle"
        exported = StateBundleService(self.root).export("phase5c", bundle_path)
        with TemporaryDirectory() as imported_root:
            imported = StateBundleService(Path(imported_root)).import_bundle(bundle_path)
            restored = SQLiteWorkItemRepository(
                ActivatedWorkspaceRepository(
                    "phase5c",
                    Path(imported_root) / "workspaces" / "phase5c",
                )
            )
            restored_parent = restored.inspect(parent["workItemId"])
            restored_child = restored.inspect(child["workItemId"])
        self.assertEqual(imported["contentDigest"], exported["contentDigest"])
        self.assertEqual(restored_parent["claims"][0]["state"], "active")
        self.assertEqual(restored_parent["references"][0]["id"], "bundle-operation")
        self.assertEqual(restored_child["dependencyIds"], [parent["workItemId"]])

    def test_compact_surface_remains_eleven_tools_and_within_accepted_ceiling(self) -> None:
        operations = CompactProjection().operations()
        payload = json.dumps(
            [item.model_dump(mode="json", by_alias=True) for item in operations],
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(len(operations), 11)
        self.assertLessEqual(len(payload), 24_834)


if __name__ == "__main__":
    unittest.main()
