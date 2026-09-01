"""Phase 6A gates for dependency policy, bounded reads, and work discovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state

from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core import workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository
from synapse_mcp.state.migrations import migration_hash, migration_text


BASE_TIME = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


class Phase6AWorkContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root, store_version="sqlite-v2")
        self.state.__enter__()
        self.addCleanup(self.state.__exit__, None, None, None)
        workspace.create_workspace("phase6a-contracts", hosts=["phase6a-contracts.example"])
        self.repository = SQLiteWorkItemRepository(
            ActivatedWorkspaceRepository(
                "phase6a-contracts",
                workspace.WORKSPACES_DIR / "phase6a-contracts",
            )
        )
        self.context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="phase6a-contracts",
            execution_profile="legacy",
            correlation_id="phase6a-contracts-test",
        )

    def _facade(self, now: datetime = BASE_TIME) -> CompactFacadeService:
        return CompactFacadeService(work_items=WorkItemService(clock=lambda: now))

    def _create(self, identity: str, **values):
        return self.repository.create(
            {
                "workItemId": identity,
                "objective": f"Fictional objective for {identity}",
                **values,
            },
            principal_id="operator:test",
            now=BASE_TIME,
        )

    def _claim(self, item, *, now: datetime = BASE_TIME):
        return self.repository.claim(
            item["workItemId"],
            expected_version=item["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker="phase6a-worker",
            lease_seconds=60,
            now=now,
        )

    def _complete(self, item, *, status: str):
        claimed = self._claim(item)
        return self.repository.transition(
            item["workItemId"],
            {"status": status, "resultSummary": f"Dependency ended as {status}."},
            operation="complete",
            claim_id=claimed["claimId"],
            expected_version=claimed["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            now=BASE_TIME,
        )

    def test_success_required_dependency_failure_blocks_and_has_typed_resolution(self) -> None:
        dependency = self._create("dependency-success-required")
        downstream = self._create(
            "downstream-success-required",
            dependencyIds=[dependency["workItemId"]],
        )

        self._complete(dependency, status="failed")
        blocked = self.repository.inspect(downstream["workItemId"])

        self.assertEqual(blocked["dependencyPolicy"], "success_required")
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blocker"]["code"], "dependency_success_impossible")
        self.assertEqual(blocked["blocker"]["dependencies"], {dependency["workItemId"]: "failed"})

        resolved = self._facade().invoke(
            "tasks.control",
            {
                "operation": "work.resolve_blocked",
                "workspaceId": "phase6a-contracts",
                "workItemId": downstream["workItemId"],
                "expectedVersion": blocked["version"],
                "payload": {
                    "resolution": "replan",
                    "reason": "Produce a terminal-state report instead.",
                    "dependencyPolicy": "terminal_required",
                },
            },
            context=self.context,
        )

        self.assertEqual(resolved.outcome_kind, "success")
        self.assertEqual(resolved.result["status"], "available")
        self.assertEqual(resolved.result["dependencyPolicy"], "terminal_required")
        self.assertGreater(resolved.result["version"], blocked["version"])

    def test_existing_pre_policy_work_item_upgrades_with_explicit_compatible_default(self) -> None:
        root = workspace.WORKSPACES_DIR / "phase6a-pre-policy"
        database = root / "state-v2" / "state.sqlite3"
        database.parent.mkdir(parents=True)
        names = (
            "0001_initial.sql",
            "0002_runtime_adoption.sql",
            "0003_operational_work_items.sql",
            "0004_work_execution_attempts.sql",
        )
        connection = sqlite3.connect(database)
        try:
            for version, name in enumerate(names, start=1):
                connection.executescript(migration_text(name))
                connection.execute(
                    "INSERT INTO schema_migrations(version, name, schema_hash) VALUES(?, ?, ?)",
                    (version, name, migration_hash(name)),
                )
            manifest = "\n".join(f"{name}:{migration_hash(name)}" for name in names)
            connection.execute(
                "INSERT INTO store_metadata(key, value) VALUES('schema_hash', ?)",
                (sha256(manifest.encode("utf-8")).hexdigest(),),
            )
            connection.execute("INSERT INTO store_metadata(key, value) VALUES('store_version', 'sqlite-v2')")
            timestamp = BASE_TIME.isoformat()
            connection.execute(
                "INSERT INTO workspaces(workspace_id, created_at, updated_at) VALUES(?, ?, ?)",
                ("phase6a-pre-policy", timestamp, timestamp),
            )
            connection.execute(
                "INSERT INTO workspace_revisions(workspace_id, revision, updated_at) VALUES(?, 1, ?)",
                ("phase6a-pre-policy", timestamp),
            )
            connection.execute(
                "INSERT INTO work_items(work_item_id, workspace_id, objective, role, status, exclusive_claim, "
                "required_packs_json, selected_packs_json, target_selectors_json, context_query_json, assignee_json, "
                "completion_contract_json, progress_summary, result_summary, blocker_reason, handoff_reason, "
                "next_recommended_work, unresolved_gaps_json, version, created_workspace_revision, "
                "base_workspace_revision, current_workspace_revision, last_seen_workspace_revision, created_at, updated_at) "
                "VALUES('existing-work', 'phase6a-pre-policy', 'Existing objective', '', 'available', 1, "
                "'[]', '[]', '[]', '{}', '{}', '{}', '', '', '', '', '', '[]', 1, 1, 0, 1, 0, ?, ?)",
                (timestamp, timestamp),
            )
            connection.commit()
        finally:
            connection.close()

        repository = SQLiteWorkItemRepository(ActivatedWorkspaceRepository("phase6a-pre-policy", root))
        upgraded = repository.inspect("existing-work")

        self.assertEqual(upgraded["dependencyPolicy"], "success_required")
        self.assertEqual(upgraded["blocker"], {})
        with repository.workspace.connection_factory.connect() as checked:
            self.assertEqual(int(checked.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]), 5)

    def test_cancelled_dependency_obeys_both_dependency_policies(self) -> None:
        first = self._create("dependency-first")
        second = self._create("dependency-second")
        strict = self._create(
            "strict-downstream",
            dependencyIds=[first["workItemId"], second["workItemId"]],
            dependencyPolicy="success_required",
        )
        reporting = self._create(
            "reporting-downstream",
            dependencyIds=[first["workItemId"], second["workItemId"]],
            dependencyPolicy="terminal_required",
        )

        self._complete(first, status="cancelled")
        self.assertEqual(self.repository.inspect(strict["workItemId"])["status"], "blocked")
        self.assertEqual(self.repository.inspect(reporting["workItemId"])["status"], "planned")

        self._complete(second, status="failed")
        available = self.repository.inspect(reporting["workItemId"])
        self.assertEqual(available["status"], "available")
        self.assertEqual(
            available["dependencyStates"],
            {first["workItemId"]: "cancelled", second["workItemId"]: "failed"},
        )

        cancelled = self._facade().invoke(
            "tasks.control",
            {
                "operation": "work.resolve_blocked",
                "workspaceId": "phase6a-contracts",
                "workItemId": strict["workItemId"],
                "expectedVersion": self.repository.inspect(strict["workItemId"])["version"],
                "payload": {
                    "resolution": "cancel",
                    "reason": "The success-only objective is no longer applicable.",
                },
            },
            context=self.context,
        )
        self.assertEqual(cancelled.result["status"], "cancelled")
        self.assertNotEqual(cancelled.result["status"], "completed")

    def test_explicit_reclaim_clears_manual_structured_blocker(self) -> None:
        claimed = self._claim(self._create("manual-blocker-reclaim"))
        blocked = self.repository.transition(
            claimed["workItemId"],
            {"reason": "Pause for operator review."},
            operation="block",
            claim_id=claimed["claimId"],
            expected_version=claimed["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            now=BASE_TIME,
        )
        self.assertEqual(blocked["blocker"]["code"], "manual_block")

        reclaimed = self.repository.claim(
            blocked["workItemId"],
            expected_version=blocked["version"],
            principal_id="operator:test",
            authority_session_id="",
            agent_run_id="",
            worker="phase6a-worker",
            lease_seconds=60,
            reclaim_blocked=True,
            now=BASE_TIME,
        )
        self.assertEqual(reclaimed["status"], "claimed")
        self.assertEqual(reclaimed["blockerReason"], "")
        self.assertEqual(reclaimed["blocker"], {})

    def test_stable_cursor_pages_250_bounded_summaries(self) -> None:
        for index in range(250):
            self._create(f"paged-{index:03d}")

        facade = self._facade()
        cursor = None
        identifiers: list[str] = []
        page_sizes: list[int] = []
        while True:
            payload = {"limit": 50}
            if cursor:
                payload["cursor"] = cursor
            page = facade.invoke(
                "tasks.control",
                {
                    "operation": "work.list",
                    "workspaceId": "phase6a-contracts",
                    "payload": payload,
                },
                context=self.context,
            )
            self.assertEqual(page.outcome_kind, "success")
            identifiers.extend(item["workItemId"] for item in page.result["workItems"])
            page_sizes.append(
                len(json.dumps(page.result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            )
            self.assertTrue(all("claims" not in item for item in page.result["workItems"]))
            cursor = page.result.get("nextCursor")
            if not cursor:
                break

        self.assertEqual(len(identifiers), 250)
        self.assertEqual(len(set(identifiers)), 250)
        self.assertEqual(len(page_sizes), 5)
        self.assertLess(max(page_sizes), 40_000)

        hundred = facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase6a-contracts",
                "payload": {"limit": 100},
            },
            context=self.context,
        )
        encoded = json.dumps(hundred.result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertLess(len(encoded), 80_000)

        detailed = facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase6a-contracts",
                "payload": {"detail": True, "limit": 1},
            },
            context=self.context,
        )
        self.assertFalse(detailed.result["summary"])
        self.assertIn("claims", detailed.result["workItems"][0])

    def test_expired_claim_is_effective_at_read_time_without_recovery(self) -> None:
        claimed = self._claim(self._create("expired-read"))
        facade = self._facade(BASE_TIME + timedelta(seconds=61))

        listed = facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase6a-contracts",
                "payload": {"worker": "phase6a-worker"},
            },
            context=self.context,
        )
        self.assertEqual(listed.result["workItems"], [])

        inspected = facade.invoke(
            "tasks.control",
            {
                "operation": "work.inspect",
                "workspaceId": "phase6a-contracts",
                "workItemId": claimed["workItemId"],
            },
            context=self.context,
        )
        self.assertEqual(inspected.result["status"], "available")
        self.assertEqual(inspected.result["storedStatus"], "claimed")
        self.assertEqual(inspected.result["effectiveLeaseState"], "expired")
        self.assertEqual(inspected.result["claims"][0]["state"], "expired")

    def test_fresh_facade_discovers_every_work_operation_contract(self) -> None:
        facade = CompactFacadeService(work_items=WorkItemService(clock=lambda: BASE_TIME))
        result = facade.invoke(
            "tasks.control",
            {"operation": "work.contract"},
            context=FacadeCallContext(principal_id="operator:test", execution_profile="legacy"),
        )

        self.assertEqual(result.outcome_kind, "success")
        contracts = {item["operation"]: item for item in result.result["operations"]}
        self.assertEqual(
            set(contracts),
            {
                "work.create",
                "work.list",
                "work.inspect",
                "work.claim",
                "work.heartbeat",
                "work.update",
                "work.handoff",
                "work.release",
                "work.complete",
                "work.block",
                "work.resolve_blocked",
                "work.recover",
            },
        )
        self.assertIn("objective", contracts["work.create"]["payloadSchema"]["properties"])
        self.assertIn("cursor", contracts["work.list"]["payloadSchema"]["properties"])
        self.assertIn("expectedVersion", contracts["work.resolve_blocked"]["requiredTopLevel"])
        self.assertTrue(all(item["example"]["operation"] == name for name, item in contracts.items()))

    def test_version_chains_from_claim_through_execution_update_and_completion(self) -> None:
        claimed = self._claim(self._create("version-chain"))
        facade = self._facade()
        executed = facade.invoke(
            "actions.run_passive",
            {
                "actionId": "workspace.summary",
                "arguments": {"workspaceId": "phase6a-contracts"},
                "idempotencyKey": "phase6a-version-chain",
                "workItem": {
                    "workItemId": claimed["workItemId"],
                    "claimId": claimed["claimId"],
                },
            },
            context=self.context,
        )
        execution_version = executed.diagnostics["workItem"]["version"]
        self.assertGreater(execution_version, claimed["version"])

        updated = facade.invoke(
            "tasks.control",
            {
                "operation": "work.update",
                "workspaceId": "phase6a-contracts",
                "workItemId": claimed["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": execution_version,
                "payload": {"progressSummary": "Execution result reviewed."},
            },
            context=self.context,
        )
        completed = facade.invoke(
            "tasks.control",
            {
                "operation": "work.complete",
                "workspaceId": "phase6a-contracts",
                "workItemId": claimed["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": updated.result["version"],
                "payload": {"resultSummary": "Version chain completed."},
            },
            context=self.context,
        )
        self.assertEqual(completed.result["status"], "completed")
        self.assertGreater(completed.result["version"], updated.result["version"])


if __name__ == "__main__":
    unittest.main()
