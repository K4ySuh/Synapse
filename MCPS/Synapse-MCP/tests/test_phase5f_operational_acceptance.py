"""Phase 5F operational acceptance and final adversarial closure gates."""

from __future__ import annotations

from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from helpers import isolated_state
from phase5_acceptance_support import (
    BASE_TIME,
    PRINCIPAL_ID,
    WORKSPACE_ID,
    run_operational_repetition,
)

from synapse_mcp.core import workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository
from synapse_mcp.state.errors import StateConflictError, StateStoreError


ROOT = Path(__file__).resolve().parents[3]


class Phase5FOperationalAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = runpy.run_path(str(ROOT / "bin" / "run-phase5-acceptance"))
        cls.benchmark = runpy.run_path(
            str(ROOT / "bin" / "run-phase5-codex-benchmark")
        )

    def test_fictional_operational_corpus_converges_without_replay_or_traffic(self) -> None:
        with TemporaryDirectory() as temporary:
            result = run_operational_repetition(Path(temporary), 1)
        self.assertEqual(result["directWorkflow"]["result"], "pass")
        self.assertEqual(result["coordinatedWorkflow"]["result"], "pass")
        self.assertEqual(result["contention"]["winners"], 1)
        self.assertEqual(result["workspace"]["lostUpdates"], 0)
        self.assertEqual(result["workspace"]["duplicateActionsOrJobs"], 0)
        self.assertFalse(result["recovery"]["automaticReplay"])
        self.assertEqual(result["recovery"]["activeOrUnknownExecution"], 1)
        self.assertEqual(result["authority"]["coveredOutcome"], "success")
        self.assertEqual(result["authority"]["uncoveredOutcome"], "approval_required")
        self.assertEqual(result["authority"]["externalTargetTraffic"], 0)
        self.assertEqual(result["coordinatedWorkflow"]["reportStatus"], "completed")
        self.assertGreater(result["coordinatedWorkflow"]["candidateCount"], 0)
        self.assertGreater(result["coordinatedWorkflow"]["findingCount"], 0)
        self.assertGreater(result["coordinatedWorkflow"]["contradictionCount"], 0)
        self.assertGreater(result["coordinatedWorkflow"]["gapCount"], 0)

    def test_completion_cannot_commit_before_referenced_evidence(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace(WORKSPACE_ID, hosts=["app.acme-demo.test"])
                activated = ActivatedWorkspaceRepository(
                    WORKSPACE_ID, workspace.WORKSPACES_DIR / WORKSPACE_ID
                )
                repository = SQLiteWorkItemRepository(activated)
                created = repository.create(
                    {
                        "workItemId": "work-atomic-evidence",
                        "objective": "Require evidence before completion",
                    },
                    principal_id=PRINCIPAL_ID,
                    now=BASE_TIME,
                )
                claimed = repository.claim(
                    created["workItemId"],
                    expected_version=created["version"],
                    principal_id=PRINCIPAL_ID,
                    authority_session_id="",
                    agent_run_id="",
                    worker="atomic-worker",
                    lease_seconds=60,
                    now=BASE_TIME,
                )
                with self.assertRaises(StateStoreError) as missing:
                    repository.transition(
                        created["workItemId"],
                        {
                            "resultSummary": "Must not become visible before evidence.",
                            "references": [
                                {"type": "evidence", "id": "missing-evidence"}
                            ],
                        },
                        operation="complete",
                        claim_id=claimed["claimId"],
                        expected_version=claimed["version"],
                        principal_id=PRINCIPAL_ID,
                        authority_session_id="",
                        agent_run_id="",
                        now=BASE_TIME,
                    )
                observed = repository.inspect(created["workItemId"])
        self.assertEqual(missing.exception.reason_code, "work_item_reference_not_found")
        self.assertEqual(observed["status"], "claimed")
        self.assertEqual(observed["version"], claimed["version"])
        self.assertEqual(observed["references"], [])

    def test_claim_identity_cannot_cross_principal_or_workspace(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace(WORKSPACE_ID, hosts=["app.acme-demo.test"])
                workspace.create_workspace("other-workspace", hosts=["other.example"])
                repository = SQLiteWorkItemRepository(
                    ActivatedWorkspaceRepository(
                        WORKSPACE_ID, workspace.WORKSPACES_DIR / WORKSPACE_ID
                    )
                )
                created = repository.create(
                    {
                        "workItemId": "work-bound-identity",
                        "objective": "Prove claim binding",
                    },
                    principal_id=PRINCIPAL_ID,
                    now=BASE_TIME,
                )
                claimed = repository.claim(
                    created["workItemId"],
                    expected_version=created["version"],
                    principal_id=PRINCIPAL_ID,
                    authority_session_id="",
                    agent_run_id="",
                    worker="bound-worker",
                    lease_seconds=60,
                    now=BASE_TIME,
                )
                with self.assertRaises(StateConflictError) as principal:
                    repository.heartbeat(
                        created["workItemId"],
                        claim_id=claimed["claimId"],
                        expected_version=claimed["version"],
                        principal_id="other-principal",
                        authority_session_id="",
                        agent_run_id="",
                        lease_seconds=60,
                        now=BASE_TIME,
                    )
                other = SQLiteWorkItemRepository(
                    ActivatedWorkspaceRepository(
                        "other-workspace", workspace.WORKSPACES_DIR / "other-workspace"
                    )
                )
                with self.assertRaises(StateStoreError) as crossed:
                    other.inspect(created["workItemId"])
        self.assertEqual(principal.exception.reason_code, "work_item_claim_principal_mismatch")
        self.assertEqual(crossed.exception.reason_code, "work_item_not_found")

    def test_optional_codex_diagnostic_pins_low_usage_profile_and_resumes_clean_runs(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.benchmark["_codex_command"](
                root,
                root / "schema.json",
                root / "final.json",
                self.benchmark["DEFAULT_MODEL"],
                self.benchmark["DEFAULT_REASONING_EFFORT"],
            )
            overrides = [
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--config"
            ]
            self.assertEqual(self.benchmark["DEFAULT_MODEL"], "gpt-5.6-luna")
            self.assertEqual(self.benchmark["DEFAULT_REASONING_EFFORT"], "low")
            self.assertIn('model_reasoning_effort="low"', overrides)
            self.assertIn('model_reasoning_summary="none"', overrides)
            self.assertIn('model_verbosity="low"', overrides)
            self.assertIn('agents.default_subagent_model="gpt-5.6-luna"', overrides)
            self.assertIn('agents.default_subagent_reasoning_effort="low"', overrides)
            self.assertIn(
                f'tool_output_token_limit={self.benchmark["TOOL_OUTPUT_TOKEN_LIMIT"]}',
                overrides,
            )
            self.assertIn("claim contention", self.benchmark["OBJECTIVE_PROMPT"].lower())

            output = root / "output"
            output.mkdir()
            identity = self.benchmark["_checkpoint_identity"](
                client_version="fixture-client",
                model=self.benchmark["DEFAULT_MODEL"],
                reasoning_effort="low",
            )

            def passed_run(repetition: int) -> dict[str, object]:
                return {
                    "repetition": repetition,
                    "overall": "pass",
                    "singleAgent": {"result": "pass"},
                    "multiAgent": {"result": "pass"},
                    "externalTargetTraffic": 0,
                    "duplicateActiveExecution": 0,
                    "nonMcpToolTypes": [],
                }

            self.benchmark["_write_checkpoint"](
                output / self.benchmark["CHECKPOINT_NAME"],
                identity=identity,
                runs=[passed_run(1)],
            )
            called: list[int] = []

            def run_case(*_args, repetition: int, **_kwargs):
                called.append(repetition)
                return passed_run(repetition)

            globals_ = self.benchmark["live_gate"].__globals__
            with patch.dict(
                globals_,
                {
                    "_preflight": lambda: {
                        "codex": {"available": True, "version": "fixture-client"}
                    },
                    "_run_case": run_case,
                },
            ):
                result = self.benchmark["live_gate"](
                    repetitions=3,
                    output=output,
                    evidence=root / "evidence.json",
                    model=self.benchmark["DEFAULT_MODEL"],
                    reasoning_effort="low",
                    resume=True,
                    allow_high_usage=True,
                )
        self.assertEqual(called, [2, 3])
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["reasoningEffort"], "low")

    def test_optional_codex_diagnostic_requires_explicit_high_usage_override(self) -> None:
        with self.assertRaises(self.benchmark["BenchmarkFailure"]) as caught:
            self.benchmark["_require_explicit_high_usage"](
                repetitions=2,
                model=self.benchmark["DEFAULT_MODEL"],
                reasoning_effort=self.benchmark["DEFAULT_REASONING_EFFORT"],
                allow_high_usage=False,
            )
        self.assertIn("--allow-high-usage", str(caught.exception))
        self.benchmark["_require_explicit_high_usage"](
            repetitions=2,
            model="gpt-5.6-sol",
            reasoning_effort="medium",
            allow_high_usage=True,
        )
        with self.assertRaises(self.benchmark["BenchmarkFailure"]):
            self.benchmark["_require_explicit_high_usage"](
                repetitions=0,
                model=self.benchmark["DEFAULT_MODEL"],
                reasoning_effort=self.benchmark["DEFAULT_REASONING_EFFORT"],
                allow_high_usage=True,
            )

    def test_optional_live_diagnostic_requires_canonical_work_and_execution_truth(self) -> None:
        final = {
            "singleAgent": {
                "directSimpleWork": True,
                "revisionDeltaRecovered": True,
                "existingJobInspectedWithoutResubmit": True,
                "reportIncludesGaps": True,
            },
            "multiAgent": {
                "specialistsClaimedDistinctWork": True,
                "exclusiveContentionRerouted": True,
                "workerLossRecoveredWithoutReplay": True,
                "distinctEvidenceConverged": True,
                "reportDependenciesRespected": True,
                "coherentFinalSummary": True,
            },
            "completedCoverage": ["fictional bounded coverage"],
            "gaps": ["fictional coverage gap"],
        }
        events = {
            "calls": [
                {"tool": "engagement.inspect"},
                {"tool": "context.query"},
                {"tool": "context.query"},
            ],
            "collaborationCallCount": 3,
            "successfulReportRenders": 1,
            "duplicateActiveExecution": 0,
        }
        post = {
            "workItems": [],
            "workItemEventCounts": {
                "work_item.claimed": 6,
                "work_item.recovered": 1,
            },
            "distinctClaimWorkerCount": 4,
            "contentionRerouteRecorded": True,
            "dispatchActionCounts": {"crawler.crawl": 1},
            "jobs": {"count": 1},
        }
        self.assertFalse(self.benchmark["_acceptance"](final, events, post)["multiPass"])

        def item(role: str, *, dependencies: int = 0, evidence: int = 0, jobs: int = 0):
            return {
                "role": role,
                "status": "completed",
                "dependencyCount": dependencies,
                "evidenceReferenceCount": evidence,
                "jobReferenceCount": jobs,
                "automaticReplay": False,
            }

        post["workItems"] = [
            item("perimeter"),
            item("web", evidence=1, jobs=1),
            item("intelligence"),
            item("access-control", evidence=1),
            item("reporting", dependencies=4),
        ]
        accepted = self.benchmark["_acceptance"](final, events, post)
        self.assertTrue(accepted["singlePass"])
        self.assertTrue(accepted["multiPass"])

    def test_aggregate_pass_requires_only_offline_tests_and_distribution(self) -> None:
        passed = {"result": "pass"}
        skipped = {"result": "skipped"}
        self.assertEqual(self.runner["_aggregate_result"](passed, passed), "pass")
        self.assertEqual(self.runner["_aggregate_result"](skipped, passed), "partial")
        self.assertEqual(self.runner["_aggregate_result"](passed, skipped), "partial")

    def test_packaged_guidance_marks_work_item_boundaries_as_create_time(self) -> None:
        coordinator = (
            ROOT
            / "skills"
            / "codex"
            / "multi-agent-compat"
            / "synapse-coordinate-engagement"
            / "SKILL.md"
        ).read_text(encoding="utf-8")
        prompt = (
            ROOT
            / "MCPS"
            / "Synapse-MCP"
            / "synapse_mcp"
            / "operational_prompt.md"
        ).read_text(encoding="utf-8")
        self.assertIn("create-time coordination metadata", coordinator)
        self.assertIn("relationships are immutable after", coordinator)
        self.assertIn("coordination boundaries are not mutable later", prompt)

    def test_acceptance_runner_and_handoff_contract_are_present(self) -> None:
        runner = ROOT / "bin" / "run-phase5-acceptance"
        handoff = ROOT / "docs" / "modernization" / "phase-5-handoff.md"
        method = ROOT / "docs" / "modernization" / "phase-5-benchmark-method.md"
        self.assertTrue(runner.is_file())
        self.assertTrue(runner.stat().st_mode & 0o111)
        self.assertTrue(handoff.is_file())
        self.assertTrue(method.is_file())
        handoff_text = handoff.read_text(encoding="utf-8")
        self.assertIn("PHASE_5_PASS", handoff_text)
        self.assertIn("legacy", handoff_text.lower())
        self.assertIn("rollback", handoff_text.lower())


if __name__ == "__main__":
    unittest.main()
