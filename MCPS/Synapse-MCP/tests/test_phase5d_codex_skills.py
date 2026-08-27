"""Phase 5D gates for Codex routing, coordination, and specialist playbooks."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from helpers import isolated_state

from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.app.work_items import WorkItemService
from synapse_mcp.core import background_jobs, workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, SQLiteWorkItemRepository


ROOT = Path(__file__).resolve().parents[3]
BASE_TIME = datetime(2026, 8, 27, 14, 0, tzinfo=timezone.utc)
SKILL_NAMES = (
    "operate-synapse",
    "synapse-coordinate-engagement",
    "synapse-engagement-bootstrap",
    "synapse-perimeter-triage",
    "synapse-web-assessment",
    "synapse-access-control",
    "synapse-cve-validation",
    "synapse-reporting",
)


def _load_validator():
    path = ROOT / "bin" / "validate-codex-skills"
    loader = SourceFileLoader("phase5d_skill_validator", str(path))
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise RuntimeError("Could not load the Codex skill validator.")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class Phase5DCodexSkillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root, store_version="sqlite-v2")
        self.state.__enter__()
        self.addCleanup(self.state.__exit__, None, None, None)
        workspace.create_workspace("phase5d", hosts=["phase5d.example"])
        self.activated = ActivatedWorkspaceRepository(
            "phase5d", workspace.WORKSPACES_DIR / "phase5d"
        )
        self.repository = SQLiteWorkItemRepository(self.activated)
        self.context = FacadeCallContext(
            principal_id="operator:phase5d",
            workspace_id="phase5d",
            execution_profile="legacy",
            correlation_id="phase5d-scenario",
        )
        self.facade = CompactFacadeService(
            work_items=WorkItemService(clock=lambda: BASE_TIME)
        )

    def create_work(
        self,
        identity: str,
        *,
        role: str,
        pack: str,
        parent: str = "",
        dependencies: list[str] | None = None,
        gaps: list[str] | None = None,
    ) -> dict:
        payload = {
            "workItemId": identity,
            "objective": f"Complete the fictional {role} work package",
            "role": role,
            "requiredPacks": [pack],
            "selectedPacks": [pack],
            "targets": ["phase5d.example"],
            "contextQuery": {"targets": ["phase5d.example"], "maxTokens": 10_000},
            "completionContract": {"evidence": f"bounded {role} result"},
            "unresolvedGaps": gaps or [],
        }
        if parent:
            payload["parentWorkItemId"] = parent
        if dependencies:
            payload["dependencyIds"] = dependencies
        outcome = self.facade.invoke(
            "tasks.control",
            {"operation": "work.create", "workspaceId": "phase5d", "payload": payload},
            context=self.context,
        )
        self.assertEqual(outcome.outcome_kind, "success")
        return outcome.result

    def claim_work(
        self,
        item: dict,
        worker: str,
        *,
        context: FacadeCallContext | None = None,
    ) -> dict:
        outcome = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.claim",
                "workspaceId": "phase5d",
                "workItemId": item["workItemId"],
                "expectedVersion": item["version"],
                "worker": worker,
            },
            context=context or self.context,
        )
        self.assertEqual(outcome.outcome_kind, "success")
        return outcome.result

    def query_work(self, item: dict, claim_id: str = "") -> dict:
        arguments = {
            "workspaceId": "phase5d",
            "workItemId": item["workItemId"],
            "maxTokens": 30_000,
        }
        if claim_id:
            arguments["claimId"] = claim_id
        outcome = self.facade.invoke("context.query", arguments, context=self.context)
        self.assertEqual(outcome.outcome_kind, "success")
        return outcome.result

    def seed_reporting_context(self) -> None:
        artifact = self.activated.artifacts.ingest_bytes(
            b"fictional Phase 5D offline evidence",
            media_type="text/plain",
            origin="phase5d.scenario",
        )
        self.activated.ingest_collections(
            target="phase5d.example",
            target_payload={"workspaceId": "phase5d", "target": "phase5d.example", "kind": "host"},
            evidence_payload={
                "evidenceId": "evidence-phase5d",
                "source": "phase5d.scenario",
                "dataType": "fictional_fixture",
                "summary": "A bounded fictional observation supports specialist handoff.",
            },
            artifact=artifact,
            collections={
                "services": (
                    {
                        "type": "service",
                        "key": "tcp:443",
                        "name": "fictional-https",
                        "port": 443,
                        "evidenceIds": ["evidence-phase5d"],
                    },
                ),
                "observations": (
                    {
                        "type": "test_candidate",
                        "key": "candidate-phase5d",
                        "summary": "A fictional candidate still requires validation and review.",
                        "candidateFor": ["fictional-control"],
                    },
                    {
                        "type": "detection_gap",
                        "key": "gap-phase5d",
                        "summary": "Authenticated fictional coverage remains unavailable.",
                    },
                    {
                        "type": "state_contradiction",
                        "key": "contradiction-phase5d",
                        "summary": "Two fictional role observations conflict.",
                        "scopeStatus": "in_scope",
                        "authorityStatus": "unknown",
                    },
                ),
                "findings": (
                    {
                        "id": "finding-phase5d",
                        "key": "finding-phase5d",
                        "title": "Confirmed fictional passive fact",
                        "status": "confirmed",
                        "severity": "low",
                        "operatorReviewed": True,
                        "evidenceIds": ["evidence-phase5d"],
                    },
                ),
            },
            audit_payload={"summary": "Installed the fictional Phase 5D reporting fixture."},
        )

    def test_package_validator_and_simple_context_read_need_no_decomposition(self) -> None:
        validator = _load_validator()
        self.assertEqual(validator.validate(), [])
        self.assertEqual(set(validator.OPERATIONAL_SKILLS), set(SKILL_NAMES))

        outcome = self.facade.invoke(
            "context.query",
            {"workspaceId": "phase5d", "targets": ["phase5d.example"], "maxTokens": 10_000},
            context=self.context,
        )
        self.assertEqual(outcome.outcome_kind, "success")
        self.assertEqual(self.repository.list(), [])
        self.assertEqual(outcome.result["workItems"], [])

    def test_validator_rejects_stale_metadata_missing_references_and_copied_contracts(self) -> None:
        validator = _load_validator()
        copied_root = self.root / "skills"
        shutil.copytree(ROOT / "skills" / "codex", copied_root)
        validator.ROOT = self.root
        validator.SKILL_ROOT = copied_root
        validator.SHARED_REFERENCES = copied_root / "operate-synapse" / "references"

        interface = copied_root / "synapse-web-assessment" / "agents" / "openai.yaml"
        interface.write_text(
            interface.read_text(encoding="utf-8").replace("$synapse-web-assessment", "$stale-web-skill"),
            encoding="utf-8",
        )
        access = copied_root / "synapse-access-control" / "SKILL.md"
        access.write_text(
            access.read_text(encoding="utf-8").replace(
                "../operate-synapse/references/specialist-workflow.md",
                "../operate-synapse/references/missing-workflow.md",
            ),
            encoding="utf-8",
        )
        reporting = copied_root / "synapse-reporting" / "SKILL.md"
        reporting.write_text(
            reporting.read_text(encoding="utf-8")
            + "\ninputSchema copied-contract marker. High_level is client-safe.\n",
            encoding="utf-8",
        )

        failures = validator.validate()
        self.assertTrue(any("default_prompt" in item for item in failures))
        self.assertTrue(any("missing reference" in item for item in failures))
        self.assertTrue(any("copied schema/catalog" in item for item in failures))
        self.assertTrue(any("contradictory terminology" in item for item in failures))

    def test_coordinator_creates_three_independent_claimed_specialists_with_bounded_context(self) -> None:
        coordinator = self.create_work("work-coordinator", role="coordinator", pack="core")
        specialists = [
            self.create_work("work-perimeter", role="perimeter", pack="infra", parent=coordinator["workItemId"]),
            self.create_work("work-web", role="web", pack="web", parent=coordinator["workItemId"]),
            self.create_work("work-cve", role="cve", pack="intelligence", parent=coordinator["workItemId"]),
        ]

        for item in specialists:
            claimed = self.claim_work(item, f"{item['role']}-specialist")
            bounded = self.query_work(item, claimed["claimId"])
            visible = {entry["itemId"] for entry in bounded["workItems"]}
            self.assertIn(item["workItemId"], visible)
            self.assertLessEqual(visible, {coordinator["workItemId"], item["workItemId"]})
            self.assertEqual(claimed["dependencyIds"], [])
            self.assertEqual(claimed["status"], "claimed")

        listed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase5d",
                "payload": {"parentWorkItemId": coordinator["workItemId"]},
            },
            context=self.context,
        ).result
        self.assertEqual(listed["count"], 3)
        self.assertEqual({item["role"] for item in listed["workItems"]}, {"perimeter", "web", "cve"})

    def test_duplicate_claim_is_rejected_and_worker_is_rerouted(self) -> None:
        first = self.create_work("work-exclusive", role="web", pack="web")
        remaining = self.create_work("work-remaining", role="reporting", pack="reporting")
        claimed = self.claim_work(first, "specialist-a")

        collision = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.claim",
                "workspaceId": "phase5d",
                "workItemId": first["workItemId"],
                "expectedVersion": claimed["version"],
                "worker": "specialist-b",
            },
            context=self.context,
        )
        self.assertNotEqual(collision.outcome_kind, "success")
        self.assertEqual(collision.diagnostics["reasonCode"], "work_item_already_claimed")
        rerouted = self.claim_work(remaining, "specialist-b")
        self.assertEqual(rerouted["status"], "claimed")

    def test_recovered_active_job_is_polled_and_never_rerun(self) -> None:
        item = self.create_work("work-active-job", role="perimeter", pack="infra")
        claimed = self.claim_work(item, "perimeter-specialist")
        with patch.object(background_jobs, "_start_watchdog"):
            started = background_jobs.start_command(
                ["sleep", "30"],
                timeout_seconds=30,
                event_type="phase5d.fictional_job",
                summary="Run one inert local Phase 5D fixture job.",
                tool="phase5d.fixture",
                workspace_id="phase5d",
                target="phase5d.example",
            )
        self.addCleanup(background_jobs.cancel, started["jobId"])
        self.repository.link_execution(
            item["workItemId"],
            claim_id=claimed["claimId"],
            principal_id="operator:phase5d",
            authority_session_id="",
            agent_run_id="",
            references=[
                {
                    "type": "job",
                    "id": started["jobId"],
                    "state": "running",
                    "replaySafety": "non_idempotent",
                }
            ],
            event_type="work_item.execution_result",
            now=BASE_TIME,
        )

        recovered = self.query_work(item, claimed["claimId"])
        work = next(entry for entry in recovered["workItems"] if entry["itemId"] == item["workItemId"])
        self.assertEqual(work["attributes"]["activeOrUnknownExecution"][0]["id"], started["jobId"])
        before = {
            entry["jobId"]
            for entry in background_jobs.list_jobs(workspace_id="phase5d")["jobs"]
        }
        with patch.object(background_jobs, "start_command", side_effect=AssertionError("job was rerun")):
            polled = self.facade.invoke(
                "tasks.control",
                {"operation": "inspect", "workspaceId": "phase5d", "jobId": started["jobId"]},
                context=self.context,
            )
        after = {
            entry["jobId"]
            for entry in background_jobs.list_jobs(workspace_id="phase5d")["jobs"]
        }
        self.assertEqual(polled.outcome_kind, "success")
        self.assertEqual(polled.result["jobId"], started["jobId"])
        self.assertEqual(before, after)

    def test_missing_authority_blocks_specialist_and_is_visible_to_coordinator(self) -> None:
        coordinator = self.create_work("work-authority-coordinator", role="coordinator", pack="core")
        specialist = self.create_work(
            "work-authority-specialist",
            role="web",
            pack="web",
            parent=coordinator["workItemId"],
        )
        authority_context = FacadeCallContext(
            principal_id="operator:phase5d",
            workspace_id="phase5d",
            execution_profile="full_delegated",
            authority_session_id="phase5d-uncovered-authority",
            correlation_id="phase5d-authority-scenario",
        )
        claimed = self.claim_work(specialist, "web-specialist", context=authority_context)
        denied = self.facade.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": {
                    "workspaceId": "phase5d",
                    "url": "https://phase5d.example/api",
                    "followRedirects": False,
                },
                "workItem": {
                    "workItemId": specialist["workItemId"],
                    "claimId": claimed["claimId"],
                },
            },
            context=authority_context,
        )
        self.assertEqual(denied.outcome_kind, "approval_required")
        current = self.repository.inspect(specialist["workItemId"])
        blocked = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.block",
                "workspaceId": "phase5d",
                "workItemId": specialist["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": current["version"],
                "payload": {
                    "reason": "ApprovalRequired: no server-held grant covers the active request.",
                    "unresolvedGaps": ["active validation remains uncovered"],
                },
            },
            context=authority_context,
        )
        self.assertEqual(blocked.result["status"], "blocked")
        coordinator_view = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase5d",
                "payload": {"parentWorkItemId": coordinator["workItemId"]},
            },
            context=self.context,
        ).result
        self.assertEqual(coordinator_view["workItems"][0]["status"], "blocked")
        self.assertIn("ApprovalRequired", coordinator_view["workItems"][0]["blockerReason"])

    def test_specialist_evidence_is_visible_to_dependent_reporting(self) -> None:
        self.seed_reporting_context()
        coordinator = self.create_work("work-report-coordinator", role="coordinator", pack="core")
        specialist = self.create_work(
            "work-evidence-specialist",
            role="web",
            pack="web",
            parent=coordinator["workItemId"],
        )
        report = self.create_work(
            "work-dependent-report",
            role="reporting",
            pack="reporting",
            parent=coordinator["workItemId"],
            dependencies=[specialist["workItemId"]],
        )
        self.assertEqual(report["status"], "planned")
        claimed = self.claim_work(specialist, "web-specialist")
        updated = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.update",
                "workspaceId": "phase5d",
                "workItemId": specialist["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": claimed["version"],
                "payload": {
                    "progressSummary": "Recorded one fictional passive candidate.",
                    "references": [{"type": "evidence", "id": "evidence-phase5d"}],
                    "unresolvedGaps": ["active validation was not requested"],
                },
            },
            context=self.context,
        ).result
        completed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.complete",
                "workspaceId": "phase5d",
                "workItemId": specialist["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": updated["version"],
                "payload": {
                    "resultSummary": "Passive specialist result is ready for reporting.",
                    "references": [{"type": "evidence", "id": "evidence-phase5d"}],
                },
            },
            context=self.context,
        )
        self.assertEqual(completed.result["status"], "completed")
        unlocked = self.repository.inspect(report["workItemId"])
        self.assertEqual(unlocked["status"], "available")

        reporting_context = self.query_work(unlocked)
        upstream = next(
            item for item in reporting_context["workItems"] if item["itemId"] == specialist["workItemId"]
        )
        self.assertEqual(upstream["lifecycle"], "completed")
        self.assertIn("evidence-phase5d", upstream["evidenceReferences"])
        self.assertIn("active validation was not requested", upstream["attributes"]["unresolvedGaps"])

    def test_final_coordinator_status_separates_completed_work_and_workspace_truth(self) -> None:
        self.seed_reporting_context()
        coordinator = self.create_work("work-final-coordinator", role="coordinator", pack="core")
        specialist = self.create_work(
            "work-final-specialist",
            role="web",
            pack="web",
            parent=coordinator["workItemId"],
        )
        claimed = self.claim_work(specialist, "web-specialist")
        completed = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.complete",
                "workspaceId": "phase5d",
                "workItemId": specialist["workItemId"],
                "claimId": claimed["claimId"],
                "expectedVersion": claimed["version"],
                "payload": {
                    "resultSummary": "Completed fictional passive review; candidate remains unpromoted.",
                    "references": [{"type": "evidence", "id": "evidence-phase5d"}],
                    "unresolvedGaps": ["authenticated coverage remains open"],
                },
            },
            context=self.context,
        )
        self.assertEqual(completed.result["status"], "completed")

        children = self.facade.invoke(
            "tasks.control",
            {
                "operation": "work.list",
                "workspaceId": "phase5d",
                "payload": {"parentWorkItemId": coordinator["workItemId"]},
            },
            context=self.context,
        ).result["workItems"]
        context = self.facade.invoke(
            "context.query",
            {"workspaceId": "phase5d", "targets": ["phase5d.example"], "maxTokens": 30_000},
            context=self.context,
        ).result
        final_status = {
            "completedWork": [item["workItemId"] for item in children if item["status"] == "completed"],
            "candidates": context["candidates"],
            "findings": [item for item in context["confirmedFacts"] if item["kind"] == "finding"],
            "contradictions": context["contradictions"],
            "gaps": context["coverageGaps"],
        }
        self.assertEqual(final_status["completedWork"], [specialist["workItemId"]])
        self.assertTrue(final_status["candidates"])
        self.assertTrue(final_status["findings"])
        self.assertTrue(final_status["contradictions"])
        self.assertTrue(final_status["gaps"])
        self.assertNotEqual(
            final_status["candidates"][0]["itemId"],
            final_status["findings"][0]["itemId"],
        )


if __name__ == "__main__":
    unittest.main()
