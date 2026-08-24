"""Phase 3R agent-benchmark classification and evidence-hygiene gates."""

from __future__ import annotations

from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[3]


class Phase3RAgentBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.objective = runpy.run_path(str(ROOT / "bin" / "run-phase3-agent-benchmark"))
        cls.smoke = runpy.run_path(str(ROOT / "bin" / "run-phase3d-codex"))

    def test_objective_prompt_has_no_implementation_identifiers_or_call_counts(self) -> None:
        self.objective["_assert_prompt_is_objective_driven"]()

    def test_live_runners_and_config_are_codex_only(self) -> None:
        for relative in (
            "bin/run-phase3-agent-benchmark",
            "bin/run-phase3d-codex",
            "bin/print-mcp-config",
        ):
            self.assertNotIn(
                "claude",
                (ROOT / relative).read_text(encoding="utf-8").lower(),
                relative,
            )

    def test_objective_acceptance_allows_catalog_selected_canonical_paths(self) -> None:
        calls = []
        for action_id in (
            "workspace.summary",
            "workspace.prepare_target_context",
            "headers_cookies.analyze_workspace",
            "dumps.list",
            "sitemap.from_dump",
            "fingerprint.from_dump",
            "cors.generate_test_plan",
            "cors.execute_test",
            "crawler.crawl",
            "evidence.log_event",
            "evidence.tail",
        ):
            calls.append(
                {
                    "tool": (
                        "actions.run_active"
                        if action_id in {"cors.execute_test", "crawler.crawl"}
                        else "actions.run_passive"
                    ),
                    "actionId": action_id,
                    "outcomeKind": "success",
                    "error": False,
                }
            )
        for tool in ("reports.render", "artifacts.inspect"):
            calls.append(
                {
                    "tool": tool,
                    "actionId": None,
                    "outcomeKind": "success",
                    "error": False,
                }
            )
        for operation in ("cancel", "inspect"):
            calls.append(
                {
                    "tool": "tasks.control",
                    "actionId": None,
                    "taskOperation": operation,
                    "outcomeKind": "success",
                    "error": False,
                }
            )
        accepted = self.objective["_workflow_acceptance"](
            calls,
            {"jobs": {"finalized": 1}},
        )
        self.assertTrue(all(accepted.values()), accepted)

    def test_objective_acceptance_allows_canonical_report_renderer(self) -> None:
        calls = []
        for action_id in (
            "workspace.summary",
            "workspace.prepare_target_context",
            "headers_cookies.analyze_workspace",
            "dumps.list",
            "sitemap.from_dump",
            "fingerprint.from_dump",
            "cors.generate_test_plan",
            "cors.execute_test",
            "crawler.crawl",
            "evidence.log_event",
            "evidence.tail",
            "documentation.render_assessment_summary",
        ):
            calls.append(
                {
                    "tool": "actions.run_passive",
                    "actionId": action_id,
                    "outcomeKind": "success",
                    "error": False,
                }
            )
        for operation in ("cancel", "inspect"):
            calls.append(
                {
                    "tool": "tasks.control",
                    "actionId": None,
                    "taskOperation": operation,
                    "outcomeKind": "success",
                    "error": False,
                }
            )
        calls.append(
            {
                "tool": "artifacts.inspect",
                "actionId": None,
                "outcomeKind": "success",
                "error": False,
            }
        )
        accepted = self.objective["_workflow_acceptance"](
            calls,
            {"jobs": {"finalized": 1}},
        )
        self.assertTrue(all(accepted.values()), accepted)

    def test_committable_objective_call_records_do_not_retain_raw_trace_ids(self) -> None:
        record = self.objective["_call_record"](
            "actions.run_passive",
            {"actionId": "workspace.summary", "arguments": {"workspaceId": "benchmark"}},
            {
                "_meta": {
                    "synapse/protocolVersion": "2025-06-18",
                    "synapse/surface": "modern-compact",
                },
                "structured_content": {
                    "outcomeKind": "success",
                    "traceId": "raw-trace",
                    "resourceReferences": [],
                    "diagnostics": {"effects": {"traffic": []}},
                },
            },
            None,
        )
        self.assertNotIn("traceId", record)
        self.assertTrue(record["tracePresent"])

    def test_transport_smoke_is_classified_and_omits_raw_resume_material(self) -> None:
        result = {
            "case": "approval",
            "success": True,
            "wallClockSeconds": 1.0,
            "toolCalls": 1,
            "toolNames": ["actions.run_active"],
            "inputTokens": 10,
            "outputTokens": 4,
            "negotiatedRevisions": ["2025-06-18"],
            "observedModel": None,
            "final": {
                "outcomeKind": "approval_required",
                "dispatch": "not_started",
                "operationHandle": "operation-secret",
                "traceId": "trace-secret",
            },
        }
        public = self.smoke["_public_case"](result, trace_continuity=True)
        self.assertNotIn("operationHandle", public)
        self.assertNotIn("traceId", public)
        self.assertTrue(public["opaqueOperationHandlePresent"])
        self.assertIn("transport and safety smoke", self.smoke["__doc__"])


if __name__ == "__main__":
    unittest.main()
