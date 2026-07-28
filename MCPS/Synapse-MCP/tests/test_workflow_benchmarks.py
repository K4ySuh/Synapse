"""Behavioral workflow baselines; excludes agent and live-client benchmarks."""

from __future__ import annotations

import httpx
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from benchmark_support import (
    CONTEXT_BUDGETS,
    WORKFLOW_NAMES,
    run_workflow_corpus,
    workflow_01_open_workspace_and_summarize,
    workflow_02_prepare_target_context_under_budget,
    workflow_03_passive_headers_cookies_analysis,
    workflow_04_disabled_traffic_cors_probe,
    workflow_05_background_submit_and_inspect,
    workflow_06_resume_after_simulated_timeout_without_duplicating_work,
    workflow_07_render_report_from_fixture_workspace,
)


class WorkflowBenchmarkTests(unittest.TestCase):
    def test_workflow_01_open_workspace_and_summarize(self) -> None:
        metric = workflow_01_open_workspace_and_summarize()

        self.assertEqual(metric["callCount"], 1)
        self.assertEqual(metric["targetCount"], 1)
        self.assertGreater(metric["entityTotals"]["endpoints"], 0)

    def test_workflow_02_prepare_target_context_under_budget(self) -> None:
        metric = workflow_02_prepare_target_context_under_budget()

        self.assertEqual(metric["callCount"], len(CONTEXT_BUDGETS))
        self.assertEqual(metric["ingestShape"], "sitemap JSON with hosts[].urls[]")
        self.assertGreater(metric["entityTotals"]["endpoints"], 0)
        self.assertEqual(
            [measurement["maxTokens"] for measurement in metric["budgets"]],
            list(CONTEXT_BUDGETS),
        )
        for measurement in metric["budgets"]:
            self.assertGreater(measurement["responseCharacters"], 0)
            self.assertGreater(measurement["estimatedTokens"], 0)
            self.assertGreater(measurement["estimatedToBudgetRatio"], 0)

    def test_workflow_03_passive_headers_cookies_analysis(self) -> None:
        metric = workflow_03_passive_headers_cookies_analysis()

        self.assertEqual(metric["callCount"], 1)
        self.assertEqual(metric["mode"], "passive_analysis")
        self.assertGreater(metric["candidateCount"], 0)

    def test_workflow_04_disabled_traffic_cors_probe(self) -> None:
        metric = workflow_04_disabled_traffic_cors_probe()

        self.assertEqual(metric["callCount"], 2)
        self.assertFalse(metric["planSendsTraffic"])
        self.assertIsNone(metric["responseStatus"])

    def test_workflow_05_background_submit_and_inspect(self) -> None:
        metric = workflow_05_background_submit_and_inspect()

        self.assertEqual(metric["callCount"], 3)
        self.assertTrue(metric["finalized"])
        self.assertTrue(metric["resultPresent"])
        self.assertEqual(metric["activeJobCount"], 0)

    def test_workflow_06_resume_after_simulated_timeout_without_duplicating_work(
        self,
    ) -> None:
        metric = (
            workflow_06_resume_after_simulated_timeout_without_duplicating_work()
        )

        self.assertEqual(metric["timeoutCode"], -32003)
        self.assertTrue(metric["originalJobIdRecovered"])
        self.assertEqual(metric["jobCountBefore"], metric["jobCountAfter"])
        self.assertTrue(metric["finalized"])

    def test_workflow_07_render_report_from_fixture_workspace(self) -> None:
        metric = workflow_07_render_report_from_fixture_workspace()

        self.assertEqual(metric["callCount"], 1)
        self.assertEqual(metric["format"], "html")
        self.assertGreater(metric["outputBytes"], 0)
        self.assertTrue(metric["outputInsideIsolatedRoot"])

    def test_benchmarks_send_no_network_traffic(self) -> None:
        real_client = httpx.Client

        def guarded_client(*args, **kwargs):
            if not isinstance(kwargs.get("transport"), httpx.MockTransport):
                raise AssertionError("httpx.Client constructed without MockTransport")
            return real_client(*args, **kwargs)

        with TemporaryDirectory(prefix="synapse-benchmark-metrics-") as tmp:
            with patch.object(httpx, "Client", guarded_client):
                result = run_workflow_corpus(Path(tmp), print_table=False)

        self.assertEqual(
            [metric["name"] for metric in result["metrics"]],
            list(WORKFLOW_NAMES),
        )

    def test_benchmark_metrics_are_collected_for_every_workflow(self) -> None:
        with TemporaryDirectory(prefix="synapse-benchmark-metrics-") as tmp:
            output_root = Path(tmp)
            result = run_workflow_corpus(output_root)
            metrics_path = Path(result["metricsPath"])

            self.assertTrue(metrics_path.is_file())
            self.assertTrue(metrics_path.resolve().is_relative_to(output_root.resolve()))
            document = json.loads(metrics_path.read_text(encoding="utf-8"))

        metrics = document["workflows"]
        self.assertEqual(
            [metric["name"] for metric in metrics],
            list(WORKFLOW_NAMES),
        )
        for metric in metrics:
            self.assertGreaterEqual(metric["wallClockMs"], 0)
            self.assertGreater(metric["callCount"], 0)


if __name__ == "__main__":
    unittest.main()
