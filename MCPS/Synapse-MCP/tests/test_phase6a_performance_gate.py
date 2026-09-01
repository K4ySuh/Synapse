"""Adversarial gates for the repeat-aggregated Phase 6A performance method."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]


with patch.dict(os.environ, {"SYNAPSE_PHASE6_PERFORMANCE_RUNTIME_SELECTED": "1"}):
    RUNNER = runpy.run_path(str(ROOT / "bin" / "run-phase6-performance"))


class Phase6APerformanceGateTests(unittest.TestCase):
    def test_aggregation_uses_median_repetition_percentiles(self) -> None:
        aggregate = RUNNER["_aggregate_measurements"](
            [
                {
                    "batchSize": 10,
                    "sampleCount": 40,
                    "p50Milliseconds": 10.0,
                    "p95Milliseconds": 12.0,
                    "minimumMilliseconds": 8.0,
                    "maximumMilliseconds": 40.0,
                },
                {
                    "batchSize": 10,
                    "sampleCount": 40,
                    "p50Milliseconds": 30.0,
                    "p95Milliseconds": 45.0,
                    "minimumMilliseconds": 20.0,
                    "maximumMilliseconds": 60.0,
                },
                {
                    "batchSize": 10,
                    "sampleCount": 40,
                    "p50Milliseconds": 11.0,
                    "p95Milliseconds": 13.0,
                    "minimumMilliseconds": 7.0,
                    "maximumMilliseconds": 35.0,
                },
            ]
        )

        self.assertEqual(aggregate["repetitionCount"], 3)
        self.assertEqual(aggregate["batchSize"], 10)
        self.assertEqual(aggregate["sampleCount"], 120)
        self.assertEqual(aggregate["operationCount"], 1200)
        self.assertEqual(aggregate["p50Milliseconds"], 11.0)
        self.assertEqual(aggregate["p95Milliseconds"], 13.0)
        self.assertEqual(aggregate["minimumMilliseconds"], 7.0)
        self.assertEqual(aggregate["maximumMilliseconds"], 60.0)

    def test_matching_method_rejects_p95_regression_over_twenty_percent(self) -> None:
        document = self._document(fixture={"methodVersion": 3})
        baseline = self._document(fixture={"methodVersion": 3})
        document["measurements"]["registryControlOverhead"]["p95Milliseconds"] = 1.201

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            path.write_text(json.dumps(baseline), encoding="utf-8")
            evaluation = RUNNER["_evaluate"](document, path)

        self.assertEqual(evaluation["result"], "fail")
        self.assertEqual(evaluation["relativeBaseline"]["status"], "fail")
        self.assertIn("registryControlOverhead.p95 regressed", evaluation["failures"][0])

    def test_method_mismatch_never_uses_relative_acceptance(self) -> None:
        document = self._document(fixture={"methodVersion": 3})
        baseline = self._document(fixture={"methodVersion": 2})

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            path.write_text(json.dumps(baseline), encoding="utf-8")
            evaluation = RUNNER["_evaluate"](document, path)

        self.assertEqual(evaluation["result"], "pass")
        self.assertEqual(
            evaluation["relativeBaseline"]["status"],
            "environment_or_fixture_mismatch",
        )
        self.assertFalse(evaluation["acceptedByMatchingRelativeBaseline"])

    @staticmethod
    def _document(*, fixture: dict[str, int]) -> dict[str, object]:
        measurements = {
            name: {"p50Milliseconds": 1.0, "p95Milliseconds": 1.0}
            for name in RUNNER["ABSOLUTE_CEILINGS_MS"]
        }
        return {
            "environment": {"fingerprint": "matching-environment"},
            "fixture": fixture,
            "measurements": measurements,
        }


if __name__ == "__main__":
    unittest.main()
