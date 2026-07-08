import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.core.adapters import ActionEntity
from synapse_mcp.core.purple_team.gap_analysis import generate_gap_finding
from synapse_mcp.core.purple_team.technique_reference import TECHNIQUE_DETECTION_MAP, TechniqueReference
from synapse_mcp.transport import stdio_server


class DetectionGapGenerationTests(unittest.TestCase):
    def test_mark_detection_outcome_creates_gap_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_action("act-valid", "T1078")

                result = json.loads(
                    stdio_server.call_tool(
                        "mark_detection_outcome",
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "actionKey": "act-valid",
                            "detected": False,
                            "notes": "No alert was found in the debrief.",
                        },
                    )
                )
                gap = result["detectionGap"]

                self.assertFalse(gap["detected"])
                self.assertEqual(gap["criticality"], TECHNIQUE_DETECTION_MAP["T1078"].criticality)
                self.assertEqual(gap["mitreTechniqueId"], "T1078")

    def test_gap_finding_none_when_no_technique_tag(self) -> None:
        action = ActionEntity(actionId="act-no-tag", key="act-no-tag", tool="manual", target="example.com", summary="Action")

        self.assertIsNone(generate_gap_finding(action, False, "No alert."))

    def test_gap_finding_key_stable_on_re_mark(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_action("act-repeat", "T1078")
                stdio_server.call_tool(
                    "mark_detection_outcome",
                    {"workspaceId": "engagement", "target": "example.com", "actionKey": "act-repeat", "detected": False},
                )
                stdio_server.call_tool(
                    "mark_detection_outcome",
                    {"workspaceId": "engagement", "target": "example.com", "actionKey": "act-repeat", "detected": True},
                )

                gaps = workspace._load_target_entities("engagement", "example.com")["detectionGaps"]

                self.assertEqual(len(gaps), 1)
                self.assertTrue(gaps[0]["detected"])
                self.assertEqual(gaps[0]["key"], "gapfinding:example.com|act-repeat")

    def test_gap_finding_re_mark_to_unknown(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_action("act-unknown", "T1078")
                stdio_server.call_tool(
                    "mark_detection_outcome",
                    {"workspaceId": "engagement", "target": "example.com", "actionKey": "act-unknown", "detected": False},
                )
                stdio_server.call_tool(
                    "mark_detection_outcome",
                    {"workspaceId": "engagement", "target": "example.com", "actionKey": "act-unknown", "detected": None},
                )

                gaps = workspace._load_target_entities("engagement", "example.com")["detectionGaps"]

                self.assertEqual(len(gaps), 1)
                self.assertIsNone(gaps[0].get("detected"))

    def test_criticality_frozen_at_generation(self) -> None:
        action = ActionEntity(actionId="act-freeze", key="act-freeze", tool="manual", target="example.com", summary="Action", mitreTechniqueId="T1078")
        gap = generate_gap_finding(action, False, "No alert.")
        original = TECHNIQUE_DETECTION_MAP["T1078"]
        try:
            TECHNIQUE_DETECTION_MAP["T1078"] = TechniqueReference(
                techniqueId="T1078",
                name="Valid Accounts",
                expectedDetectionSources=["Changed source"],
                criticality="low",
            )
            self.assertEqual(gap.criticality, original.criticality)
        finally:
            TECHNIQUE_DETECTION_MAP["T1078"] = original


def _seed_action(action_id: str, technique_id: str | None) -> None:
    workspace.create_workspace("engagement", hosts=["example.com"])
    workspace.record_action(
        "engagement",
        "example.com",
        {
            "type": "tool_run",
            "tool": "manual",
            "actionId": action_id,
            "key": action_id,
            "target": "example.com",
            "summary": f"Action for {technique_id or 'untagged'}",
            **({"mitreTechniqueId": technique_id} if technique_id else {}),
        },
    )


if __name__ == "__main__":
    unittest.main()
