import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.transport import stdio_server


class EngagementReportLayerTests(unittest.TestCase):
    def test_operator_workspace_report_includes_pretext_body_and_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_engagement()

                rendered = _render_workspace("internal")

                self.assertIn("Engagement Coverage", rendered)
                self.assertIn("Phishing Pretext Candidates", rendered)
                self.assertIn("BODY-SECRET-PRETEXT", rendered)
                self.assertIn("Detection Coverage", rendered)
                self.assertIn("T1078", rendered)

    def test_high_level_workspace_report_strips_pretext_and_excludes_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_engagement()

                rendered = _render_workspace("high_level")

                # Aggregate pretext line survives; sensitive detail does not.
                self.assertIn("Phishing Pretext Candidates", rendered)
                self.assertIn("medium-sophistication pretext", rendered)
                self.assertNotIn("BODY-SECRET-PRETEXT", rendered)
                self.assertNotIn("Finance VP Q4 Payroll", rendered)
                self.assertNotIn("HR operations persona", rendered)
                # Detection coverage is operator-only: fully absent in the safe render.
                self.assertNotIn("Detection Coverage", rendered)
                self.assertNotIn("T1078", rendered)

    def test_empty_engagement_layer_still_renders(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", hosts=["example.com"])

                rendered = _render_workspace("internal")

                self.assertIn("Engagement Coverage", rendered)
                self.assertIn("No pretext candidates recorded.", rendered)


def _seed_engagement() -> None:
    workspace.create_workspace("engagement", hosts=["example.com"])
    workspace.ingest_data(
        "engagement",
        "example.com",
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "pretextCandidates": [
                        {
                            "type": "pretext_candidate",
                            "subject": "Finance VP Q4 Payroll",
                            "senderPersona": "HR operations persona",
                            "bodyTemplate": "BODY-SECRET-PRETEXT",
                            "sophisticationTier": "medium",
                        }
                    ]
                }
            }
        ),
    )
    workspace.record_action(
        "engagement",
        "example.com",
        {
            "type": "tool_run",
            "tool": "manual",
            "actionId": "act-1",
            "key": "act-1",
            "target": "example.com",
            "summary": "Valid accounts",
            "mitreTechniqueId": "T1078",
        },
    )
    stdio_server.call_tool(
        "mark_detection_outcome",
        {"workspaceId": "engagement", "target": "example.com", "actionKey": "act-1", "detected": False, "notes": "no alert"},
    )


def _render_workspace(mode: str) -> str:
    return json.loads(
        stdio_server.call_tool(
            "documentation.render_workspace_report",
            {
                "workspaceId": "engagement",
                "redactionMode": mode,
                "format": "markdown",
                "returnContent": True,
                "outputPath": f"reports/{mode}-workspace.md",
            },
        )
    )["content"]


if __name__ == "__main__":
    unittest.main()
