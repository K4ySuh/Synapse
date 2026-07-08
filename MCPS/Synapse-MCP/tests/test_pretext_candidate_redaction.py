import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.transport import stdio_server


class PretextCandidateRedactionTests(unittest.TestCase):
    def test_operator_report_includes_body_template(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                entity_key = _seed_pretext()
                stdio_server.call_tool(
                    "approve_pretext_candidate",
                    {"workspaceId": "engagement", "target": "example.com", "entityKey": entity_key, "confirm": True},
                )

                rendered = _render_summary("internal")

                self.assertIn("BODY-SECRET-PRETEXT", rendered)

    def test_safe_report_excludes_all_sensitive_pretext_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                entity_key = _seed_pretext()
                stdio_server.call_tool(
                    "approve_pretext_candidate",
                    {"workspaceId": "engagement", "target": "example.com", "entityKey": entity_key, "confirm": True},
                )

                rendered = _render_summary("high_level")

                self.assertNotIn("BODY-SECRET-PRETEXT", rendered)
                self.assertNotIn("HR operations persona", rendered)
                self.assertNotIn("Finance VP Q4 Payroll", rendered)
                self.assertIn("1 medium-sophistication pretext approved", rendered)

    def test_safe_report_empty_section_still_renders(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", hosts=["example.com"])

                rendered = _render_summary("high_level")

                self.assertIn("## Pretext Candidates", rendered)
                self.assertIn("No pretext candidates recorded.", rendered)


def _seed_pretext() -> str:
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
    return workspace._load_target_entities("engagement", "example.com")["pretextCandidates"][0]["key"]


def _render_summary(mode: str) -> str:
    return json.loads(
        stdio_server.call_tool(
            "documentation.render_assessment_summary",
            {
                "workspaceId": "engagement",
                "redactionMode": mode,
                "outputPath": f"reports/{mode}-summary.md",
            },
        )
    )["content"]


if __name__ == "__main__":
    unittest.main()
