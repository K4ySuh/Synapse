import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.transport import stdio_server


class PretextGeneratorGateTests(unittest.TestCase):
    def test_approve_without_confirm_is_noop(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                entity_key = _seed_pretext()

                result = json.loads(
                    stdio_server.call_tool(
                        "approve_pretext_candidate",
                        {"workspaceId": "engagement", "target": "example.com", "entityKey": entity_key, "confirm": False},
                    )
                )
                pretext = workspace._load_target_entities("engagement", "example.com")["pretextCandidates"][0]

                self.assertFalse(result["approved"])
                self.assertTrue(result["requiresConfirmation"])
                self.assertEqual(pretext["status"], "draft")
                self.assertNotIn("approvedAt", pretext)

    def test_approve_with_confirm_transitions_status(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                entity_key = _seed_pretext()

                result = json.loads(
                    stdio_server.call_tool(
                        "approve_pretext_candidate",
                        {"workspaceId": "engagement", "target": "example.com", "entityKey": entity_key, "confirm": True},
                    )
                )

                self.assertTrue(result["approved"])
                self.assertEqual(result["pretextCandidate"]["status"], "approved")
                self.assertIn("approvedAt", result["pretextCandidate"])

    def test_registry_marks_high_risk(self) -> None:
        capabilities = json.loads(stdio_server.call_tool("adapters.capabilities", {"adapter": "pretext_generator"}))

        self.assertTrue(capabilities["requiresConfirmation"])
        self.assertEqual(capabilities["defaultRiskTier"], "high")


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
                            "subject": "Payroll portal update",
                            "senderPersona": "HR operations",
                            "bodyTemplate": "Please confirm your payroll profile.",
                            "sophisticationTier": "medium",
                        }
                    ]
                }
            }
        ),
    )
    pretext = workspace._load_target_entities("engagement", "example.com")["pretextCandidates"][0]
    return pretext["key"]


if __name__ == "__main__":
    unittest.main()
