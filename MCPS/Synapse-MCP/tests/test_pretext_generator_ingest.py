import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.adapters.social import pretext_generator
from synapse_mcp.core import workspace
from synapse_mcp.core.adapters import PretextCandidateEntity


class PretextGeneratorIngestTests(unittest.TestCase):
    def test_ingest_flags_missing_observation_ref(self) -> None:
        entity = PretextCandidateEntity(
            subject="Payroll portal update",
            senderPersona="HR operations",
            bodyTemplate="Please confirm your payroll profile.",
            sophisticationTier="medium",
            sourceObservationRefs=["obs:does-not-exist"],
        )

        normalized = pretext_generator.ingest_data(entity, "engagement", "example.com", {"observations": []}).as_dict()

        self.assertEqual(normalized["missingEvidenceIds"], ["obs:does-not-exist"])
        self.assertEqual(normalized["sourceObservationRefs"], ["obs:does-not-exist"])

    def test_entity_key_stable_across_body_edit(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", hosts=["example.com"])
                first = {
                    "entities": {
                        "pretextCandidates": [
                            {
                                "type": "pretext_candidate",
                                "subject": "Payroll portal update",
                                "senderPersona": "HR operations",
                                "bodyTemplate": "First draft body.",
                                "sophisticationTier": "medium",
                            }
                        ]
                    }
                }
                second = {
                    "entities": {
                        "pretextCandidates": [
                            {
                                "type": "pretext_candidate",
                                "subject": "Payroll portal update",
                                "senderPersona": "HR operations",
                                "bodyTemplate": "Refined body.",
                                "sophisticationTier": "medium",
                            }
                        ]
                    }
                }

                workspace.ingest_data("engagement", "example.com", "adapter_result", "adapter_result", "json", json.dumps(first))
                workspace.ingest_data("engagement", "example.com", "adapter_result", "adapter_result", "json", json.dumps(second))
                pretexts = workspace._load_target_entities("engagement", "example.com")["pretextCandidates"]

                self.assertEqual(len(pretexts), 1)
                self.assertEqual(pretexts[0]["bodyTemplate"], "Refined body.")

    def test_entity_key_differs_by_persona(self) -> None:
        base = {
            "type": "pretext_candidate",
            "target": "example.com",
            "subject": "Payroll portal update",
            "bodyTemplate": "Please confirm your payroll profile.",
            "sophisticationTier": "medium",
        }

        first_key = workspace._entity_key({**base, "senderPersona": "HR operations"})
        second_key = workspace._entity_key({**base, "senderPersona": "IT service desk"})

        self.assertNotEqual(first_key, second_key)


if __name__ == "__main__":
    unittest.main()
