import unittest

from synapse_mcp.core.adapters import ActionEntity
from synapse_mcp.core.purple_team.technique_reference import TECHNIQUE_DETECTION_MAP, TechniqueReference


class TechniqueTaggingTests(unittest.TestCase):
    def test_action_entity_accepts_technique_id(self) -> None:
        action = ActionEntity(tool="manual", target="example.com", summary="Authenticated access", mitreTechniqueId="T1078")

        self.assertEqual(action.mitre_technique_id, "T1078")
        self.assertEqual(action.as_dict()["mitreTechniqueId"], "T1078")

    def test_action_entity_defaults_technique_id_none(self) -> None:
        action = ActionEntity(tool="manual", target="example.com", summary="Authenticated access")

        self.assertIsNone(action.mitre_technique_id)

    def test_technique_reference_lookup(self) -> None:
        reference = TECHNIQUE_DETECTION_MAP["T1078"]

        self.assertIsInstance(reference, TechniqueReference)
        self.assertEqual(reference.techniqueId, "T1078")
        self.assertTrue(reference.expectedDetectionSources)


if __name__ == "__main__":
    unittest.main()
