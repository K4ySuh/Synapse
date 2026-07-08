import inspect
import unittest

from synapse_mcp.adapters.social import pretext_generator


class PretextGeneratorParseTests(unittest.TestCase):
    def test_parse_valid_pretext_minimal(self) -> None:
        entity = pretext_generator.parse_adapter_result(
            {
                "type": "pretext_candidate",
                "subject": "Quarterly access review",
                "senderPersona": "IT service desk",
                "bodyTemplate": "Please review the attached access report.",
                "sophisticationTier": "medium",
            }
        )

        self.assertEqual(entity.status, "draft")
        self.assertEqual(entity.source_observation_refs, [])
        self.assertEqual(entity.as_dict()["senderPersona"], "IT service desk")

    def test_parse_rejects_invalid_sophistication_tier(self) -> None:
        with self.assertRaises(ValueError):
            pretext_generator.parse_adapter_result(
                {
                    "type": "pretext_candidate",
                    "subject": "Quarterly access review",
                    "senderPersona": "IT service desk",
                    "bodyTemplate": "Please review the attached access report.",
                    "sophisticationTier": "extreme",
                }
            )

    def test_parse_is_context_free(self) -> None:
        signature = inspect.signature(pretext_generator.parse_adapter_result)
        self.assertEqual(list(signature.parameters), ["raw"])


if __name__ == "__main__":
    unittest.main()
