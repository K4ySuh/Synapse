import json
import unittest
from dataclasses import fields

from pydantic import ValidationError

from synapse_mcp.app.actions import (
    ActionDescriptor,
    ActionId,
    ApprovalRequired,
    Availability,
    ExecutionFailure,
    Idempotency,
    IdempotencyPolicy,
    InputContractDocument,
    PolicyDenial,
    SideEffectClass,
    UnavailableCapability,
    ValidationFailure,
    legacy_payload_signals_error,
    make_input_model,
    outcome_from_mcp_error,
    success_from_legacy_payload,
)
from synapse_mcp.core.errors import McpError


def input_document(schema: dict) -> InputContractDocument:
    return InputContractDocument(json.dumps(schema, separators=(",", ":")))


class ActionContractTests(unittest.TestCase):
    def test_action_id_splits_at_first_dot(self) -> None:
        workspace_id = ActionId.parse("workspace.summary")
        self.assertEqual((workspace_id.pack, workspace_id.local_name), ("workspace", "summary"))
        self.assertEqual(str(workspace_id), "workspace.summary")

        cve_id = ActionId.parse("cve.session_key.set")
        self.assertEqual((cve_id.pack, cve_id.local_name), ("cve", "session_key.set"))
        self.assertEqual(str(cve_id), "cve.session_key.set")

    def test_action_id_rejects_dotless_and_malformed_segments(self) -> None:
        for malformed in ("approve_pretext_candidate", "Workspace.summary", "workspace..summary"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    ActionId.parse(malformed)

    def test_side_effect_class_has_no_background_submit_member(self) -> None:
        self.assertNotIn("BACKGROUND_SUBMIT", SideEffectClass.__members__)
        self.assertEqual(len(SideEffectClass), 11)

    def test_conditional_idempotency_requires_a_condition(self) -> None:
        with self.assertRaises(ValueError):
            IdempotencyPolicy(Idempotency.CONDITIONAL)
        with self.assertRaises(ValueError):
            IdempotencyPolicy(Idempotency.PURE_READ, condition="only sometimes")

        policy = IdempotencyPolicy(Idempotency.CONDITIONAL, condition="when background=true")
        self.assertEqual(policy.condition, "when background=true")

    def test_unavailable_requires_a_reason(self) -> None:
        with self.assertRaises(ValueError):
            Availability(available=False)
        self.assertEqual(Availability(available=False, reason="dependency absent").reason, "dependency absent")

    def test_input_model_does_not_coerce_integer_strings(self) -> None:
        document = input_document(
            {
                "type": "object",
                "properties": {"maxTokens": {"type": "integer"}},
                "required": ["maxTokens"],
            }
        )
        model = make_input_model("TokenInput", document)

        with self.assertRaises(ValidationError):
            model.model_validate({"maxTokens": "900"})
        self.assertEqual(model.model_validate({"maxTokens": 900}).maxTokens, 900)

    def test_input_model_accepts_unknown_public_fields_and_rejects_underscore_fields(self) -> None:
        model = make_input_model(
            "PermissiveInput",
            input_document({"type": "object", "properties": {"workspaceId": {"type": "string"}}}),
        )

        validated = model.model_validate({"workspaceId": "demo", "totallyUnknownArg": 42})
        self.assertEqual(validated.totallyUnknownArg, 42)
        with self.assertRaises(ValidationError):
            model.model_validate({"workspaceId": "demo", "_internal": True})

    def test_required_confirm_becomes_runtime_optional_but_stays_in_the_document(self) -> None:
        document = input_document(
            {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "confirm": {"type": "boolean"},
                },
                "required": ["target", "confirm"],
            }
        )
        model = make_input_model("ConfirmedInput", document)

        validated = model.model_validate({"target": "https://example.test"})
        self.assertIsNone(validated.confirm)
        self.assertIn("confirm", model.contract_document.parsed()["required"])

    def test_input_model_applies_document_defaults_exactly(self) -> None:
        default_tags = ["security", "review"]
        document = input_document(
            {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 50},
                    "tags": {"type": "array", "items": {"type": "string"}, "default": default_tags},
                },
            }
        )
        model = make_input_model("DefaultsInput", document)

        validated = model.model_validate({})
        self.assertEqual(validated.limit, 50)
        self.assertEqual(validated.tags, default_tags)

    def test_input_model_preserves_nested_union_enum_and_extra_constraints(self) -> None:
        document = input_document(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "source": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ]
                    },
                    "mode": {"type": "string", "enum": ["safe", "expert"]},
                    "options": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 3}},
                        "required": ["limit"],
                    },
                },
                "required": ["source", "mode", "options"],
            }
        )
        model = make_input_model("NestedInput", document)

        self.assertEqual(
            model.model_validate({"source": ["nvd"], "mode": "safe", "options": {"limit": 2}}).source,
            ["nvd"],
        )
        invalid_values = (
            {"source": 1, "mode": "safe", "options": {"limit": 2}},
            {"source": "nvd", "mode": "unknown", "options": {"limit": 2}},
            {"source": "nvd", "mode": "safe", "options": {"limit": 0}},
            {"source": "nvd", "mode": "safe", "options": {"limit": 2, "extra": True}},
            {"source": "nvd", "mode": "safe", "options": {"limit": 2}, "extra": True},
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                model.model_validate(value)

    def test_input_model_rejects_unknown_validation_keyword(self) -> None:
        with self.assertRaisesRegex(ValueError, r"Unsupported input schema keyword.*pattern"):
            make_input_model(
                "UnsupportedPatternInput",
                input_document(
                    {
                        "type": "object",
                        "properties": {"name": {"type": "string", "pattern": "^[a-z]+$"}},
                    }
                ),
            )

    def test_outcome_from_mcp_error_maps_every_code_and_preserves_legacy_code(self) -> None:
        cases = (
            (-32602, ValidationFailure),
            (-32002, PolicyDenial),
            (-32000, ExecutionFailure),
            (-32003, ExecutionFailure),
            (-32001, UnavailableCapability),
            (-32999, ExecutionFailure),
        )
        for code, expected_type in cases:
            with self.subTest(code=code):
                message = f"legacy message {code}"
                outcome = outcome_from_mcp_error(McpError(code, message))
                self.assertIsInstance(outcome, expected_type)
                self.assertEqual(outcome.legacy_code, code)
                self.assertEqual(outcome.message, message)

    def test_minus_32001_maps_to_approval_required_only_when_confirm_is_declared(self) -> None:
        error = McpError(-32001, "Confirmation is required.")

        approval = outcome_from_mcp_error(error, confirm_declared=True, confirm_value=None)
        unavailable = outcome_from_mcp_error(error, confirm_declared=False, confirm_value=None)
        asserted = outcome_from_mcp_error(error, confirm_declared=True, confirm_value=True)

        self.assertIsInstance(approval, ApprovalRequired)
        self.assertIsInstance(unavailable, UnavailableCapability)
        self.assertIsInstance(asserted, UnavailableCapability)
        self.assertEqual(approval.legacy_code, -32001)
        self.assertEqual(unavailable.legacy_code, -32001)

    def test_legacy_success_payload_signal_handles_raw_and_serialized_results(self) -> None:
        raw = {"error": "legacy payload error"}
        serialized = json.dumps(raw)

        self.assertTrue(legacy_payload_signals_error(raw))
        self.assertTrue(legacy_payload_signals_error(serialized))
        self.assertTrue(success_from_legacy_payload(raw).payload_signals_error)
        self.assertTrue(success_from_legacy_payload(serialized).payload_signals_error)
        self.assertFalse(legacy_payload_signals_error({"error": ""}))
        self.assertFalse(legacy_payload_signals_error("not-json"))

    def test_descriptor_has_canonical_effects_and_no_authoritative_singular_label(self) -> None:
        self.assertEqual(
            [field.name for field in fields(ActionDescriptor)],
            [
                "id",
                "pack",
                "title",
                "summary",
                "input_model",
                "output_model",
                "effects",
                "effect_resolver",
                "risk_class",
                "scope_policy",
                "credential_policy",
                "task_policy",
                "executor",
                "availability",
            ],
        )
        self.assertNotIn("side_effect_class", [field.name for field in fields(ActionDescriptor)])


if __name__ == "__main__":
    unittest.main()
