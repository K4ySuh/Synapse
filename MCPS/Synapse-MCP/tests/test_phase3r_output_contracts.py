"""Phase 3R standard output-contract gates."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state
from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.app.actions.contracts import OUTPUT_CONTRACTS
from synapse_mcp.app.actions.legacy_bridge import RetainedLegacyExecutor
from synapse_mcp.app.facade import CompactProjection, DirectProjection
from synapse_mcp.app.facade.contracts import FacadeCallContext, FacadeEnvelope
from synapse_mcp.core import workspace


class Phase3ROutputContractTests(unittest.TestCase):
    def test_retained_contracts_are_derived_action_specific_and_nonempty(self) -> None:
        retained = [
            descriptor
            for descriptor in REGISTRY.descriptors()
            if isinstance(descriptor.executor, RetainedLegacyExecutor)
        ]
        self.assertEqual(len(retained), 168)
        self.assertEqual(set(OUTPUT_CONTRACTS), {str(descriptor.id) for descriptor in retained})
        shapes = set()
        for descriptor in retained:
            action_id = str(descriptor.id)
            declaration = OUTPUT_CONTRACTS[action_id]
            self.assertTrue(declaration["fields"], action_id)
            self.assertTrue(declaration["sources"][0].startswith("implementation:"), action_id)
            schema = descriptor.output_model.model_json_schema(mode="validation", by_alias=True)
            self.assertEqual(schema["x-synapse-action-id"], action_id)
            self.assertIn("x-synapse-dynamic-boundary", schema)
            public_shape = {
                key: value
                for key, value in schema.items()
                if key not in {"title", "x-synapse-action-id", "x-synapse-contract-sources"}
            }
            shapes.add(json.dumps(public_shape, sort_keys=True))
        self.assertGreaterEqual(len(shapes), 130)

    def test_retained_array_roots_remain_valid_and_truthful(self) -> None:
        expected = {"dumps.list", "evidence.tail"}
        declared = {
            action_id
            for action_id, contract in OUTPUT_CONTRACTS.items()
            if contract["rootType"] == "array"
        }
        self.assertEqual(declared, expected)
        for action_id in expected:
            self.assertEqual(REGISTRY.get(action_id).output_model.model_json_schema()["type"], "array")

    def test_every_direct_standard_envelope_is_action_bound_and_unique(self) -> None:
        operations = DirectProjection().operations()
        self.assertEqual(len(operations), 174)
        encoded = set()
        for operation in operations:
            schema = operation.output_schema
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["properties"]["operation"]["const"], operation.name)
            self.assertEqual(schema["properties"]["actionId"]["const"], operation.name)
            self.assertEqual(schema["x-synapse-action-output"], operation.name)
            self.assertEqual(len(schema["oneOf"]), 3)
            encoded.add(json.dumps(schema, sort_keys=True))
        self.assertEqual(len(encoded), 174)

    def test_representative_direct_outcomes_match_their_standard_envelope_shape(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary)):
            workspace.create_workspace("output-contracts", hosts=["app.example.test"])
            projection = DirectProjection()
            context = FacadeCallContext(principal_id="legacy-test", execution_profile="legacy")
            success = projection.invoke(
                "workspace.summary",
                {"workspaceId": "output-contracts"},
                context=context,
            )
            self.assertEqual(success.outcome_kind, "success")
            schema = next(
                operation.output_schema
                for operation in projection.operations()
                if operation.name == "workspace.summary"
            )
            payload = success.model_dump(mode="json", by_alias=True)
            self.assertEqual(payload["operation"], "workspace.summary")
            self.assertEqual(payload["actionId"], "workspace.summary")
            self.assertIsInstance(payload["result"], dict)
            for outcome_kind in (
                "approval_required",
                "validation_failure",
                "unavailable_capability",
                "policy_denial",
                "execution_failure",
                "execution_unknown",
            ):
                envelope = FacadeEnvelope(
                    operation="workspace.summary",
                    action_id="workspace.summary",
                    outcome_kind=outcome_kind,
                    summary=outcome_kind,
                    requested_input={"review": "operator_authority"} if outcome_kind == "approval_required" else None,
                    trace_id="trace-output-contract",
                    operation_handle="opaque-handle" if outcome_kind == "approval_required" else None,
                ).model_dump(mode="json", by_alias=True)
                self.assertIn(envelope["outcomeKind"], schema["properties"]["outcomeKind"]["enum"])
                if outcome_kind == "approval_required":
                    self.assertIsInstance(envelope["requestedInput"], dict)
                    self.assertIsInstance(envelope["operationHandle"], str)
                else:
                    self.assertIsNone(envelope["result"])

    def test_compact_standard_schemas_name_all_outcomes_and_approval_carrier(self) -> None:
        for operation in CompactProjection().operations():
            schema = operation.output_schema
            self.assertEqual(schema["properties"]["operation"]["const"], operation.name)
            self.assertEqual(
                set(schema["properties"]["outcomeKind"]["enum"]),
                {
                    "success",
                    "approval_required",
                    "validation_failure",
                    "unavailable_capability",
                    "policy_denial",
                    "execution_failure",
                    "execution_unknown",
                },
            )
            approval = schema["allOf"][0]
            self.assertEqual(
                approval["if"]["properties"]["outcomeKind"]["const"],
                "approval_required",
            )
            self.assertEqual(
                approval["then"]["properties"]["operationHandle"]["type"],
                "string",
            )


if __name__ == "__main__":
    unittest.main()
