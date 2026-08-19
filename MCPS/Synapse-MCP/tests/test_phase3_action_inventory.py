"""Phase 3A accounting and frozen-equivalence gates for all canonical actions."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from synapse_mcp.adapters.infra import shodan_adapter
from synapse_mcp.app.actions import (
    ActionInput,
    ActionEffects,
    ActionOutput,
    ActionRequest,
    CredentialAccess,
    CredentialRequirement,
    ExecutionContext,
    REGISTRY,
    RiskClass,
    ScopeRequirement,
    UnavailableCapability,
)
from synapse_mcp.app.actions.inventory import action_inventory, action_inventory_document
from synapse_mcp.transport import projection, stdio_server
from synapse_mcp.transport.legacy_projection_map import LEGACY_DISPATCH_ACTIONS, LEGACY_PROJECTION_MAP


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TOOLS_FIXTURE = Path(__file__).parent / "fixtures" / "legacy_contracts" / "tools_list.json"


class Phase3ActionInventoryTests(unittest.TestCase):
    def test_checked_in_inventory_is_reproducible(self) -> None:
        completed = subprocess.run(
            [str(REPOSITORY_ROOT / "bin" / "generate-action-inventory"), "--check"],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("174 actions", completed.stdout)

    def test_inventory_registry_and_projection_are_complete_and_ordered(self) -> None:
        entries = action_inventory()
        action_ids = tuple(str(entry["actionId"]) for entry in entries)
        aliases = tuple(str(entry["legacyName"]) for entry in entries)
        descriptors = REGISTRY.descriptors()

        self.assertEqual(len(entries), 174)
        self.assertEqual(len(set(action_ids)), 174)
        self.assertEqual(len(set(aliases)), 174)
        self.assertEqual(tuple(str(descriptor.id) for descriptor in descriptors), action_ids)
        self.assertEqual(tuple(LEGACY_PROJECTION_MAP), action_ids)
        self.assertEqual(LEGACY_DISPATCH_ACTIONS, frozenset(action_ids))
        self.assertEqual(
            tuple(projection.legacy_name for projection in LEGACY_PROJECTION_MAP.values()),
            aliases,
        )
        self.assertEqual(REGISTRY.legacy_aliases(), dict(zip(aliases, action_ids)))
        self.assertEqual(len(REGISTRY.packs()), 40)
        self.assertEqual(sum(Counter(entry["pack"] for entry in entries).values()), 174)

    def test_every_inventory_row_matches_its_executable_descriptor(self) -> None:
        for entry in action_inventory():
            action_id = str(entry["actionId"])
            with self.subTest(action=action_id):
                descriptor = REGISTRY.get(action_id)
                self.assertEqual(descriptor.pack, entry["pack"])
                self.assertEqual(descriptor.legacy_aliases, (entry["legacyName"],))
                self.assertEqual(descriptor.legacy_serializer, entry["serializer"])
                self.assertEqual(descriptor.implementation_ref, entry["implementationTarget"])
                self.assertEqual(descriptor.approval_required, entry["confirmDeclared"])
                self.assertEqual(descriptor.input_model.__name__, entry["inputModel"])
                self.assertEqual(descriptor.output_model.__name__, entry["outputModel"])
                self.assertTrue(issubclass(descriptor.input_model, ActionInput))
                self.assertTrue(issubclass(descriptor.output_model, ActionOutput))
                output_schema = descriptor.output_model.model_json_schema(mode="validation")
                self.assertEqual(output_schema.get("type"), "object")
                self.assertTrue(
                    output_schema.get("properties"),
                    f"{action_id} has an empty output contract",
                )
                self.assertEqual(descriptor.input_model.contract_document.parsed(), entry["inputSchema"])
                self.assertEqual(descriptor.risk_class, RiskClass(entry["riskClass"]))
                self.assertEqual(
                    descriptor.scope_policy.requirement,
                    ScopeRequirement(entry["scopeRequirement"]),
                )
                self.assertEqual(
                    descriptor.credential_policy.requirement,
                    CredentialRequirement(entry["credentialRequirement"]),
                )
                self.assertEqual(
                    descriptor.credential_policy.access,
                    CredentialAccess(entry["credentialAccess"]),
                )
                self.assertTrue(
                    descriptor.effects.permits(
                        ActionEffects(
                            replay_safety=descriptor.effects.replay_safety.__class__(
                                entry["idempotency"]["behaviour"]
                            )
                        )
                    ),
                    f"{action_id} maximum effects do not cover reviewed replay classification",
                )
                self.assertEqual(
                    descriptor.idempotency_policy.behaviour.value,
                    entry["idempotency"]["behaviour"],
                )
                self.assertEqual(
                    descriptor.idempotency_policy.condition,
                    entry["idempotency"]["condition"],
                )
                self.assertEqual(
                    descriptor.task_policy.background_capable,
                    entry["taskMode"] == "background_capable",
                )
                self.assertEqual(
                    descriptor.task_policy.deadline_tier.name.lower(),
                    entry["deadlineTier"],
                )
                self.assertEqual(
                    descriptor.task_policy.passive_recordable,
                    entry["passiveRecordable"],
                )
                self.assertEqual(entry["migrationStatus"], "migrated")
                self.assertEqual(
                    entry["parityTest"],
                    "MCPS/Synapse-MCP/tests/test_phase3_action_inventory.py",
                )

    def test_frozen_legacy_names_order_descriptions_schemas_and_payload_are_exact(self) -> None:
        expected = json.loads(TOOLS_FIXTURE.read_text(encoding="utf-8"))["result"]["tools"]
        actual = stdio_server.TOOL_SCHEMAS
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 174)
        self.assertEqual(len(json.dumps(actual, separators=(",", ":")).encode("utf-8")), 99_337)
        inventory = action_inventory_document()
        self.assertEqual(inventory["legacyCompactPayloadBytes"], 99_337)

    def test_missing_optional_scanner_binaries_are_typed_unavailability(self) -> None:
        cases = {
            "ffuf.run_profile": {
                "target": "https://app.example.test",
                "wordlist": "/tmp/wordlist",
                "confirm": True,
            },
            "nuclei.run_profile": {"target": "https://app.example.test", "confirm": True},
            "nmap.run_profile": {"target": "app.example.test", "confirm": True},
        }
        with patch("synapse_mcp.app.actions.catalog.shutil.which", return_value=None):
            for action_id, arguments in cases.items():
                with self.subTest(action=action_id):
                    descriptor = REGISTRY.get(action_id)
                    request = ActionRequest(
                        input=descriptor.input_model.model_validate(arguments),
                        context=ExecutionContext(None, "availability-test", 45.0, True),
                    )
                    outcome = REGISTRY.execute(action_id, request)
                    self.assertIsInstance(outcome, UnavailableCapability)
                    self.assertEqual(outcome.reason_code, "missing_optional_binary")

    def test_missing_provider_configuration_is_typed_unavailability(self) -> None:
        descriptor = REGISTRY.get("shodan.host")
        request = ActionRequest(
            input=descriptor.input_model.model_validate(
                {"ip": "127.0.0.1", "confirm": True}
            ),
            context=ExecutionContext(None, "provider-availability-test", 45.0, True),
        )
        with patch.object(shodan_adapter, "_SESSION_API_KEY", ""):
            outcome = REGISTRY.execute("shodan.host", request)
        self.assertIsInstance(outcome, UnavailableCapability)
        self.assertEqual(outcome.legacy_code, -32001)

    def test_generated_output_contract_preserves_background_job_identity(self) -> None:
        model = REGISTRY.get("crawler.extended").output_model
        output = model.model_validate(
            {
                "background": True,
                "job": {"jobId": "job-fixture", "status": "running"},
                "target": "https://app.example.test",
            }
        )
        dumped = output.model_dump(mode="json", by_alias=True)
        self.assertTrue(dumped["background"])
        self.assertEqual(dumped["job"]["jobId"], "job-fixture")
        self.assertEqual(dumped["target"], "https://app.example.test")


if __name__ == "__main__":
    unittest.main()
