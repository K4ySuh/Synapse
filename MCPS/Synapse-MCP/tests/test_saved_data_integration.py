"""Passive saved-data integration pilot across canonical Synapse boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state
from synapse_mcp.adapters.web import spec_import
from synapse_mcp.app.actions import ActionRegistry, PassThroughPolicyEvaluator, REGISTRY
from synapse_mcp.app.facade import (
    ActionExecutionService,
    CompactFacadeService,
    FacadeCallContext,
    OperationHandleService,
    ResourceReferenceService,
)
from synapse_mcp.core import documentation, saved_spec_import, workspace


FIXTURE = Path(__file__).parent / "fixtures" / "integrations" / "saved-openapi.json"


class SavedDataIntegrationPilotTests(unittest.TestCase):
    def test_saved_spec_contribution_context_and_report_projection(self) -> None:
        raw_spec = FIXTURE.read_text(encoding="utf-8")
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("pilot", hosts=["api.example.test"])

                dry_run = {
                    "workspaceId": "pilot",
                    "target": "api.example.test",
                    "rawData": raw_spec,
                    "ingest": False,
                }
                self.assertEqual(
                    json.loads(spec_import.import_spec(dry_run)),
                    json.loads(saved_spec_import.import_spec(dry_run)),
                )
                imported = json.loads(spec_import.import_spec({**dry_run, "ingest": True}))
                import_evidence = imported["ingestion"]["evidenceId"]
                self.assertEqual(imported["endpointCount"], 2)
                self.assertEqual(imported["parameterCount"], 2)

                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                resources = ResourceReferenceService(state_path=root / "resources.json")
                service = ActionExecutionService(
                    registry=registry,
                    resources=resources,
                    operations=OperationHandleService(state_path=root / "operations.json"),
                )
                context = FacadeCallContext(
                    principal_id="consumer:pilot",
                    workspace_id="pilot",
                    authority_session_id="session:pilot",
                    execution_profile="observe",
                )
                contribution = {
                    "schemaVersion": "1.0",
                    "requestId": "pilot-health-001",
                    "producer": {"name": "pilot-fixture", "version": "1.0.0"},
                    "entities": {
                        "endpoints": [
                            {
                                "url": "https://api.example.test/health",
                                "method": "GET",
                                "source": "pilot-fixture",
                            }
                        ]
                    },
                }
                accepted = service.run(
                    operation="actions.run_passive",
                    action_id="workspace.ingest_data",
                    arguments={
                        "workspaceId": "pilot",
                        "target": "api.example.test",
                        "source": "contribution.v1",
                        "format": "json",
                        "rawData": json.dumps(contribution),
                    },
                    context=context,
                    passive_only=True,
                )
                self.assertEqual(accepted.outcome_kind, "success")
                receipt = accepted.result
                self.assertEqual(receipt["schemaVersion"], "1.0")
                self.assertEqual(receipt["insertedCounts"]["endpoints"], 1)
                self.assertEqual(len(receipt["canonicalRecordIds"]["endpoints"]), 1)
                self.assertEqual(len(receipt["evidenceIds"]), 1)

                recovered = CompactFacadeService(resources=resources).invoke(
                    "context.query",
                    {
                        "workspaceId": "pilot",
                        "targets": ["api.example.test"],
                        "entityTypes": ["endpoint", "parameter", "documented_auth_scheme"],
                        "maxTokens": 30_000,
                    },
                    context=context,
                )
                self.assertEqual(recovered.outcome_kind, "success")
                facts = recovered.result["confirmedFacts"]
                recovered_urls = {
                    item.get("attributes", {}).get("url")
                    for item in facts
                    if item.get("kind") == "endpoint"
                }
                self.assertEqual(
                    recovered_urls,
                    {
                        "https://api.example.test/v1/items",
                        "https://api.example.test/health",
                    },
                )
                recovered_evidence = {
                    evidence_id
                    for item in facts
                    for evidence_id in item.get("evidenceReferences", [])
                }
                self.assertIn(import_evidence, recovered_evidence)
                self.assertIn(receipt["evidenceIds"][0], recovered_evidence)

                report = documentation.build_report_context(
                    {"workspaceId": "pilot", "target": "api.example.test"}
                )
                target = report["report"]["targets"][0]
                self.assertEqual(target["endpointCount"], 3)
                self.assertEqual(target["parameterCount"], 2)

                stored = workspace._activated_repository("pilot").collection(
                    "api.example.test", "endpoints"
                )
                spec_rows = [item for item in stored if item.get("source") == "spec_import"]
                self.assertEqual(len(spec_rows), 2)
                self.assertTrue(all(item.get("inferred") and item.get("observed") is False for item in spec_rows))

    def test_registry_retains_the_public_action_and_legacy_alias(self) -> None:
        descriptor = REGISTRY.get("spec_import.import_spec")
        self.assertEqual(descriptor.legacy_aliases, ("spec_import.import_spec",))
        self.assertEqual(
            REGISTRY.action_id_for_legacy_alias("spec_import.import_spec"),
            "spec_import.import_spec",
        )
        schema = descriptor.input_model.model_json_schema(mode="validation", by_alias=True)
        self.assertEqual(set(schema["required"]), {"workspaceId", "target", "rawData"})
        self.assertEqual(schema["properties"]["format"]["enum"], ["openapi", "swagger", "postman"])


if __name__ == "__main__":
    unittest.main()
