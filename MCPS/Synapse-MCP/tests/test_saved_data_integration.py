"""Passive saved-data integration pilot across canonical Synapse boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state
from synapse_mcp import guidance
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
    def test_saved_spec_reaches_method_contribution_without_heuristic_action(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("saved-only", hosts=["api.example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                self.assertEqual(
                    {str(descriptor.id) for descriptor in registry.descriptors()},
                    {"workspace.ingest_data"},
                )
                resources = ResourceReferenceService(state_path=root / "resources.json")
                service = ActionExecutionService(
                    registry=registry,
                    resources=resources,
                    operations=OperationHandleService(state_path=root / "operations.json"),
                )
                context = FacadeCallContext(
                    principal_id="consumer:saved-only",
                    workspace_id="saved-only",
                    authority_session_id="session:saved-only",
                    execution_profile="observe",
                )
                imported = spec_import.import_spec({
                    "workspaceId": "saved-only",
                    "target": "api.example.test",
                    "rawData": FIXTURE.read_text(encoding="utf-8"),
                    "ingest": True,
                })
                evidence_id = json.loads(imported)["ingestion"]["evidenceId"]
                recovered = CompactFacadeService(resources=resources).invoke(
                    "context.query",
                    {"workspaceId": "saved-only", "targets": ["api.example.test"], "maxTokens": 30_000},
                    context=context,
                )
                self.assertEqual(recovered.outcome_kind, "success")
                endpoint = next(
                    item for item in recovered.result["confirmedFacts"]
                    if item.get("kind") == "endpoint"
                    and item.get("attributes", {}).get("url") == "https://api.example.test/v1/items"
                )
                method = next(
                    package for package in guidance.build_guidance_snapshot().packages
                    if package["id"] == "synapse-web-access-control"
                )
                analysis = {
                    "schemaVersion": "1.1",
                    "requestId": "saved-only-access-question-001",
                    "producer": {"name": "saved-data-fixture", "version": "1.0.0"},
                    "evidenceRefs": [evidence_id],
                    "entities": {"analyses": [{
                        "kind": "coverage_gap",
                        "subject": {
                            "url": endpoint["attributes"]["url"],
                            "method": "GET",
                        },
                        "knowledgeState": "inferred",
                        "confidence": "low",
                        "reason": "The saved specification has no second actor or ownership response.",
                        "inconclusive": True,
                        "supportingEvidenceIds": [evidence_id],
                        "methodRef": {
                            "id": method["id"],
                            "digest": f"sha256:{method['sha256']}",
                        },
                    }]},
                }
                committed = service.run(
                    operation="actions.run_passive",
                    action_id="workspace.ingest_data",
                    arguments={
                        "workspaceId": "saved-only",
                        "target": "api.example.test",
                        "source": "contribution.v1",
                        "format": "json",
                        "rawData": json.dumps(analysis),
                    },
                    context=context,
                    passive_only=True,
                )
                self.assertEqual(committed.outcome_kind, "success")
                self.assertEqual(committed.result["schemaVersion"], "1.1")
                self.assertEqual(len(committed.result["canonicalRecordIds"]["observations"]), 1)
                latest = CompactFacadeService(resources=resources).invoke(
                    "context.query",
                    {"workspaceId": "saved-only", "targets": ["api.example.test"], "maxTokens": 30_000},
                    context=context,
                )
                self.assertEqual(latest.outcome_kind, "success")
                self.assertTrue(any(
                    item["attributes"].get("sourceAttribution", {}).get("methodRef", {}).get("id")
                    == "synapse-web-access-control"
                    for item in latest.result["coverageGaps"]
                ))

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

                method_digests = {
                    package["id"]: package["sha256"]
                    for package in guidance.build_guidance_snapshot().packages
                    if package["kind"] == "method"
                }
                method_analysis = {
                    "schemaVersion": "1.1",
                    "requestId": "pilot-methods-001",
                    "producer": {"name": "pilot-fixture", "version": "1.0.0"},
                    "evidenceRefs": receipt["evidenceIds"],
                    "entities": {
                        "analyses": [
                            {
                                "kind": "candidate",
                                "subject": {
                                    "entityId": receipt["canonicalRecordIds"]["endpoints"][0],
                                    "url": "https://api.example.test/health",
                                    "method": "GET",
                                },
                                "candidateClass": "auth_session",
                                "knowledgeState": "inferred",
                                "confidence": "low",
                                "reason": "Saved response metadata leaves session expiry unresolved.",
                                "supportingEvidenceIds": receipt["evidenceIds"],
                                "methodRef": {
                                    "id": "synapse-web-auth-session",
                                    "digest": f"sha256:{method_digests['synapse-web-auth-session']}",
                                },
                            },
                            {
                                "kind": "coverage_gap",
                                "subject": {
                                    "entityId": receipt["canonicalRecordIds"]["endpoints"][0],
                                    "url": "https://api.example.test/health",
                                    "method": "GET",
                                },
                                "knowledgeState": "reported",
                                "confidence": "low",
                                "reason": "No second actor is available for an ownership comparison.",
                                "inconclusive": True,
                                "methodRef": {
                                    "id": "synapse-web-access-control",
                                    "digest": f"sha256:{method_digests['synapse-web-access-control']}",
                                },
                            },
                        ]
                    },
                }
                analyzed = service.run(
                    operation="actions.run_passive",
                    action_id="workspace.ingest_data",
                    arguments={
                        "workspaceId": "pilot",
                        "target": "api.example.test",
                        "source": "contribution.v1",
                        "format": "json",
                        "rawData": json.dumps(method_analysis),
                    },
                    context=context,
                    passive_only=True,
                )
                self.assertEqual(analyzed.outcome_kind, "success")
                self.assertEqual(analyzed.result["schemaVersion"], "1.1")
                self.assertEqual(len(analyzed.result["canonicalRecordIds"]["observations"]), 2)

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
                endpoints = {
                    item["attributes"]["url"]: item
                    for item in facts if item.get("kind") == "endpoint"
                }
                documented = endpoints["https://api.example.test/v1/items"]
                reported = endpoints["https://api.example.test/health"]
                self.assertEqual(documented["lifecycle"], "observed")
                self.assertEqual(documented["attributes"]["knowledgeState"], "documented")
                self.assertEqual(documented["attributes"]["sourceAttribution"], {"source": "spec_import"})
                self.assertEqual(reported["lifecycle"], "observed")
                self.assertEqual(reported["attributes"]["knowledgeState"], "reported")
                self.assertEqual(reported["attributes"]["sourceAttribution"], {
                    "source": "pilot-fixture",
                    "submission": "contribution.v1",
                    "producer": {"name": "pilot-fixture", "version": "1.0.0"},
                })
                recovered_evidence = {
                    evidence_id
                    for item in facts
                    for evidence_id in item.get("evidenceReferences", [])
                }
                self.assertIn(import_evidence, recovered_evidence)
                self.assertIn(receipt["evidenceIds"][0], recovered_evidence)

                recovered_analysis = CompactFacadeService(resources=resources).invoke(
                    "context.query",
                    {"workspaceId": "pilot", "targets": ["api.example.test"], "maxTokens": 30_000},
                    context=context,
                )
                self.assertEqual(recovered_analysis.outcome_kind, "success")
                candidate = next(
                    item for item in recovered_analysis.result["candidates"]
                    if "auth_session" in item["attributes"].get("candidateFor", [])
                )
                gap = next(
                    item for item in recovered_analysis.result["coverageGaps"]
                    if item["attributes"].get("sourceAttribution", {}).get("methodRef", {}).get("id")
                    == "synapse-web-access-control"
                )
                self.assertEqual(
                    candidate["attributes"]["sourceAttribution"]["methodRef"]["id"],
                    "synapse-web-auth-session",
                )
                self.assertEqual(candidate["attributes"]["knowledgeState"], "inferred")
                self.assertEqual(gap["attributes"]["analysisConclusion"], "inconclusive")

                restarted = CompactFacadeService(
                    resources=ResourceReferenceService(state_path=root / "restarted-resources.json")
                ).invoke(
                    "context.query",
                    {
                        "workspaceId": "pilot", "targets": ["api.example.test"],
                        "entityTypes": ["endpoint"], "maxTokens": 30_000,
                    },
                    context=context,
                )
                self.assertEqual(restarted.outcome_kind, "success")
                restarted_endpoints = {
                    item["attributes"]["url"]: item
                    for item in restarted.result["confirmedFacts"] if item.get("kind") == "endpoint"
                }
                self.assertEqual(
                    restarted_endpoints["https://api.example.test/v1/items"]["attributes"]["knowledgeState"],
                    "documented",
                )
                self.assertEqual(
                    restarted_endpoints["https://api.example.test/health"]["attributes"]["knowledgeState"],
                    "reported",
                )
                self.assertEqual(
                    restarted_endpoints["https://api.example.test/health"]["attributes"]["sourceAttribution"]["producer"]["name"],
                    "pilot-fixture",
                )

                report = documentation.build_report_context(
                    {"workspaceId": "pilot", "target": "api.example.test"}
                )
                target = report["report"]["targets"][0]
                self.assertEqual(target["endpointCount"], 3)
                self.assertEqual(target["parameterCount"], 2)
                self.assertEqual(set(target), {
                    "target", "scopeStatus", "serviceCount", "endpointCount", "parameterCount",
                    "findingCount", "observationCount", "services", "technologies",
                    "pendingObservations", "recentActions",
                })

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
