"""Versioned saved-data contribution contract and durable receipt tests."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRegistry, ActionRequest, ExecutionContext, PassThroughPolicyEvaluator, Success
from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.app.facade import (
    ActionCatalogService, ActionExecutionService, FacadeCallContext,
    OperationHandleService, ResourceReferenceService,
)
from synapse_mcp.core import workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.state.runtime import ActivatedWorkspaceRepository
from synapse_mcp.state.bundles import StateBundleService


def _payload(request_id: str, path: str) -> str:
    return json.dumps({
        "schemaVersion": "1.0",
        "requestId": request_id,
        "producer": {"name": "saved-fixture", "version": "1.2.0"},
        "entities": {"endpoints": [{"url": f"https://example.test/{path}", "method": "GET"}]},
    })


class ContributionTests(unittest.TestCase):
    def _submit(self, registry: ActionRegistry, principal: str, raw: str):
        descriptor = registry.get("workspace.ingest_data")
        value = descriptor.input_model.model_validate({
            "workspaceId": "engagement", "target": "example.test", "source": "contribution.v1",
            "format": "json", "rawData": raw,
        })
        return registry.execute("workspace.ingest_data", ActionRequest(
            value,
            ExecutionContext("engagement", f"fixture-{principal}", 45.0, None,
                             principal_id=principal, execution_profile="observe"),
        ))

    def test_two_consumers_retry_conflict_and_recovery(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                first = self._submit(registry, "consumer:a", _payload("req-1", "alpha"))
                self.assertIsInstance(first, Success)
                receipt_a = first.payload.model_dump(mode="json", exclude_none=True)
                self.assertEqual(receipt_a["insertedCounts"]["endpoints"], 1)
                self.assertEqual(len(receipt_a["canonicalRecordIds"]["endpoints"]), 1)
                revision = receipt_a["committedRevision"]
                replay = self._submit(registry, "consumer:a", _payload("req-1", "alpha"))
                self.assertEqual(replay.payload.model_dump(mode="json", exclude_none=True), receipt_a)
                self.assertEqual(workspace._activated_repository("engagement").revision(), revision)

                conflict = self._submit(registry, "consumer:a", _payload("req-1", "different"))
                self.assertEqual(conflict.kind, "validation_failure")
                self.assertIn("contribution_request_conflict", conflict.message)
                self.assertEqual(workspace._activated_repository("engagement").revision(), revision)

                second = self._submit(registry, "consumer:b", _payload("req-1", "beta"))
                self.assertIsInstance(second, Success)
                receipt_b = second.payload.model_dump(mode="json", exclude_none=True)
                self.assertNotEqual(receipt_a["submissionId"], receipt_b["submissionId"])
                self.assertNotEqual(receipt_a["consumerRef"], receipt_b["consumerRef"])
                repository = ActivatedWorkspaceRepository("engagement", workspace.workspace_path("engagement"))
                endpoints = {item["path"]: item for item in repository.collection("example.test", "endpoints")}
                self.assertEqual(set(endpoints), {"/alpha", "/beta"})
                self.assertEqual(endpoints["/alpha"]["evidenceIds"], receipt_a["evidenceIds"])
                self.assertEqual(endpoints["/beta"]["evidenceIds"], receipt_b["evidenceIds"])
                with repository.connection_factory.connect() as connection:
                    links = connection.execute(
                        "SELECT ee.entity_id, ee.evidence_id FROM entity_evidence ee WHERE workspace_id=?",
                        ("engagement",),
                    ).fetchall()
                    self.assertEqual(len(links), 2)
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM contribution_receipts WHERE workspace_id=?", ("engagement",)
                    ).fetchone()[0], 2)
                context = workspace.prepare_target_context("engagement", "example.test")
                self.assertEqual(context["knownEndpoints"]["total"], 2)
                bundle = Path(tmp) / "accepted-bundle"
                StateBundleService(Path(tmp)).export("engagement", bundle)
                imported_root = Path(tmp) / "imported"
                StateBundleService(imported_root).import_bundle(bundle)
                imported = ActivatedWorkspaceRepository("engagement", imported_root / "workspaces" / "engagement")
                with imported.connection_factory.connect() as connection:
                    persisted = connection.execute(
                        "SELECT receipt_json FROM contribution_receipts WHERE workspace_id=? AND request_id=? AND principal_ref=?",
                        ("engagement", "req-1", receipt_a["consumerRef"]),
                    ).fetchone()
                self.assertEqual(json.loads(persisted[0]), receipt_a)
                self.assertEqual(len(imported.collection("example.test", "endpoints")), 2)
                backup = repository.backup_to(Path(tmp) / "accepted-backup.sqlite3")
                with sqlite3.connect(backup) as connection:
                    backed_up = connection.execute(
                        "SELECT receipt_json FROM contribution_receipts WHERE workspace_id=? AND request_id=? AND principal_ref=?",
                        ("engagement", "req-1", receipt_a["consumerRef"]),
                    ).fetchone()
                self.assertEqual(json.loads(backed_up[0]), receipt_a)

    def test_concurrent_identical_request_has_one_receipt(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(
                        lambda _: self._submit(registry, "consumer:race", _payload("same-request", "race")),
                        range(2),
                    ))
                self.assertTrue(all(isinstance(item, Success) for item in results))
                self.assertEqual(results[0].payload.model_dump(), results[1].payload.model_dump())
                repository = workspace._activated_repository("engagement")
                with repository.connection_factory.connect() as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM contribution_receipts WHERE workspace_id=?", ("engagement",)
                    ).fetchone()[0], 1)
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM evidence WHERE workspace_id=?", ("engagement",)
                    ).fetchone()[0], 1)

    def test_existing_evidence_links_only_to_named_entity(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                first = workspace.ingest_data(
                    "engagement", "example.test", "contribution.v1", "consumer_submission", "json",
                    _payload("first", "first"), principal_id="consumer:a",
                )
                prior = first["evidenceIds"][0]
                prior_artifact = first["artifactIds"][0]
                second_payload = {
                    "schemaVersion": "1.0", "requestId": "second",
                    "producer": {"name": "saved-fixture", "version": "1.2.0"},
                    "evidenceRefs": [prior],
                    "artifactRefs": [prior_artifact],
                    "entities": {"endpoints": [
                        {"url": "https://example.test/linked", "evidenceIds": [prior]},
                        {"url": "https://example.test/unlinked"},
                    ]},
                }
                second = workspace.ingest_data(
                    "engagement", "example.test", "contribution.v1", "consumer_submission", "json",
                    json.dumps(second_payload), principal_id="consumer:b",
                )
                new_id = second["evidenceIds"][0]
                self.assertIn(prior_artifact, second["artifactIds"])
                endpoints = {
                    item["path"]: item
                    for item in workspace._activated_repository("engagement").collection("example.test", "endpoints")
                }
                self.assertEqual(set(endpoints["/linked"]["evidenceIds"]), {prior, new_id})
                self.assertEqual(endpoints["/unlinked"]["evidenceIds"], [new_id])
                with workspace._activated_repository("engagement").connection_factory.connect() as connection:
                    self.assertIsNotNone(connection.execute(
                        "SELECT 1 FROM evidence_artifacts WHERE workspace_id=? AND evidence_id=? AND artifact_id=?",
                        ("engagement", new_id, prior_artifact),
                    ).fetchone())

    def test_facade_binds_consumer_and_workspace_from_context(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                service = ActionExecutionService(
                    registry=registry,
                    resources=ResourceReferenceService(state_path=Path(tmp) / "resources.json"),
                    operations=OperationHandleService(state_path=Path(tmp) / "operations.json"),
                )
                arguments = {
                    "workspaceId": "engagement", "target": "example.test", "source": "contribution.v1",
                    "format": "json", "rawData": _payload("facade-request", "facade"),
                }
                context = FacadeCallContext(
                    principal_id="consumer:facade", workspace_id="engagement",
                    authority_session_id="fixture-session",
                )
                accepted = service.run(
                    operation="actions.run_passive", action_id="workspace.ingest_data",
                    arguments=arguments, context=context, passive_only=True,
                )
                self.assertEqual(accepted.outcome_kind, "success")
                self.assertEqual(accepted.result["workspaceId"], "engagement")
                self.assertNotIn("consumer:facade", json.dumps(accepted.result))
                denied = service.run(
                    operation="actions.run_passive", action_id="workspace.ingest_data",
                    arguments=arguments, context=FacadeCallContext(
                        principal_id="consumer:facade", workspace_id="another-workspace",
                        authority_session_id="fixture-session",
                    ), passive_only=True,
                )
                self.assertEqual(denied.outcome_kind, "policy_denial")

    def test_strict_validation_has_no_canonical_write(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                repository = workspace._activated_repository("engagement")
                baseline = repository.revision()
                invalid = json.loads(_payload("req-2", "ok"))
                invalid["entities"]["findings"] = [{"title": "caller-reviewed", "operatorReviewed": True}]
                with self.assertRaisesRegex(McpError, "entities.findings"):
                    workspace.ingest_data("engagement", "example.test", "contribution.v1", "consumer_submission",
                                          "json", json.dumps(invalid), principal_id="consumer:a")
                self.assertEqual(repository.revision(), baseline)
                self.assertEqual(repository.collection("example.test", "endpoints"), [])

                missing = json.loads(_payload("req-3", "ok"))
                missing["evidenceRefs"] = ["ev_missing"]
                with self.assertRaisesRegex(McpError, "contribution_evidence_ref_invalid"):
                    workspace.ingest_data("engagement", "example.test", "contribution.v1", "consumer_submission",
                                          "json", json.dumps(missing), principal_id="consumer:a")
                self.assertEqual(repository.revision(), baseline)

                artifact = repository.artifacts.ingest_bytes(b"rollback-fixture", origin="contribution-test")
                def fail(stage: str) -> None:
                    if stage == "after_contribution_receipt":
                        raise RuntimeError("rollback-after-receipt")

                with self.assertRaisesRegex(RuntimeError, "rollback-after-receipt"):
                    repository.ingest_collections(
                        target="example.test",
                        target_payload={"workspaceId": "engagement", "target": "example.test", "kind": "host"},
                        evidence_payload={"evidenceId": "ev_rollback", "source": "contribution.v1"},
                        artifact=artifact,
                        collections={"endpoints": [{"type": "endpoint", "url": "https://example.test/rollback", "key": "rollback"}]},
                        audit_payload={"summary": "Rollback fixture"},
                        contribution={
                            "principalId": "consumer:a", "requestId": "rollback", "payloadFingerprint": "a" * 64,
                            "producer": {"name": "saved-fixture", "version": "1.2.0"},
                        },
                        fault_injector=fail,
                    )
                self.assertEqual(repository.revision(), baseline)
                self.assertFalse(repository.evidence_exists("ev_rollback"))
                with repository.connection_factory.connect() as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM contribution_receipts WHERE workspace_id=?", ("engagement",)
                    ).fetchone()[0], 0)

    def test_published_schema_matches_validator(self) -> None:
        description = ActionCatalogService().describe("workspace.ingest_data")
        contract = description.input_schema["x-synapse-contribution"]
        self.assertEqual(contract["source"], "contribution.v1")
        self.assertEqual(contract["rawDataSchema"]["properties"]["schemaVersion"]["const"], "1.0")
        self.assertEqual(set(contract["rawDataSchema"]["$defs"]["ContributionEntities"]["properties"]),
                         {"endpoints", "observations"})

    def test_json_v1_workspace_requires_explicit_activation(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp), store_version="json-v1"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                with self.assertRaisesRegex(McpError, "activated SQLite-v2"):
                    workspace.ingest_data(
                        "engagement", "example.test", "contribution.v1", "consumer_submission", "json",
                        _payload("legacy-refusal", "legacy"), principal_id="consumer:a",
                    )
                self.assertEqual(
                    list((workspace.target_path("engagement", "example.test") / "evidence").glob("ev_*")), []
                )
