"""Task 4E State Store v2 default and adoption acceptance coverage."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY
from synapse_mcp.core import scope, workspace
from synapse_mcp.state import ActivatedWorkspaceRepository, NewWorkspaceStoreService
from synapse_mcp.state.selector import selected_store_version
from synapse_mcp.transport import stdio_server


ROOT = Path(__file__).resolve().parents[3]


class Phase4EAcceptanceTests(unittest.TestCase):
    def test_genuinely_new_workspace_defaults_to_v2(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                created = workspace.create_workspace(
                    "fresh-default",
                    organization="Fictional",
                    hosts=["phase4.example"],
                )
                workspace_root = root / "workspaces" / "fresh-default"
                self.assertTrue(created["created"])
                self.assertEqual(selected_store_version(workspace_root), "sqlite-v2")
                self.assertFalse((workspace_root / "workspace.json").exists())
                self.assertTrue((workspace_root / "state-v2" / "state.sqlite3").is_file())
                summary = workspace.workspace_summary("fresh-default")
                self.assertEqual(summary["storeVersion"], "sqlite-v2")
                self.assertEqual(summary["revision"], 1)
                self.assertEqual(summary["targetCount"], 1)

    def test_existing_v1_workspace_is_not_automatically_migrated(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                first = workspace.create_workspace(
                    "existing-v1",
                    hosts=["legacy.example"],
                    store_version="json-v1",
                )
                second = workspace.create_workspace("existing-v1", notes="still explicit v1")
                workspace_root = root / "workspaces" / "existing-v1"
                self.assertTrue(first["created"])
                self.assertFalse(second["created"])
                self.assertEqual(selected_store_version(workspace_root), "json-v1")
                self.assertTrue((workspace_root / "workspace.json").is_file())
                self.assertFalse((workspace_root / "state-v2" / "store-selector.json").exists())

    def test_interrupted_fresh_bootstrap_resumes_without_duplicate_revision(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = NewWorkspaceStoreService(root / "workspaces")
            arguments = {
                "organization": "Fictional",
                "notes": "offline",
                "scope": {"hosts": ["phase4.example"], "patterns": [], "cidrs": []},
                "targets": ({"workspaceId": "fresh-crash", "target": "phase4.example", "kind": "host"},),
            }
            with patch(
                "synapse_mcp.state.bootstrap.write_store_selector",
                side_effect=RuntimeError("selector crash"),
            ):
                with self.assertRaisesRegex(RuntimeError, "selector crash"):
                    service.create("fresh-crash", **arguments)
            workspace_root = root / "workspaces" / "fresh-crash"
            self.assertEqual(selected_store_version(workspace_root), "json-v1")
            resumed = service.create("fresh-crash", **arguments)
            repository = ActivatedWorkspaceRepository("fresh-crash", workspace_root)
            self.assertFalse(resumed["created"])
            self.assertEqual(repository.revision(), 1)
            self.assertEqual(len(repository.target_documents()), 1)

    def test_legacy_protocol_handlers_read_and_merge_v2_state(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("legacy-over-v2", hosts=["phase4.example"])

                def payload(status: int) -> str:
                    return json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://phase4.example/api/items",
                                        "method": "get",
                                        "statusCodes": [status],
                                    }
                                ]
                            }
                        }
                    )

                first = workspace.ingest_data(
                    "legacy-over-v2", "phase4.example", "adapter_result", "tool_output", "json", payload(200)
                )
                second = workspace.ingest_data(
                    "legacy-over-v2", "phase4.example", "adapter_result", "tool_output", "json", payload(302)
                )
                response = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {
                            "name": "workspace.prepare_target_context",
                            "arguments": {
                                "workspaceId": "legacy-over-v2",
                                "target": "phase4.example",
                                "maxTokens": 1_500,
                            },
                        },
                    }
                )
                self.assertEqual(first["entitiesCreated"]["endpoints"], 1)
                self.assertEqual(second["entitiesCreated"]["endpoints"], 0)
                self.assertNotIn("error", response)
                context = json.loads(response["result"]["content"][0]["text"])
                self.assertEqual(context["knownEndpoints"]["total"], 1)

    def test_crawler_plan_keeps_worker_and_report_outputs_inside_v2(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                scope.save_scope(["phase4.example"], "offline", "Fictional")
                workspace.create_workspace("crawler-v2", hosts=["phase4.example"])
                descriptor = REGISTRY.get("crawler.crawl")
                request = ActionRequest(
                    descriptor.input_model.model_validate(
                        {
                            "target": "https://phase4.example",
                            "workspaceId": "crawler-v2",
                            "maxPages": 1,
                            "maxDepth": 0,
                            "httpBackend": "disabled",
                            "disableTraffic": True,
                            "background": True,
                        }
                    ),
                    ExecutionContext("crawler-v2", "phase4e-output-plan", 45.0, None),
                )
                plan = REGISTRY.resolve_execution_plan("crawler.crawl", request)
                relative_paths = [
                    Path(destination.path).relative_to(root / "workspaces" / "crawler-v2").parts
                    for destination in plan.intent.local_outputs
                ]
                self.assertTrue(relative_paths)
                self.assertTrue(all(parts[:2] == ("state-v2", "generated") for parts in relative_paths))

    def test_runner_and_operator_handoff_are_retained(self) -> None:
        runner = ROOT / "bin" / "run-phase4-acceptance"
        handoff = ROOT / "docs" / "modernization" / "phase-4-handoff.md"
        self.assertTrue(runner.is_file())
        self.assertTrue(runner.stat().st_mode & 0o111)
        self.assertTrue(handoff.is_file())
        content = handoff.read_text(encoding="utf-8")
        normalized = " ".join(content.split())
        self.assertIn("Existing JSON-v1 workspaces are never migrated automatically", normalized)
        self.assertIn("Protocol profile selection is independent of workspace store selection", normalized)
        self.assertIn("partial_fail", content)


if __name__ == "__main__":
    unittest.main()
