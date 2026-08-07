from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from synapse_mcp.adapters.web import headers_cookies
from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, Success
from synapse_mcp.transport import projection, stdio_server
from synapse_mcp.transport.legacy_projection_map import (
    LEGACY_DISPATCH_ACTIONS,
    LEGACY_PROJECTION_MAP,
)


MIGRATED_ACTIONS = {
    "jobs.status",
    "workspace.summary",
    "workspace.prepare_target_context",
    "headers_cookies.analyze_workspace",
    "cors.execute_test",
    "crawler.crawl",
}


class ActionProjectionTests(unittest.TestCase):
    def test_projection_map_covers_every_migrated_action_and_preserves_legacy_names(self) -> None:
        self.assertEqual(set(LEGACY_PROJECTION_MAP), MIGRATED_ACTIONS)
        self.assertEqual(LEGACY_DISPATCH_ACTIONS, MIGRATED_ACTIONS)
        projected_by_name = {
            tool["name"]: tool
            for tool in stdio_server.TOOL_SCHEMAS
        }
        raw_by_name = {
            tool["name"]: tool
            for tool in stdio_server._LEGACY_TOOL_SCHEMAS
        }

        for action_id, legacy in LEGACY_PROJECTION_MAP.items():
            self.assertEqual(legacy.legacy_name, action_id)
            self.assertEqual(
                projection.resolved_input_schema(legacy.legacy_name),
                projected_by_name[legacy.legacy_name]["inputSchema"],
            )
            self.assertNotIn("inputSchema", raw_by_name[legacy.legacy_name])

        self.assertEqual(len(REGISTRY.descriptors()), 6)
        self.assertEqual(
            REGISTRY.packs(),
            frozenset({"jobs", "workspace", "headers_cookies", "cors", "crawler"}),
        )

    def test_registry_success_preserves_legacy_payload_error_signal(self) -> None:
        descriptor = REGISTRY.get("headers_cookies.analyze_workspace")
        arguments = {"workspaceId": "acme", "target": "app.acme-demo.test"}
        request = ActionRequest(
            input=descriptor.input_model.model_validate(arguments),
            context=ExecutionContext("acme", "review-regression", 45.0, None),
        )
        with patch.object(
            headers_cookies,
            "analyze_workspace",
            return_value='{"error":"legacy payload error"}',
        ):
            outcome = REGISTRY.execute(request)
            serialized = projection.project_call(
                "headers_cookies.analyze_workspace",
                arguments,
            )

        self.assertIsInstance(outcome, Success)
        self.assertTrue(outcome.payload_signals_error)
        self.assertEqual(serialized, '{"error":"legacy payload error"}')
        self.assertTrue(stdio_server._tool_result_has_error(serialized))

    def test_dispatch_rollback_preserves_schema_and_legacy_validation(self) -> None:
        enabled = LEGACY_DISPATCH_ACTIONS - {"jobs.status"}
        with patch.object(projection, "LEGACY_DISPATCH_ACTIONS", enabled):
            tool = next(
                item
                for item in projection.projected_tools_list()
                if item["name"] == "jobs.status"
            )
            missing = stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "jobs.status", "arguments": {}},
                }
            )
            with (
                patch.object(
                    stdio_server.background_jobs,
                    "status",
                    return_value={"status": "legacy-branch"},
                ) as legacy_status,
                patch.object(REGISTRY, "execute") as registry_execute,
            ):
                result = stdio_server._call_tool_impl(
                    "jobs.status",
                    {"jobId": "job-fixture"},
                )

        self.assertIn("inputSchema", tool)
        self.assertEqual(
            tool["inputSchema"],
            projection.resolved_input_schema("jobs.status"),
        )
        self.assertEqual(
            missing["error"],
            {
                "code": -32602,
                "message": "Invalid arguments for jobs.status: missing required field jobId",
            },
        )
        self.assertEqual(json.loads(result), {"status": "legacy-branch"})
        legacy_status.assert_called_once_with("job-fixture", False)
        registry_execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
